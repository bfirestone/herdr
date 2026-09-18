#!/usr/bin/env python3
"""Repeatable native T1 fake-provider lifecycle check; never contacts a real provider.

Usage: python3 scripts/test_integrated_client_detach.py --herdr-bin /absolute/path/to/built/herdr
Uses only a newly created temporary config/catalog/session and preserves HOME.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import fcntl
import termios

PROVIDER = r'''
import hashlib,json,os,socket,sys,subprocess
observer=socket.create_connection(('127.0.0.1',int(os.environ['HERDR_FIXTURE_PORT'])))
sync=observer.makefile('rwb',buffering=0)
def emit(x): sync.write((json.dumps(x)+'\n').encode())
def send(x): print(json.dumps(x),flush=True)
read=lambda:json.loads(sys.stdin.readline())
descendant=subprocess.Popen([sys.executable,'-c','import time; time.sleep(90)'])
emit({'provider':os.getpid(),'helper':os.getppid(),'descendant':descendant.pid})
a=read();send({'id':a['id'],'result':{'userAgent':'codex/0.154.0'}})
assert read()['method']=='initialized'
a=read();assert a['method']=='thread/start'
send({'id':a['id'],'result':{'thread':{'id':'fixed'},'cwd':os.getcwd(),'approvalPolicy':'on-request','sandbox':{'type':'readOnly'}}})
count=0
while True:
 line=sys.stdin.readline()
 if not line: break
 a=json.loads(line);assert a['method']=='turn/start'
 assert a['params']['threadId']=='fixed'
 text=a['params']['input'][0]['text'];count+=1
 assert text not in str(sys.argv) and text not in str(dict(os.environ))
 emit({'count':count,'digest':hashlib.sha256(text.encode()).hexdigest()})
 send({'id':a['id'],'result':{'turn':{'id':'turn-'+str(count)}}})
 send({'method':'turn/completed','params':{'threadId':'fixed','turn':{'id':'turn-'+str(count)}}})
'''


def eventually(check, description, seconds=12):
    deadline = time.monotonic() + seconds
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError('deadline: ' + description)
        time.sleep(0.03)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def run(binary):
    import socket
    binary = str(Path(binary).resolve(strict=True))
    root = Path(tempfile.mkdtemp(prefix='hdr-detach-', dir='/tmp')).resolve()
    server = client = None
    master = slave = observer = None
    owned_pids = []
    success = False
    env = os.environ.copy()
    original_home = env.get('HOME')
    for key in ['HERDR_SOCKET_PATH', 'HERDR_CLIENT_SOCKET_PATH', 'HERDR_SESSION', 'HERDR_PANE_ID', 'HERDR_ENV', 'HERDR_REMOTE_KEYBINDINGS']:
        env.pop(key, None)
    session = 't1-' + uuid.uuid4().hex[:8]
    scratch = root / 'scratch'
    scratch.mkdir()
    bindir = root / 'bin'
    bindir.mkdir()
    provider = bindir / 'codex'
    provider.write_text('#!' + sys.executable + '\n' + PROVIDER)
    provider.chmod(0o700)
    config = root / 'config.toml'
    config.write_text('onboarding = false\n[terminal]\ndefault_shell = "/bin/sh"\nshell_mode = "non_login"\n')
    env.update(XDG_CONFIG_HOME=str(root / 'cfg'), XDG_STATE_HOME=str(root / 'state'), HERDR_CONFIG_PATH=str(config), TERM='xterm-256color')
    assert env.get('HOME') == original_home
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(12)
    server_env = dict(env, PATH=str(bindir) + os.pathsep + env['PATH'], HERDR_FIXTURE_PORT=str(listener.getsockname()[1]))
    command = [binary, '--session', session]
    request_number = 0

    def api(method, params=None):
        nonlocal request_number
        request_number += 1
        request = {'id': 'detach-' + str(request_number), 'method': method, 'params': params or {}}
        result = subprocess.run(command + ['remote-api-bridge'], input=json.dumps(request) + '\n', capture_output=True, text=True, env=env, cwd=scratch, timeout=18)
        if result.returncode:
            raise AssertionError('bridge failed: ' + result.stderr[-1000:])
        response = json.loads(result.stdout)
        assert response['id'] == request['id']
        return response

    def result(method, params=None):
        response = api(method, params)
        assert 'error' not in response, response
        return response['result']

    def ready():
        if server.poll() is not None:
            raise AssertionError('server exited: ' + (root / 'server.stderr').read_text())
        try:
            return result('ping')
        except (AssertionError, json.JSONDecodeError):
            return False

    def log_contains(marker):
        return any(marker in p.read_text(errors='replace') for p in (root / 'cfg').rglob('herdr-server.log'))

    def observe():
        line = observer.readline()
        assert line and len(line) < 1024, 'bounded provider observation required'
        return json.loads(line)

    try:
        with (root / 'server.stderr').open('wb') as output:
            server = subprocess.Popen(command + ['server'], env=server_env, cwd=scratch, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        eventually(ready, 'unique server ready')
        workspace = result('workspace.create', {'cwd': str(scratch), 'label': 'isolated detach fixture', 'focus': True})['workspace']
        started = result('agent.start_integrated', {'provider': 'codex', 'workspace_id': workspace['workspace_id'], 'cwd': str(scratch)})
        peer, _ = listener.accept()
        peer.settimeout(12)
        observer = peer.makefile('rb')
        identities = observe()
        owned_pids = [identities[key] for key in ['helper', 'provider', 'descendant']]
        agent = started['agent']
        pane = agent['pane_id']
        identity = {key: started[key] for key in ['server_instance', 'recipient_token']}
        identity['terminal_id'] = agent['terminal_id']
        def idle():
            return result('agent.get', {'target': pane})['agent']['agent_status'] == 'idle'
        eventually(idle, 'integrated owner idle')
        assert result('agent.focus', {'target': pane})['agent']['terminal_id'] == identity['terminal_id']
        assert result('agent.read', {'target': pane, 'source': 'recent', 'format': 'text', 'lines': 20})['type'] == 'pane_read'
        denied = api('agent.prompt', {'target': pane, 'text': 'never send via PTY'})
        assert denied['error']['code'] == 'unsupported_recipient', denied

        def submit(text, count):
            eventually(idle, 'idle before explicit submission')
            reply = result('agent.prompt_exact', dict(identity, text=text))
            assert reply['outcome'] == 'accepted', reply
            assert reply['acceptance'] == 'provider_input_accepted'
            for key, value in identity.items():
                assert reply[key] == value
            receipt = observe()
            assert receipt == {'count': count, 'digest': hashlib.sha256(text.encode()).hexdigest()}, receipt

        # config::config_dir and state_dir honor XDG overrides; the catalog resides
        # under that fresh state root, never the normal HOME catalog.
        assert Path(env['XDG_CONFIG_HOME']).is_relative_to(root)
        assert Path(env['XDG_STATE_HOME']).is_relative_to(root)
        assert config.is_relative_to(root) and 'remote' not in config.read_text()
        catalogs = list((root / 'state').rglob('endpoints.json'))
        assert not catalogs, 'fixture unexpectedly has a saved endpoint catalog'
        assert all(path.is_relative_to(root) for path in (root / 'cfg').rglob('*'))
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 100, 0, 0))
        client = subprocess.Popen(command + ['client'], env=env, cwd=scratch, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        slave = None
        # Drain the actual client PTY until the server records a completed attach.
        def attached():
            assert client.poll() is None, 'client exited before attach'
            if select.select([master], [], [], 0)[0]:
                os.read(master, 65536)
            return log_contains('client connected')
        eventually(attached, 'actual client attached')
        prompts = ['before-detach ' + uuid.uuid4().hex + '\n界', 'after-detach ' + uuid.uuid4().hex + '\r\nprivate body']
        submit(prompts[0], 1)
        os.write(master, b'\x02q')  # Default Herdr prefix + explicit detach, no provider input.
        def detached():
            if select.select([master], [], [], 0)[0]:
                try:
                    os.read(master, 65536)
                except OSError:
                    pass
            return client.poll() is not None
        eventually(detached, 'actual client detached')
        assert client.wait(timeout=2) == 0
        eventually(lambda: log_contains('client detached'), 'server observed detach')
        assert server.poll() is None
        assert all(alive(pid) for pid in owned_pids)
        submit(prompts[1], 2)
        assert all(alive(pid) for pid in owned_pids)
        assert env.get('HOME') == original_home
        # Bodies occur only on the intended pipes, never in fixture disk receipts.
        for path in root.rglob('*'):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                assert all(prompt.encode() not in data for prompt in prompts), str(path)
        for pid in [server.pid, *owned_pids]:
            argv = subprocess.run(['ps', '-ww', '-p', str(pid), '-o', 'command='], capture_output=True, check=True, timeout=3).stdout
            assert all(prompt.encode() not in argv for prompt in prompts)
        success = True
        print(json.dumps({'client_attach_detach': 'PASS', 'post_detach_same_helper_provider': 'PASS', 'provider_input_count': 2, 'legacy_prompt_rejected': True, 'agent_get_focus_read': 'PASS', 'session': session, 'scratch': str(root), 'binary': binary}))
    finally:
        cleanup_errors = []
        if client is not None and client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=3)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=3)
        if server is not None and server.poll() is None:
            try:
                subprocess.run(command + ['server', 'stop'], env=env, cwd=scratch, capture_output=True, timeout=10, check=True)
                assert server.wait(timeout=10) == 0
            except Exception as error:
                cleanup_errors.append(str(error))
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)
        for pid in owned_pids:
            try:
                eventually(lambda pid=pid: not alive(pid), 'owned helper/provider termination', seconds=5)
            except AssertionError as error:
                # Preserve the failure while ensuring this test never strands its children.
                cleanup_errors.append(str(error))
                for sig in [signal.SIGTERM, signal.SIGKILL]:
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        break
                    try:
                        eventually(lambda pid=pid: not alive(pid), 'owned fallback cleanup', seconds=2)
                        break
                    except AssertionError:
                        continue
        for fd in [master, slave]:
            if fd is not None:
                os.close(fd)
        if observer is not None:
            observer.close()
        listener.close()
        print(json.dumps({'owned_cleanup': 'FAIL' if cleanup_errors else 'PASS', 'owned_pids': owned_pids}))
        if success and not cleanup_errors:
            shutil.rmtree(root)
        else:
            print('Retained owned diagnostic directory: ' + str(root), file=sys.stderr)
        assert not cleanup_errors, cleanup_errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--herdr-bin', required=True, type=Path)
    args = parser.parse_args()
    if not args.herdr_bin.is_absolute():
        parser.error('--herdr-bin must be an absolute freshly built binary path')
    run(args.herdr_bin)
