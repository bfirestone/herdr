#!/usr/bin/env python3
"""Opt-in Codex 0.154.0 qualification in one new disposable Herdr session.

Never invokes login or uses PTY prompt input. Strict test policy is an explicit opt-in.
Live smoke preserves HOME/auth. Descriptor CI uses an empty provider home without auth.
JSON output contains evidence categories, never prompts or provider diagnostics.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import pty
import fcntl
import termios
import struct
import select
import stat
import subprocess
import tempfile
import time
import unittest
import io
import socket
from contextlib import redirect_stdout
from unittest import mock

VERSION = 'codex-cli 0.154.0'
ROUTING = ('HERDR_SOCKET_PATH', 'HERDR_CLIENT_SOCKET_PATH', 'HERDR_SESSION',
           'HERDR_PANE_ID', 'HERDR_ENV', 'HERDR_REMOTE_KEYBINDINGS')


class ProofFailure(Exception):
    """A safe category, never a raw provider error."""


def validate_targets(session, scratch):
    match = re.fullmatch(r'codex-proof-([0-9a-f]{32})', session)
    if not match or not scratch.is_absolute():
        raise ProofFailure('invalid_disposable_target')
    if scratch.name != 'herdr-codex-' + match[1] or scratch.exists() or scratch.is_symlink():
        raise ProofFailure('target_not_fresh')
    if not scratch.parent.is_dir() or scratch.parent.resolve() != scratch.parent:
        raise ProofFailure('target_parent_not_canonical')


def validate_binary(path):
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ProofFailure('invalid_executable')
    return str(path.resolve(strict=True))


def validate_provider(path):
    binary = validate_binary(path)
    result = subprocess.run([binary, '--version'], capture_output=True, timeout=10)
    if result.returncode or result.stdout.strip() != VERSION.encode():
        raise ProofFailure('unsupported_provider_version')
    return binary


def isolated_environment(root, provider, strict_test_policy=False):
    env = os.environ.copy()
    for key in ROUTING:
        env.pop(key, None)
    bindir = root / 'bin'
    bindir.mkdir(mode=0o700)
    launcher = bindir / 'codex'
    if strict_test_policy:
        launcher.write_text('#!' + os.sys.executable + '\nimport os,sys\n' +
                            'os.execv(' + repr(provider) + ', [' + repr(provider) +
                            ', \'-c\', \'approval_policy="on-request"\', \'-c\', \'approvals_reviewer="user"\', *sys.argv[1:]])\n')
        launcher.chmod(0o700)
    else:
        launcher.symlink_to(provider)
    config = root / 'herdr.toml'
    config.write_text('onboarding = false\n[terminal]\ndefault_shell = "/bin/sh"\nshell_mode = "non_login"\n')
    env.update(XDG_CONFIG_HOME=str(root / 'c'), XDG_STATE_HOME=str(root / 's'),
               HERDR_CONFIG_PATH=str(config), CODEX_SQLITE_HOME=str(root / 'codex-state'), TERM='xterm-256color',
               PATH=str(bindir) + os.pathsep + env.get('PATH', ''))
    assert env.get('HOME') == os.environ.get('HOME')
    return env


def eventually(check, category, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.05)
    raise ProofFailure(category)


def descendants(root, parents):
    owned = {root}
    while True:
        expanded = owned | {pid for pid, parent in parents.items() if parent in owned}
        if expanded == owned:
            return owned - {root}
        owned = expanded


def process_parents():
    try:
        result = subprocess.run(['ps', '-axo', 'pid=,ppid='], capture_output=True, check=True, timeout=5)
        return {int(pid): int(parent) for pid, parent in (line.split() for line in result.stdout.splitlines())}
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise ProofFailure('process_inspection_unavailable') from error


def observe_owned(owner, pid):
    try:
        owner.owned_children |= descendants(pid, process_parents())
    except ProofFailure as error:
        owner.cleanup_failure = owner.cleanup_failure or error
        raise


def cleanup_step(errors, action):
    # Failure of observation must not skip closure/reaping of known owned handles.
    try:
        action()
    except ProofFailure as error:
        errors.append(error)
    except (OSError, subprocess.SubprocessError):
        errors.append(ProofFailure('owned_cleanup_unverified'))


def reap_owned(child, graceful=False):
    if graceful:
        try:
            child.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
    try:
        child.terminate()
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            child.kill()
        except ProcessLookupError:
            pass
        child.wait(timeout=3)


def consent_request(preview, thread, turn, command, cwd):
    if 'HERDR PERMISSION' not in preview:
        raise ProofFailure('consent_not_visible')
    # The renderer uses box borders. A wide owned client prevents JSON wrapping.
    text = '\n'.join(line.strip().strip('│').rstrip() for line in preview.splitlines())
    try:
        card, _ = json.JSONDecoder().raw_decode(text[text.index('{'):])
        request = card['request']
        params = request['params']
        actual = params['command']
        argv = shlex.split(actual)
        if len(argv) == 3 and argv[0] in ('/bin/zsh', '/bin/bash', '/bin/sh') and argv[1] in ('-c', '-lc'):
            actual = argv[2]
        if (request['method'] != 'item/commandExecution/requestApproval'
                or params['threadId'] != thread or params['turnId'] != turn
                or params['cwd'] != cwd or actual != command
                or params.get('additionalPermissions') is not None
                or 'accept' not in params.get('availableDecisions', ['accept'])):
            raise ValueError('unapproved scope')
        return request
    except (ValueError, KeyError, TypeError) as error:
        raise ProofFailure('consent_scope_unverified') from error


class Session:
    def __init__(self, binary, session, root, provider, consent_root=None, strict_test_policy=False):
        self.command = [binary, '--session', session]
        self.root = root
        self.consent_root = consent_root or root
        self.workspace = root / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.state_root = Path(tempfile.mkdtemp(prefix='hcp-', dir='/tmp'))
        self.env = isolated_environment(self.state_root, provider, strict_test_policy)
        self.sequence = 0
        self.server = None
        self.client = None
        self.client_pty = None
        self.owned_children = set()
        self.closed = False
        self.cleanup_failure = None

    def api(self, method, params=None):
        if self.server is not None:
            observe_owned(self, self.server.pid)
        self.sequence += 1
        request = {'id': 'qualification-' + str(self.sequence), 'method': method, 'params': params or {}}
        response = subprocess.run(self.command + ['remote-api-bridge'],
                                  input=(json.dumps(request) + '\n').encode(), capture_output=True,
                                  timeout=20, env=self.env, cwd=self.workspace)
        if response.returncode or len(response.stdout) > 1024 * 1024:
            raise ProofFailure('bridge_failure')
        try:
            value = json.loads(response.stdout)
        except (ValueError, UnicodeError) as error:
            raise ProofFailure('invalid_bridge_response') from error
        if value.get('id') != request['id']:
            raise ProofFailure('uncorrelated_bridge_response')
        return value

    def result(self, method, params=None):
        value = self.api(method, params)
        if 'error' in value or 'result' not in value:
            raise ProofFailure('api_' + method.replace('.', '_') + '_failed')
        return value['result']

    def start(self):
        # No TUI launch: this server cannot federate through an attached client.
        self.server = subprocess.Popen(self.command + ['server'], env=self.env, cwd=self.workspace,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        def ready():
            if self.server.poll() is not None:
                raise ProofFailure('owned_server_exited')
            try:
                return self.result('ping')
            except ProofFailure:
                return False
        eventually(ready, 'owned_server_start_timeout')
        ws = self.result('workspace.create', {'cwd': str(self.workspace), 'label': 'Codex qualification', 'focus': True})['workspace']
        started = self.result('agent.start_integrated', {'provider': 'codex', 'workspace_id': ws['workspace_id'], 'cwd': str(self.workspace)})
        self.pane = started['agent']['pane_id']
        self.identity = {key: started[key] for key in ('server_instance', 'recipient_token')}
        self.identity['terminal_id'] = started['agent']['terminal_id']
        eventually(lambda: self.status() == 'idle', 'provider_startup_unverified')

    def status(self):
        return self.result('agent.get', {'target': self.pane})['agent']['agent_status']

    def preview(self):
        return self.result('pane.read', {'pane_id': self.pane, 'source': 'recent', 'format': 'text', 'lines': 500, 'strip_ansi': True})['read']['text']

    def submit(self, text):
        reply = self.result('agent.prompt_exact', dict(self.identity, text=text))
        if (reply.get('outcome') != 'accepted' or reply.get('acceptance') != 'provider_input_accepted'
                or not reply.get('submission_id')
                or any(reply.get(key) != value for key, value in self.identity.items())):
            raise ProofFailure('provider_ack_unverified')
        return reply['submission_id']

    def open_consent_view(self):
        self.result('agent.focus', {'target': self.pane})
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 120, 500, 0, 0))
        self.client_pty = master
        try:
            self.client = subprocess.Popen(self.command + ['client'], env=self.env, cwd=self.workspace,
                                           stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        finally:
            os.close(slave)

    def drain_client(self):
        if self.client is not None and self.client.poll() is not None:
            raise ProofFailure('consent_client_exited')
        if self.client_pty is not None and select.select([self.client_pty], [], [], 0)[0]:
            os.read(self.client_pty, 256 * 1024)

    def permission_exercise(self, thread, decision):
        path = self.consent_root / (decision + '.txt')
        executable = self.root / ('consent-write-' + decision)
        body = '#!/bin/sh\n[ \"$#\" -eq 0 ] || exit 2\nprintf herdr-codex-proof > ' + shlex.quote(str(path)) + '\n'
        executable.write_text(body)
        executable.chmod(0o700)
        command = str(executable)
        prompt = ('Perform only this bounded qualification operation: request command approval using '
                  'exec_command with sandbox_permissions=require_escalated for the exact command ' + command +
                  '. Do not change any other files. Do not use apply_patch or another write route. '
                  'If approval is denied, stop and reply DENIED without retrying. If allowed, reply ALLOWED.')
        turn = self.submit(prompt)
        def requested_or_completed():
            self.drain_client()
            return self.status() in ('blocked', 'idle')
        eventually(requested_or_completed, 'permission_request_timeout', timeout=90)
        if self.status() != 'blocked':
            raise ProofFailure('permission_not_requested_' + decision + ('_scratch_present' if path.exists() else '_scratch_absent'))
        # Wait for the renderer to publish the full matching card. Never authorize
        # an operation inferred from model prose or a partial/truncated card.
        def visible():
            self.drain_client()
            try:
                consent_request(self.preview(), thread, turn, command, str(self.workspace))
                return True
            except ProofFailure:
                return False
        eventually(visible, 'consent_scope_unverified_' + decision, timeout=10)
        if path.exists() or executable.read_text() != body:
            raise ProofFailure('scratch_changed_before_consent')
        # Only the fixed allow/deny word enters the helper's consent UI. All prompt
        # bodies used agent.prompt_exact above, never pane input or terminal typing.
        self.result('pane.send_input', {'pane_id': self.pane, 'text': decision, 'keys': ['Enter']})
        def completed():
            self.drain_client()
            return self.status() == 'idle'
        eventually(completed, 'permission_completion_unverified_' + decision, timeout=90)
        if decision == 'allow':
            if not path.is_file() or path.read_bytes() != b'herdr-codex-proof':
                raise ProofFailure('allowed_scratch_effect_unverified')
        elif path.exists():
            raise ProofFailure('denied_scratch_changed')

    def close(self):
        if self.closed:
            if self.cleanup_failure is not None:
                raise self.cleanup_failure
            return
        self.closed = True
        errors = [self.cleanup_failure] if self.cleanup_failure is not None else []
        if self.server is not None:
            cleanup_step(errors, lambda: observe_owned(self, self.server.pid))
        if self.client is not None and self.client.poll() is None:
            cleanup_step(errors, lambda: reap_owned(self.client))
        if self.client_pty is not None:
            cleanup_step(errors, lambda: os.close(self.client_pty))
        if self.server is not None and self.server.poll() is None:
            try:
                stopped = subprocess.run(self.command + ['server', 'stop'], env=self.env, cwd=self.workspace,
                                         capture_output=True, timeout=10)
                if stopped.returncode:
                    raise ProofFailure('owned_stop_failed')
                self.server.wait(timeout=10)
            except (OSError, subprocess.SubprocessError, ProofFailure):
                errors.append(ProofFailure('owned_cleanup_fallback'))
                cleanup_step(errors, lambda: reap_owned(self.server))
        elif self.server is not None:
            cleanup_step(errors, lambda: self.server.wait(timeout=3))
        cleanup_step(errors, lambda: eventually(lambda: not (self.owned_children & process_parents().keys()),
                                               'owned_descendant_cleanup_unverified', timeout=5))
        self.cleanup_failure = errors[0] if errors else None
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


def live(args):
    validate_targets(args.session, args.scratch)
    if args.consent_scratch is not None:
        validate_targets(args.session, args.consent_scratch)
        if args.consent_scratch == args.scratch:
            raise ProofFailure('consent_target_must_be_distinct')
    binary = validate_binary(args.herdr_bin)
    process_parents()  # Verify this prerequisite before any provider launch or target creation.
    provider = validate_provider(args.provider_path)
    args.scratch.mkdir(mode=0o700)
    if args.consent_scratch is not None:
        args.consent_scratch.mkdir(mode=0o700)
    report = {'provider_version': '0.154.0', 'session': args.session, 'scratch': str(args.scratch),
              'platform': os.uname().sysname, 'qualification': 'UNVERIFIED', 'live_smoke': 'UNVERIFIED',
              'strict_test_policy': args.strict_test_policy,
              'fixed_thread': 'UNVERIFIED', 'matching_ack': 'UNVERIFIED',
              'permission_allow_deny': 'UNVERIFIED', 'child_fd_isolation': 'UNVERIFIED',
              'queued_reset_replacement': 'UNVERIFIED'}
    session = Session(binary, args.session, args.scratch, provider, args.consent_scratch, args.strict_test_policy)
    try:
        session.start()
        preview = session.preview()
        thread = re.search(r'fixed thread ([0-9a-f-]{36})', preview)
        if not thread:
            raise ProofFailure('fixed_thread_presentation_unverified')
        report['fixed_thread'] = 'PASS'
        sandbox_text = preview.split('Sandbox:', 1)[-1].split('Exact delivery', 1)[0]
        try:
            sandbox = json.loads(''.join(line.strip().strip('│').strip() for line in sandbox_text.splitlines()))
            roots = sandbox.get('writableRoots', [])
            report['explicit_writable_root_count'] = len(roots)
            report['consent_under_explicit_writable_root'] = any(session.consent_root.is_relative_to(Path(root)) for root in roots)
            report['exclude_tmpdir_env_var'] = sandbox.get('excludeTmpdirEnvVar')
            report['exclude_slash_tmp'] = sandbox.get('excludeSlashTmp')
        except (ValueError, TypeError):
            report['effective_writable_roots'] = 'unparsed'
        report['effective_approval_policy'] = next((policy for policy in ('never', 'on-request', 'untrusted', 'on-failure') if 'Approval policy: \"' + policy + '\"' in preview), 'unparsed')
        if args.strict_test_policy and report['effective_approval_policy'] != 'on-request':
            raise ProofFailure('strict_policy_not_effective')
        report['effective_sandbox'] = next((policy for policy in ('readOnly', 'workspaceWrite', 'dangerFullAccess', 'read-only', 'workspace-write', 'danger-full-access', 'externalSandbox') if policy in preview), 'unparsed')
        session.submit('Reply with exactly HERDR_CODEX_PROOF_OK. Do not run tools or change files.')
        report['matching_ack'] = 'PASS'
        eventually(lambda: session.status() == 'idle', 'harmless_turn_completion_unverified', timeout=90)
        if 'HERDR_CODEX_PROOF_OK' not in session.preview():
            raise ProofFailure('harmless_response_unverified')
        report['harmless_turn'] = 'PASS'
        session.open_consent_view()
        for decision in ('deny', 'allow'):
            session.permission_exercise(thread[1], decision)
            report['permission_' + decision] = 'PASS'
        report['permission_allow_deny'] = 'PASS'
        report['live_smoke'] = 'PASS'
    except (ProofFailure, subprocess.TimeoutExpired) as error:
        report['diagnostic'] = str(error) if isinstance(error, ProofFailure) else 'subprocess_timeout'
    finally:
        try:
            session.close()
            report['owned_cleanup'] = 'PASS'
        except ProofFailure as error:
            report['owned_cleanup'] = 'UNVERIFIED'
            report['diagnostic'] = str(error)
        print(json.dumps(report, sort_keys=True))
        # Preserve only redacted evidence; provider logs can contain intended input.
        if report.get('owned_cleanup') == 'PASS':
            shutil.rmtree(args.scratch)
            shutil.rmtree(session.state_root)
            if args.consent_scratch is not None:
                shutil.rmtree(args.consent_scratch)
    return 0 if report['live_smoke'] == 'PASS' and report.get('owned_cleanup') == 'PASS' else 1


# This child emits descriptor metadata only; it never reads auth or configuration.
DESCRIPTOR_CHILD = r'''
import json,os,sys
from pathlib import Path
mode,receipt=sys.argv[1:]
def metadata():
 fds=[]
 for name in os.listdir('/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'):
  try:
   fd=int(name);s=os.fstat(fd)
   fds.append([fd,s.st_dev,s.st_ino,s.st_mode])
  except (ValueError,OSError): pass
 return {'pid':os.getpid(),'fds':fds}
def record(extra):
 value=metadata();value.update(extra)
 Path(receipt).write_text(json.dumps(value))
if mode=='hook':
 value=json.load(sys.stdin)
 assert value.get('hook_event_name')=='SessionStart'
 record({'input_kind':'SessionStart'})
 print(json.dumps({'continue':False,'stopReason':'owned descriptor fixture complete'}),flush=True)
elif mode=='mcp':
 first=True
 for line in sys.stdin:
  value=json.loads(line)
  if first:
   assert value['method']=='initialize'
   record({'input_kind':'initialize'})
   first=False
  if 'id' not in value: continue
  method=value.get('method')
  result=({'protocolVersion':value['params']['protocolVersion'],'capabilities':{'tools':{}},'serverInfo':{'name':'herdr-owned-descriptor-fixture','version':'1'}}
          if method=='initialize' else {'tools':[]} if method=='tools/list' else {})
  print(json.dumps({'jsonrpc':'2.0','id':value['id'],'result':result}),flush=True)
else:
 if mode=='pty':
  import tty
  tty.setraw(0)
  print('READY',flush=True)
  value=os.read(0,6).decode()
 else:
  if mode=='pipe': print('READY',flush=True)
  value=sys.stdin.read()
 print(json.dumps(dict(metadata(),input=value)),flush=True)
'''


def descriptor_environment(root):
    # Descriptor fixtures cannot use existing credentials or provider configuration.
    # HOME is preserved; only this subprocess sees an empty owned CODEX_HOME.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('OPENAI_') and key not in ('CODEX_API_KEY', 'CODEX_ACCESS_TOKEN')}
    provider_home = root / 'codex-home'
    provider_home.mkdir(mode=0o700, exist_ok=True)
    env.update(CODEX_HOME=str(provider_home), CODEX_SQLITE_HOME=str(root / 'sqlite'))
    return env


class DirectProvider:
    """Bounded observer for shipped-binary fixtures, never a product transport."""
    def __init__(self, binary, root, overrides=(), owners=None):
        self.buffer = b''
        self.responses = {}
        self.notifications = []
        self.stderr_bytes = 0
        self.owned_children = set()
        self.closed = False
        self.cleanup_failure = None
        self.sequence = 0
        env = descriptor_environment(root)
        read_fd, write_fd = os.pipe()
        stat = os.fstat(read_fd)
        self.control_identity = [stat.st_dev, stat.st_ino, stat.st_mode]
        command = [binary]
        for override in overrides:
            command += ['-c', override]
        command += ['app-server', '--listen', 'stdio://']
        try:
            self.child = subprocess.Popen(command, stdin=read_fd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, env=env, cwd=root, start_new_session=True)
        except BaseException:
            os.close(write_fd)
            raise
        finally:
            os.close(read_fd)
        self.input = os.fdopen(write_fd, 'wb', buffering=0)
        if owners is not None:
            owners.append(self)
        try:
            reply = self.call('initialize', {'clientInfo': {'name': 'herdr_descriptor_fixture', 'version': '1'},
                                             'capabilities': {'experimentalApi': True}})
            if reply.get('userAgent', '').split()[0].rsplit('/', 1)[-1] != '0.154.0':
                raise ProofFailure('fixture_initialize_version_mismatch')
            self.send({'method': 'initialized'})
            if self.call('account/read', {'refreshToken': False}).get('account') is not None:
                raise ProofFailure('fixture_unexpected_authenticated_account')
        except BaseException:
            self.close()
            raise

    def send(self, frame):
        data = (json.dumps(frame) + '\n').encode()
        if len(data) > 512 * 1024:
            raise ProofFailure('fixture_input_bound')
        self.input.write(data)

    def request(self, method, params):
        self.sequence += 1
        request_id = 'fixture-' + str(self.sequence)
        self.send({'id': request_id, 'method': method, 'params': params})
        return request_id

    def frame(self, deadline):
        observe_owned(self, self.child.pid)
        while b'\n' not in self.buffer:
            if time.monotonic() >= deadline:
                raise ProofFailure('fixture_provider_deadline')
            streams, _, _ = select.select([self.child.stdout, self.child.stderr], [], [], .1)
            for stream in streams:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    if self.child.poll() is not None:
                        raise ProofFailure('fixture_provider_exited')
                    continue
                if stream is self.child.stderr:
                    self.stderr_bytes += len(chunk)
                    if self.stderr_bytes > 65536:
                        raise ProofFailure('fixture_stderr_bound')
                else:
                    self.buffer += chunk
                    if len(self.buffer) > 1024 * 1024:
                        raise ProofFailure('fixture_output_bound')
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def observe(self, deadline):
        frame = self.frame(deadline)
        if 'id' in frame and 'method' not in frame:
            self.responses[frame['id']] = frame
        elif 'id' in frame:
            self.send({'id': frame['id'], 'error': {'code': -32601, 'message': 'Unsupported fixture request'}})
        else:
            self.notifications.append(frame)
        if len(self.responses) + len(self.notifications) > 256:
            raise ProofFailure('fixture_pending_bound')

    def response(self, request_id, timeout=30):
        deadline = time.monotonic() + timeout
        while request_id not in self.responses:
            self.observe(deadline)
        frame = self.responses.pop(request_id)
        if 'error' in frame:
            raise ProofFailure('fixture_provider_request_error')
        return frame['result']

    def output(self, process_id):
        return b''.join(base64.b64decode(frame['params']['deltaBase64'])
                        for frame in self.notifications
                        if frame.get('method') == 'command/exec/outputDelta'
                        and frame['params']['processId'] == process_id)

    def call(self, method, params):
        return self.response(self.request(method, params))

    def close(self):
        if self.closed:
            if self.cleanup_failure is not None:
                raise self.cleanup_failure
            return
        self.closed = True
        errors = [self.cleanup_failure] if self.cleanup_failure is not None else []
        cleanup_step(errors, lambda: observe_owned(self, self.child.pid))
        unexpected_exit = self.child.poll() is not None
        cleanup_step(errors, self.input.close)
        cleanup_step(errors, lambda: reap_owned(self.child, graceful=True))
        cleanup_step(errors, self.child.stdout.close)
        cleanup_step(errors, self.child.stderr.close)
        cleanup_step(errors, lambda: eventually(lambda: not (self.owned_children & process_parents().keys()),
                                               'fixture_owned_tree_cleanup', timeout=5))
        if unexpected_exit:
            errors.append(ProofFailure('fixture_unexpected_exit_cleanup_unverified'))
        self.cleanup_failure = errors[0] if errors else None
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


def assert_isolated(record, control_identity):
    fds = record['fds']
    if not any(fd[0] == 0 for fd in fds) or any(fd[1:] == control_identity for fd in fds):
        raise ProofFailure('provider_control_fd_inherited')


def fixture_command_failure(result):
    """Return bounded diagnostic categories, never provider output or paths."""
    stderr = result.get('stderr')
    stderr = stderr[:65536].lower() if isinstance(stderr, str) else ''
    cause = 'unclassified'
    if 'bwrap:' in stderr and 'namespace' in stderr:
        cause = 'namespace_setup'
    elif 'error while loading shared libraries:' in stderr and 'libpython' in stderr:
        cause = 'python_shared_library_loader'
    elif any(message in stderr for message in ('permission denied', 'exec format error', 'no such file or directory')):
        cause = 'executable_or_permission'
    detail = {'tool_failure_cause': cause}
    exit_code = result.get('exitCode')
    if type(exit_code) is int and -(2 ** 31) <= exit_code < 2 ** 31:
        detail['tool_failure_exit_code'] = exit_code
    return detail


# Literal, source-backed message observations, never extracted paths or suffixes.
# Each label matches any alternative whose literals all occur in one stream.
RUNTIME_SIGNATURES = (
    ('bwrap_build', (('error building bubblewrap command:',),)),
    ('readonly_writable_symlink', (('cannot enforce sandbox read-only path', 'because it crosses writable symlink'),)),
    ('denyread_writable_symlink', (('cannot enforce sandbox deny-read path', 'because it crosses writable symlink'),)),
    ('unreadable_glob', (('cannot be safely expanded',), ('ripgrep unreadable glob scan failed',),
                         ('unreadable glob pattern is invalid',), ('unreadable glob matcher failed',))),
    ('bwrap_unavailable', (('bubblewrap is unavailable:',),)),
    ('bwrap_message', (('bwrap:',),)),
    ('namespace_message', (('namespace', 'bwrap:'), ('error isolating linux network namespace',))),
    ('proc_mount', (("can't mount proc", '/newroot/proc'),)),
    ('inner_mount_verify', (('failed to verify descriptor-backed bubblewrap mount:',),)),
    ('inner_capabilities', (('failed to verify linux sandbox capabilities:',),
                            ('linux sandbox retained effective or permitted capabilities',))),
    ('sandbox_restrictions', (('error applying linux sandbox restrictions:',),
                              ('error applying legacy linux sandbox restrictions:',))),
    ('child_exec', (('failed to execvp',),)),
    ('protected_metadata', (('sandbox blocked creation of protected workspace metadata path',),)),
    ('python_loader', (('error while loading shared libraries:', 'libpython'),)),
    ('python_traceback', (('traceback (most recent call last):',),)),
    ('permission', (('permission denied',),)),
    ('missing', (('no such file or directory',),)),
    ('exec_format', (('exec format error',),)),
    ('operation_not_permitted', (('operation not permitted',),)),
    ('invalid_argument', (('invalid argument',),)),
    ('bwrap_capget_root', (('capget (for uid == 0) failed',),)),
    ('bwrap_bind_dirfd_race', (('race condition binding dirfd',),)),
    ('bwrap_rtm_newaddr', (('loopback: failed rtm_newaddr',),)),
    ('bwrap_rtm_newlink', (('loopback: failed rtm_newlink',),)),
)


def runtime_exit_code(result):
    value = result.get('exitCode') if isinstance(result, dict) else None
    return value if type(value) is int and -(2 ** 31) <= value < 2 ** 31 else None


def runtime_output_metadata(result, key):
    value = result.get(key)
    kind = 'absent' if key not in result else 'string' if isinstance(value, str) else 'other'
    # JSON may contain lone surrogate escapes. Replace them privately; never
    # format decoding exceptions or retain another provider-output buffer.
    data = value.encode('utf-8', errors='replace') if kind == 'string' else b''
    scan = data[:65536]
    text = scan.decode('utf-8', errors='ignore').lower()
    signatures = [label for label, alternatives in RUNTIME_SIGNATURES
                  if any(all(literal in text for literal in literals) for literals in alternatives)]
    return {'type': kind, 'observed_utf8_bytes': min(len(data), 4194305),
            'scan_utf8_bytes': len(scan), 'scan_truncated': len(data) > len(scan),
            'signatures': signatures, 'unmatched_nonempty': bool(data) and not signatures}


def runtime_probe_observation(result=None, outcome='not_run'):
    response = result if isinstance(result, dict) else {}
    return {'exit_code': runtime_exit_code(result), 'outcome': outcome,
            'stdout': runtime_output_metadata(response, 'stdout'),
            'stderr': runtime_output_metadata(response, 'stderr')}


def diagnose_provider_runtime(client, root, python, original):
    """At most two supplemental requests; the failed control is never retried."""
    deadline = time.monotonic() + 65
    detail = {'original_control': runtime_probe_observation(original, 'response'),
              'true': runtime_probe_observation(), 'python_startup': runtime_probe_observation(),
              'python_started': False}
    for name, command in (('true', ['/bin/true']),
                          ('python_startup', [python, '-c', "print('HERDR_DIAG_PYTHON_STARTED', flush=True)"])):
        try:
            if time.monotonic() >= deadline:
                raise ProofFailure('fixture_provider_deadline')
            observe_owned(client, client.child.pid)
            if client.child.poll() is not None:
                raise ProofFailure('fixture_provider_exited')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProofFailure('fixture_provider_deadline')
            request = client.request('command/exec', {'command': command, 'cwd': str(root), 'timeoutMs': 10000})
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProofFailure('fixture_provider_deadline')
            result = client.response(request, timeout=min(30, remaining))
            if time.monotonic() >= deadline:
                raise ProofFailure('fixture_provider_deadline')
            if runtime_exit_code(result) is None:
                detail[name] = runtime_probe_observation(result, 'malformed_result')
                break
            detail[name] = runtime_probe_observation(result, 'response')
            if name == 'python_startup':
                detail['python_started'] = result['exitCode'] == 0 and result.get('stdout') == 'HERDR_DIAG_PYTHON_STARTED\n'
        except Exception as error:
            # Provider text, including unexpected exception contents, is never
            # interpolated. Only exact internal categories select an outcome.
            outcome = 'transport_error'
            if isinstance(error, ProofFailure):
                outcome = {
                    'fixture_provider_request_error': 'rpc_error',
                    'fixture_provider_deadline': 'deadline',
                    'fixture_input_bound': 'bound', 'fixture_output_bound': 'bound',
                    'fixture_stderr_bound': 'bound', 'fixture_pending_bound': 'bound',
                    'fixture_provider_exited': 'provider_exit',
                    'process_inspection_unavailable': 'ownership_unverified',
                }.get(error.args[0] if error.args and type(error.args[0]) is str else '', 'transport_error')
            elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
                outcome = 'deadline'
            elif isinstance(error, (ValueError, KeyError, TypeError)):
                outcome = 'malformed_result'
            detail[name] = runtime_probe_observation(outcome=outcome)
            break
    # Every value above is an explicit scalar or fixed signature. Even with all
    # signatures in every stream this schema fits in 8 KiB (covered by tests).
    return detail


def runtime_environment_metadata():
    """Fixed read-only parent observations; these do not attest sandbox policy."""
    system_executable = None
    try:
        system_executable = stat.S_ISREG(os.stat('/usr/bin/bwrap').st_mode) and os.access('/usr/bin/bwrap', os.X_OK)
    except FileNotFoundError:
        system_executable = False
    except OSError:
        pass
    parent_is_system = None
    try:
        candidate = shutil.which('bwrap')
        if candidate is not None:
            parent_is_system = os.path.samefile(candidate, '/usr/bin/bwrap')
    except (OSError, ValueError):
        pass

    def read_scalar(path, values):
        try:
            with open(path, 'rb') as source:
                value = source.read(8)
            # A full buffer may be an incomplete value. Never accept its prefix.
            return values.get(value.strip()) if len(value) < 8 else None
        except OSError:
            return None

    apparmor = read_scalar('/sys/module/apparmor/parameters/enabled', {b'Y': True, b'N': False})
    restrict_userns = read_scalar('/proc/sys/kernel/apparmor_restrict_unprivileged_userns', {b'0': 0, b'1': 1})
    profile_present = None
    try:
        profile_present = stat.S_ISREG(os.stat('/etc/apparmor.d/bwrap').st_mode)
    except FileNotFoundError:
        profile_present = False
    except OSError:
        pass
    return {'system_bwrap_executable': system_executable,
            'parent_path_bwrap_is_system': parent_is_system,
            'apparmor_enabled': apparmor, 'restrict_unprivileged_userns': restrict_userns,
            'bwrap_profile_file_present': profile_present}


# This request runs only in the reviewed Linux CI candidate, under the same
# command/exec default policy/cwd as the descriptor requests. Never emit paths,
# labels, capability values, errors or socket endpoints from the child.
ENFORCEMENT_KEYS = frozenset(('stacked_enforce', 'effective_caps_zero', 'permitted_caps_zero',
                              'no_new_privs', 'seccomp_filter', 'python_started', 'nonroot',
                              'outside_write_denied', 'loopback_connect_denied'))
ENFORCEMENT_CHILD = r'''
import errno,json,os,socket,sys
from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
result={
 'stacked_enforce':Path('/proc/self/attr/current').read_text().strip('\n\0')=='bwrap//&unpriv_bwrap (enforce)',
 'effective_caps_zero':status.get('CapEff','').strip()=='0000000000000000',
 'permitted_caps_zero':status.get('CapPrm','').strip()=='0000000000000000',
 'no_new_privs':status.get('NoNewPrivs','').strip()=='1',
 'seccomp_filter':status.get('Seccomp','').strip()=='2',
 'python_started':True,'nonroot':os.getuid()!=0,
 'outside_write_denied':False,'loopback_connect_denied':False,
}
try:
 with open(sys.argv[1],'wb') as handle: handle.write(b'changed')
except OSError as error:
 result['outside_write_denied']=error.errno in (errno.EACCES,errno.EPERM,errno.EROFS)
try:
 with socket.create_connection(('127.0.0.1',int(sys.argv[2])),timeout=0.5): pass
except OSError as error:
 result['loopback_connect_denied']=isinstance(error,TimeoutError) or error.errno in (errno.EACCES,errno.EPERM,errno.ECONNREFUSED,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ETIMEDOUT)
print(json.dumps(result,sort_keys=True),flush=True)
'''


def enforcement_observation(result):
    if (runtime_exit_code(result) != 0 or not isinstance(result.get('stdout'), str) or
            len(result['stdout']) > 1024 or result.get('stderr', '') != ''):
        raise ProofFailure('fixture_enforcement_malformed')
    try:
        value = json.loads(result['stdout'])
    except (ValueError, TypeError):
        raise ProofFailure('fixture_enforcement_malformed') from None
    if not isinstance(value, dict) or set(value) != ENFORCEMENT_KEYS or any(type(v) is not bool for v in value.values()):
        raise ProofFailure('fixture_enforcement_malformed')
    if not all(value.values()):
        raise ProofFailure('fixture_enforcement_not_proven')
    return value


def linux_enforcement(client, root, python):
    # HOME is intentionally preserved by descriptor_environment. Use a NEW
    # private child of that directory, outside cwd and the /tmp writable roots.
    try:
        from ci_codex_sandbox import BWRAP, RESOURCE_HASH, RUNTIME, Refused, chain, digest, identity, target
    except ModuleNotFoundError:
        from scripts.ci_codex_sandbox import BWRAP, RESOURCE_HASH, RUNTIME, Refused, chain, digest, identity, target
    try:
        target()
        chain(RUNTIME)
        identity(BWRAP, mode=0o755)
    except (Refused, OSError):
        raise ProofFailure('fixture_candidate_environment') from None
    if shutil.which('bwrap') != str(BWRAP) or digest(BWRAP.read_bytes()) != RESOURCE_HASH:
        raise ProofFailure('fixture_candidate_not_first')
    help_result = subprocess.run([str(BWRAP), '--help'], capture_output=True, timeout=10)
    if help_result.returncode or not all(flag in help_result.stdout for flag in (b'--as-pid-1', b'--perms', b'--argv0', b'--ro-bind-fd')):
        raise ProofFailure('fixture_candidate_ineligible')
    with tempfile.TemporaryDirectory(prefix='herdr-codex-denial-', dir=Path.home()) as temporary, socket.socket() as listener:
        canary = Path(temporary) / 'canary'
        if root == canary.parent or root in canary.parents or Path('/tmp') in canary.parents:
            raise ProofFailure('fixture_denial_target_invalid')
        canary.write_bytes(b'parent-control')
        if canary.read_bytes() != b'parent-control':
            raise ProofFailure('fixture_parent_write_control')
        canary.write_bytes(b'owned-before')
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(1)
        with socket.create_connection(listener.getsockname(), timeout=1) as control:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b'ok')
            if control.recv(2) != b'ok':
                raise ProofFailure('fixture_parent_network_control')
        request = client.request('command/exec', {'command': [python, '-c', ENFORCEMENT_CHILD,
                                 str(canary), str(listener.getsockname()[1])], 'cwd': str(root), 'timeoutMs': 10000})
        observation = enforcement_observation(client.response(request, timeout=30))
        if canary.read_bytes() != b'owned-before':
            raise ProofFailure('fixture_outside_canary_changed')
        listener.settimeout(0.1)
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            pass
        else:
            connection.close()
            raise ProofFailure('fixture_listener_reached')
        return dict(observation, parent_write_control=True, parent_connect_control=True,
                    canary_unchanged=True, parent_listener_unreached=True)


def provider_fixtures(args):
    validate_targets(args.session, args.scratch)
    process_parents()
    provider = validate_provider(args.provider_path)
    args.scratch.mkdir(mode=0o700)
    root = args.scratch
    script = root / 'descriptor_child.py'
    script.write_text(DESCRIPTOR_CHILD)
    python = str(Path(os.sys.executable).resolve())
    report = {'provider_version': '0.154.0', 'platform': os.uname().sysname,
              'qualification': 'UNVERIFIED', 'tool_fd_isolation': 'UNVERIFIED',
              'hook_fd_isolation': 'UNVERIFIED', 'mcp_fd_isolation': 'UNVERIFIED'}
    client = None
    providers = []
    owned_children = set()
    try:
        diagnose = getattr(args, 'diagnose_provider_runtime', False) and os.sys.platform == 'linux'
        if diagnose:
            report['runtime_environment'] = runtime_environment_metadata()
        client = DirectProvider(provider, root, owners=providers)
        for mode in ('null', 'pipe', 'pty'):
            params = {'command': [python, str(script), mode, '-'], 'cwd': str(root), 'timeoutMs': 10000}
            process_id = 'owned-' + mode
            if mode != 'null':
                params.update(processId=process_id, streamStdin=True, streamStdoutStderr=True)
            if mode == 'pty':
                params.update(tty=True, size={'rows': 24, 'cols': 80})
            request_id = client.request('command/exec', params)
            if mode != 'null':
                deadline = time.monotonic() + 10
                while b'READY' not in client.output(process_id):
                    client.observe(deadline)
                client.call('command/exec/write', {'processId': process_id,
                            'deltaBase64': base64.b64encode(b'pty-ok' if mode == 'pty' else b'child-only').decode(), 'closeStdin': mode == 'pipe'})
            result = client.response(request_id)
            if diagnose and runtime_exit_code(result) is None:
                raise ProofFailure('fixture_malformed_result')
            if result['exitCode'] != 0:
                report.update(fixture_command_failure(result))
                if diagnose and mode == 'null':
                    report['runtime_diagnostics'] = diagnose_provider_runtime(client, root, python, result)
                raise ProofFailure('fixture_tool_failed_' + mode)
            output = client.output(process_id).split(b'READY\n', 1)[-1] if mode != 'null' else result['stdout']
            observation = json.loads(output)
            assert_isolated(observation, client.control_identity)
            if observation['input'] != ('child-only' if mode == 'pipe' else 'pty-ok' if mode == 'pty' else ''):
                raise ProofFailure('fixture_tool_input_mismatch')
        if getattr(args, 'require_linux_enforcement', False):
            report['linux_enforcement'] = linux_enforcement(client, root, python)
        report['provider_authentication'] = 'PASS_no_account_empty_home'
        report['tool_fd_isolation'] = 'PASS_null_private_pipe_and_pty'
        client.close()
        client = None
        hook_receipt = root / 'hook-descriptors.json'
        mcp_receipt = root / 'mcp-descriptors.json'
        hook_command = shlex.join([python, str(script), 'hook', str(hook_receipt)])
        overrides = [
            'hooks.SessionStart=[{hooks=[{type="command",command=' + json.dumps(hook_command) + ',timeout=10}]}]',
            'mcp_servers.herdr_descriptor={command=' + json.dumps(python) + ',args=' +
            json.dumps([str(script), 'mcp', str(mcp_receipt)]) + ',startup_timeout_sec=10}',
        ]
        client = DirectProvider(provider, root, overrides, owners=providers)
        listed = client.call('hooks/list', {'cwds': [str(root)]})
        hooks = [hook for entry in listed['data'] for hook in entry['hooks']
                 if hook.get('command') == hook_command and hook.get('eventName') == 'sessionStart']
        if len(hooks) != 1:
            raise ProofFailure('owned_hook_not_discovered')
        hook = hooks[0]
        # Exactly one reviewed owned command's current hash. This is a process-local
        # CLI layer: no config-write RPC, user hook changes, or blanket bypass.
        overrides.append('hooks.state={' + json.dumps(hook['key']) + '={trusted_hash=' + json.dumps(hook['currentHash']) + '}}')
        client.close()
        client = DirectProvider(provider, root, overrides, owners=providers)
        verified = client.call('hooks/list', {'cwds': [str(root)]})
        matches = [h for entry in verified['data'] for h in entry['hooks'] if h['key'] == hook['key']]
        if len(matches) != 1 or matches[0]['trustStatus'] != 'trusted' or matches[0]['currentHash'] != hook['currentHash']:
            raise ProofFailure('owned_hook_hash_not_trusted')
        thread = client.call('thread/start', {'cwd': str(root), 'ephemeral': True})['thread']['id']
        turn = client.call('turn/start', {'threadId': thread, 'input': [{'type': 'text', 'text': 'Owned descriptor fixture; the SessionStart hook must stop this turn.'}]})['turn']['id']
        deadline = time.monotonic() + 20
        def completed():
            return any(frame.get('method') == 'turn/completed' and frame['params']['threadId'] == thread
                       and frame['params']['turn']['id'] == turn for frame in client.notifications)
        while not completed():
            client.observe(deadline)
        hook_runs = [frame['params']['run'] for frame in client.notifications
                     if frame.get('method') == 'hook/completed' and frame['params']['threadId'] == thread]
        if not any(run.get('status') == 'stopped' and run.get('sourcePath') == hook['sourcePath']
                   and run.get('displayOrder') == hook['displayOrder']
                   and run.get('eventName') == 'sessionStart'
                   and {'kind': 'stop', 'text': 'owned descriptor fixture complete'} in run.get('entries', [])
                   for run in hook_runs):
            raise ProofFailure('fixture_hook_stop_not_observed')
        if any(frame.get('method') == 'item/agentMessage/delta' or
               (frame.get('method') == 'item/started' and frame['params']['item']['type'] in ('agentMessage', 'commandExecution', 'mcpToolCall'))
               for frame in client.notifications):
            raise ProofFailure('fixture_unexpected_model_or_tool_output')
        report['hook_stopped_before_model_output'] = 'PASS'
        for receipt, key, kind in ((hook_receipt, 'hook_fd_isolation', 'SessionStart'),
                                   (mcp_receipt, 'mcp_fd_isolation', 'initialize')):
            eventually(receipt.is_file, 'fixture_child_not_observed_' + key, timeout=15)
            observation = json.loads(receipt.read_text())
            owned_children.add(observation['pid'])
            assert_isolated(observation, client.control_identity)
            if observation['input_kind'] != kind:
                raise ProofFailure('fixture_child_wrong_input')
            report[key] = 'PASS'
    except (ProofFailure, subprocess.TimeoutExpired) as error:
        report['diagnostic'] = str(error) if isinstance(error, ProofFailure) else 'fixture_timeout'
    finally:
        errors = []
        for provider in providers:
            cleanup_step(errors, provider.close)
        cleanup_step(errors, lambda: eventually(lambda: not (owned_children & process_parents().keys()),
                                               'fixture_owned_child_cleanup', timeout=5))
        if not errors:
            report['owned_cleanup'] = 'PASS'
            shutil.rmtree(root)
        else:
            report['owned_cleanup'] = 'UNVERIFIED'
            if 'runtime_diagnostics' not in report:
                report['diagnostic'] = str(errors[0])
        print(json.dumps(report, sort_keys=True))
    return 0 if all(report[key].startswith('PASS') for key in ('tool_fd_isolation', 'hook_fd_isolation', 'mcp_fd_isolation', 'owned_cleanup')) else 1


class SafetyTests(unittest.TestCase):
    def test_enforcement_requires_exact_true_boolean_evidence(self):
        good = {key: True for key in ENFORCEMENT_KEYS}
        result = {'exitCode': 0, 'stdout': json.dumps(good), 'stderr': ''}
        self.assertEqual(enforcement_observation(result), good)
        for key in good:
            for value in (False, 1, None, 'true'):
                with self.subTest(key=key, value=value), self.assertRaises(ProofFailure):
                    enforcement_observation(dict(result, stdout=json.dumps(dict(good, **{key: value}))))
            missing = dict(good)
            del missing[key]
            with self.assertRaises(ProofFailure):
                enforcement_observation(dict(result, stdout=json.dumps(missing)))
        for bad in ({'exitCode': 1}, dict(result, stderr='private diagnostic'),
                    dict(result, stdout='[]'), dict(result, stdout='secret' * 500),
                    dict(result, stdout=json.dumps(dict(good, extra=True)))):
            with self.assertRaises(ProofFailure):
                enforcement_observation(bad)

    def test_enforcement_child_observes_kernel_fields_and_only_owned_denials(self):
        import errno
        original = {'CapEff': '0000000000000000', 'CapPrm': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}
        scenarios = [(None, None, None), ('CapEff', '0000000000000001', 'effective_caps_zero'),
                     ('CapPrm', '0000000000000001', 'permitted_caps_zero'),
                     ('NoNewPrivs', '0', 'no_new_privs'), ('Seccomp', '0', 'seccomp_filter'),
                     ('label', 'unconfined', 'stacked_enforce'),
                     ('label', 'bwrap//&unpriv_bwrap (complain)', 'stacked_enforce'),
                     ('label', 'prefix-bwrap//&unpriv_bwrap (enforce)', 'stacked_enforce')]
        for key, value, expected_false in scenarios:
            status = dict(original)
            if key in status:
                status[key] = value
            label = value if key == 'label' else 'bwrap//&unpriv_bwrap (enforce)'
            def read(path, *args, **kwargs):
                return label + '\n' if str(path).endswith('/attr/current') else '\n'.join(k + ':\t' + v for k, v in status.items())
            with self.subTest(key=key, value=value), mock.patch.object(Path, 'read_text', read), mock.patch.object(
                    os, 'getuid', return_value=1001), mock.patch('sys.argv', ['probe', '/owned/canary', '12345']), mock.patch(
                    'builtins.open', side_effect=PermissionError(errno.EACCES, 'private-path')) as opened, mock.patch.object(
                    socket, 'create_connection', side_effect=ConnectionRefusedError(errno.ECONNREFUSED, 'private-endpoint')) as connected, redirect_stdout(io.StringIO()) as output:
                exec(ENFORCEMENT_CHILD, {})
            observation = json.loads(output.getvalue())
            self.assertEqual(set(observation), ENFORCEMENT_KEYS)
            self.assertNotIn('private', output.getvalue())
            opened.assert_called_once_with('/owned/canary', 'wb')
            connected.assert_called_once_with(('127.0.0.1', 12345), timeout=0.5)
            if expected_false:
                self.assertFalse(observation[expected_false])
            else:
                self.assertTrue(all(observation.values()))
        # Successful write/connect must make the denial proof false.
        with mock.patch.object(Path, 'read_text', read), mock.patch.object(os, 'getuid', return_value=1001), mock.patch(
                'sys.argv', ['probe', '/owned/canary', '12345']), mock.patch('builtins.open', mock.mock_open()), mock.patch.object(
                socket, 'create_connection', return_value=mock.MagicMock()), redirect_stdout(io.StringIO()) as output:
            exec(ENFORCEMENT_CHILD, {})
        self.assertFalse(json.loads(output.getvalue())['outside_write_denied'])
        self.assertFalse(json.loads(output.getvalue())['loopback_connect_denied'])

    def test_enforcement_parent_controls_one_request_and_unchanged_canary(self):
        from scripts import ci_codex_sandbox as sandbox
        provider = mock.Mock()
        provider.response.return_value = {'exitCode': 0, 'stdout': json.dumps({key: True for key in ENFORCEMENT_KEYS}), 'stderr': ''}
        listener = mock.MagicMock()
        listener.getsockname.return_value = ('127.0.0.1', 12345)
        listener.accept.side_effect = [(mock.MagicMock(), None), TimeoutError()]
        connection = mock.MagicMock()
        connection.__enter__.return_value.recv.return_value = b'ok'
        writes = []
        def write(path, value):
            writes.append(value)
        def read(path):
            return writes[-1] if path.name == 'canary' else b'pinned'
        with mock.patch.object(sandbox, 'target'), mock.patch.object(sandbox, 'chain'), mock.patch.object(sandbox, 'identity'), mock.patch.object(
                sandbox, 'digest', return_value=sandbox.RESOURCE_HASH), mock.patch.object(shutil, 'which', return_value=str(sandbox.BWRAP)), mock.patch.object(
                subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=b'--as-pid-1 --perms --argv0 --ro-bind-fd')), mock.patch.object(
                Path, 'home', return_value=Path('/home/runner')), mock.patch.object(Path, 'read_bytes', read), mock.patch.object(
                Path, 'write_bytes', write), mock.patch.object(tempfile, 'TemporaryDirectory') as temporary, mock.patch.object(
                socket, 'socket') as socket_factory, mock.patch.object(socket, 'create_connection', return_value=connection):
            temporary.return_value.__enter__.return_value = '/home/runner/herdr-codex-denial-owned'
            socket_factory.return_value.__enter__.return_value = listener
            observation = linux_enforcement(provider, Path('/tmp/owned'), '/pinned/python')
        self.assertTrue(all(observation.values()))
        self.assertEqual(writes, [b'parent-control', b'owned-before'])
        provider.request.assert_called_once()
        method, params = provider.request.call_args.args
        self.assertEqual(method, 'command/exec')
        self.assertEqual(set(params), {'command', 'cwd', 'timeoutMs'})
        self.assertEqual(params['timeoutMs'], 10000)
        self.assertEqual(params['cwd'], '/tmp/owned')
        self.assertEqual(params['command'][:3], ['/pinned/python', '-c', ENFORCEMENT_CHILD])
        provider.response.assert_called_once_with(provider.request.return_value, timeout=30)

    def test_enforcement_cli_rejects_non_ci_nonlinux_root_and_diagnostic_combination(self):
        env = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'bfirestone/herdr',
               'GITHUB_REF': 'refs/heads/feat/desktop-exact-delivery'}
        argv = ['proof', '--provider-fixtures-only', '--require-linux-enforcement', '--session', 'unused',
                '--scratch', '/unused', '--provider-path', '/unused', '--herdr-bin', '/unused']
        for platform, uid, changes, extra, accepted in [('linux', 1001, {}, [], True),
                ('darwin', 1001, {}, [], False), ('linux', 0, {}, [], False),
                ('linux', 1001, {'CI': 'false'}, [], False), ('linux', 1001, {}, ['--diagnose-provider-runtime'], False),
                ('linux', 1001, {'GITHUB_REF': 'refs/heads/master'}, [], False)]:
            with mock.patch('sys.argv', argv + extra), mock.patch.object(os.sys, 'platform', platform), mock.patch.object(
                    os, 'geteuid', return_value=uid), mock.patch.dict(os.environ, dict(env, **changes), clear=True), mock.patch(
                    __name__ + '.provider_fixtures', return_value=17) as fixtures, mock.patch('sys.stderr', io.StringIO()):
                if accepted:
                    self.assertEqual(main(), 17)
                    fixtures.assert_called_once()
                else:
                    with self.assertRaises(SystemExit):
                        main()
                    fixtures.assert_not_called()

    def diagnostic_fixture(self, results, enabled=True, platform='linux', cleanup_error=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve() / ('herdr-codex-' + 'e' * 32)
        args = argparse.Namespace(session='codex-proof-' + 'e' * 32, scratch=root,
                                  provider_path=Path('/unused'), diagnose_provider_runtime=enabled)
        provider = mock.Mock()
        provider.child.pid = 111
        provider.child.poll.return_value = None
        provider.owned_children = set()
        provider.cleanup_failure = None
        provider.response.side_effect = results
        if cleanup_error:
            provider.close.side_effect = ProofFailure('fixture_owned_tree_cleanup')
        def start(*args, **kwargs):
            kwargs['owners'].append(provider)
            return provider
        output = io.StringIO()
        with mock.patch(__name__ + '.validate_provider', return_value='/unused'), mock.patch(
                __name__ + '.process_parents', return_value={}), mock.patch(
                __name__ + '.DirectProvider', side_effect=start), mock.patch.object(
                os.sys, 'platform', platform), redirect_stdout(output):
            status = provider_fixtures(args)
        return status, json.loads(output.getvalue()), provider, root

    def test_runtime_diagnostics_latch_control_and_send_only_two_exact_probes(self):
        original = {'exitCode': 1, 'stdout': 'private sentinel', 'stderr': ''}
        status, report, provider, root = self.diagnostic_fixture([
            original, {'exitCode': 0}, {'exitCode': 0, 'stdout': 'HERDR_DIAG_PYTHON_STARTED\n'}])
        self.assertEqual(status, 1)
        self.assertEqual(report['diagnostic'], 'fixture_tool_failed_null')
        self.assertEqual(report['tool_failure_exit_code'], 1)
        self.assertEqual(report['qualification'], 'UNVERIFIED')
        self.assertEqual(report['tool_fd_isolation'], 'UNVERIFIED')
        detail = report['runtime_diagnostics']
        self.assertEqual(detail['original_control']['exit_code'], 1)
        self.assertTrue(detail['python_started'])
        python = str(Path(os.sys.executable).resolve())
        commands = [[python, str(root / 'descriptor_child.py'), 'null', '-'], ['/bin/true'],
                    [python, '-c', "print('HERDR_DIAG_PYTHON_STARTED', flush=True)"]]
        self.assertEqual(provider.request.call_args_list, [mock.call('command/exec', {
            'command': command, 'cwd': str(root), 'timeoutMs': 10000}) for command in commands])
        self.assertEqual(provider.response.call_count, 3)
        provider.call.assert_not_called()
        provider.close.assert_called_once()
        self.assertFalse(root.exists())
        self.assertNotIn('private sentinel', json.dumps(report))
        self.assertEqual(original, {'exitCode': 1, 'stdout': 'private sentinel', 'stderr': ''})

    def test_runtime_diagnostics_default_and_success_do_not_probe(self):
        status, report, provider, _ = self.diagnostic_fixture([{'exitCode': 1}], enabled=False)
        self.assertEqual(status, 1)
        self.assertNotIn('runtime_diagnostics', report)
        self.assertEqual(provider.request.call_count, 1)
        # A passing null response reaches the existing descriptor oracle; it must
        # not take the supplemental failure path, even when opt-in is enabled.
        with mock.patch(__name__ + '.diagnose_provider_runtime') as diagnose:
            status, report, provider, _ = self.diagnostic_fixture([
                {'exitCode': 0, 'stdout': '{"fds": []}'}])
        diagnose.assert_not_called()
        self.assertEqual(provider.request.call_count, 1)
        self.assertNotIn('runtime_diagnostics', report)

    def test_runtime_diagnostics_cli_restricts_opt_in_to_linux_fixtures(self):
        argv = ['proof', '--session', 'unused', '--scratch', '/unused',
                '--provider-path', '/unused', '--herdr-bin', '/unused']
        for platform, fixture, enabled, allowed in [
                ('linux', True, True, True), ('darwin', True, True, False),
                ('linux', False, True, False), ('darwin', True, False, True),
                ('linux', False, False, True)]:
            with self.subTest(platform=platform, fixture=fixture, enabled=enabled), mock.patch.object(
                    os.sys, 'platform', platform), mock.patch.object(os.sys, 'argv', argv +
                    (['--provider-fixtures-only'] if fixture else []) +
                    (['--diagnose-provider-runtime'] if enabled else [])), mock.patch(
                    __name__ + '.provider_fixtures', return_value=17) as fixtures, mock.patch(
                    __name__ + '.live', return_value=17) as live, mock.patch('sys.stderr', new_callable=io.StringIO):
                if allowed:
                    self.assertEqual(main(), 17)
                    (fixtures if fixture else live).assert_called_once()
                else:
                    with self.assertRaises(SystemExit) as error:
                        main()
                    self.assertEqual(error.exception.code, 2)
                    fixtures.assert_not_called()
                    live.assert_not_called()

    def test_runtime_diagnostics_fixed_metadata_utf8_caps_and_secret_redaction(self):
        private = '/private/secret-value-environment-name'
        metadata = runtime_output_metadata({'stdout': 'BWRAP: namespace ' + private}, 'stdout')
        self.assertEqual(metadata['signatures'], ['bwrap_message', 'namespace_message'])
        self.assertFalse(metadata['unmatched_nonempty'])
        self.assertNotIn(private, json.dumps(metadata))
        for result, expected in [({}, 'absent'), ({'stdout': None}, 'other'),
                                 ({'stdout': {'secret': private}}, 'other'), ({'stdout': ''}, 'string')]:
            item = runtime_output_metadata(result, 'stdout')
            self.assertEqual(item['type'], expected)
            self.assertEqual(item['observed_utf8_bytes'], 0)
            self.assertFalse(item['unmatched_nonempty'])
        item = runtime_output_metadata({'stdout': 'é' * 32768 + 'permission denied'}, 'stdout')
        self.assertEqual(item['scan_utf8_bytes'], 65536)
        self.assertEqual(item['observed_utf8_bytes'], 65536 + len('permission denied'))
        self.assertTrue(item['scan_truncated'])
        self.assertEqual(item['signatures'], [])
        self.assertTrue(item['unmatched_nonempty'])
        item = runtime_output_metadata({'stdout': 'x' * 65535 + '😀permission denied'}, 'stdout')
        self.assertEqual(item['scan_utf8_bytes'], 65536)
        self.assertEqual(item['signatures'], [])
        huge = runtime_output_metadata({'stdout': '😀' * 1048577}, 'stdout')
        self.assertEqual(huge['observed_utf8_bytes'], 4194305)
        self.assertTrue(huge['scan_truncated'])
        # Lone JSON surrogate escapes must never escape through an exception.
        self.assertEqual(runtime_output_metadata({'stdout': '\ud800'}, 'stdout')['type'], 'string')

    def test_runtime_diagnostics_signatures_and_maximum_schema_size(self):
        text = ('error building bubblewrap command: cannot enforce sandbox read-only path '
                'because it crosses writable symlink cannot enforce sandbox deny-read path '
                'cannot be safely expanded bubblewrap is unavailable: bwrap: namespace '
                "can't mount proc /newroot/proc failed to verify descriptor-backed bubblewrap mount: "
                'failed to verify linux sandbox capabilities: error applying linux sandbox restrictions: '
                'failed to execvp sandbox blocked creation of protected workspace metadata path '
                'error while loading shared libraries: libpython traceback (most recent call last): '
                'permission denied no such file or directory exec format error operation not permitted invalid argument '
                'capget (for uid == 0) failed Race condition binding dirfd '
                'loopback: Failed RTM_NEWADDR loopback: Failed RTM_NEWLINK')
        result = {'exitCode': -(2 ** 31), 'stdout': text, 'stderr': text}
        provider = mock.Mock()
        provider.child.poll.return_value = None
        provider.response.return_value = result
        with mock.patch(__name__ + '.observe_owned'):
            detail = diagnose_provider_runtime(provider, Path('/unused'), '/python', result)
        expected = ['bwrap_build', 'readonly_writable_symlink', 'denyread_writable_symlink',
                    'unreadable_glob', 'bwrap_unavailable', 'bwrap_message', 'namespace_message',
                    'proc_mount', 'inner_mount_verify', 'inner_capabilities', 'sandbox_restrictions',
                    'child_exec', 'protected_metadata', 'python_loader', 'python_traceback',
                    'permission', 'missing', 'exec_format', 'operation_not_permitted', 'invalid_argument',
                    'bwrap_capget_root', 'bwrap_bind_dirfd_race', 'bwrap_rtm_newaddr', 'bwrap_rtm_newlink']
        for name in ('original_control', 'true', 'python_startup'):
            for stream in ('stdout', 'stderr'):
                self.assertEqual(detail[name][stream]['signatures'], expected)
        self.assertLessEqual(len(json.dumps(detail).encode()), 8192)
        self.assertFalse(detail['python_started'])

    def test_runtime_diagnostics_specific_bwrap_literals_redact_suffixes(self):
        cases = [('capget (for uid == 0) failed', 'bwrap_capget_root'),
                 ('Race condition binding dirfd', 'bwrap_bind_dirfd_race'),
                 ('loopback: Failed RTM_NEWADDR', 'bwrap_rtm_newaddr'),
                 ('loopback: Failed RTM_NEWLINK', 'bwrap_rtm_newlink')]
        for literal, label in cases:
            for stream in ('stdout', 'stderr'):
                with self.subTest(label=label, stream=stream):
                    result = {stream: 'bwrap: ' + literal.upper() +
                              ': Operation not permitted /private/secret-suffix'}
                    item = runtime_output_metadata(result, stream)
                    self.assertEqual(item['signatures'], ['bwrap_message', 'operation_not_permitted', label])
                    self.assertFalse(item['unmatched_nonempty'])
                    self.assertNotIn('secret-suffix', json.dumps(item))
                    other = 'stderr' if stream == 'stdout' else 'stdout'
                    self.assertEqual(runtime_output_metadata(result, other)['signatures'], [])
                    self.assertNotIn(label, runtime_output_metadata({stream: literal[:-1]}, stream)['signatures'])

    def environment_metadata(self, apparmor=b'Y\n', restrict=b'1\n', stat_error=None,
                             access=True, which='/usr/bin/bwrap', samefile=True):
        streams = [io.BytesIO(apparmor), io.BytesIO(restrict)]
        reads = [mock.Mock(wraps=stream.read) for stream in streams]
        handles = [mock.MagicMock() for _ in streams]
        for handle, read in zip(handles, reads):
            handle.__enter__.return_value.read = read
        with mock.patch('os.stat', side_effect=stat_error, return_value=mock.Mock(st_mode=0o100755)) as status, mock.patch(
                'os.access', return_value=access) as executable, mock.patch(
                'shutil.which', return_value=which) as lookup, mock.patch(
                'os.path.samefile', side_effect=samefile if isinstance(samefile, Exception) else None,
                return_value=samefile) as same, mock.patch('builtins.open', side_effect=handles) as opened, mock.patch(
                'subprocess.run') as process:
            detail = runtime_environment_metadata()
        process.assert_not_called()
        self.assertEqual(status.call_args_list, [mock.call('/usr/bin/bwrap'), mock.call('/etc/apparmor.d/bwrap')])
        self.assertEqual(opened.call_args_list, [mock.call('/sys/module/apparmor/parameters/enabled', 'rb'),
                                               mock.call('/proc/sys/kernel/apparmor_restrict_unprivileged_userns', 'rb')])
        for read in reads:
            read.assert_called_once_with(8)
        self.assertLess(len(json.dumps(detail).encode()), 512)
        return detail, executable, lookup, same

    def test_runtime_environment_valid_fixed_scalars_and_parent_lookup(self):
        detail, executable, lookup, same = self.environment_metadata()
        self.assertEqual(detail, {'system_bwrap_executable': True, 'parent_path_bwrap_is_system': True,
                                 'apparmor_enabled': True, 'restrict_unprivileged_userns': 1,
                                 'bwrap_profile_file_present': True})
        executable.assert_called_once_with('/usr/bin/bwrap', os.X_OK)
        lookup.assert_called_once_with('bwrap')
        same.assert_called_once_with('/usr/bin/bwrap', '/usr/bin/bwrap')
        detail, _, _, _ = self.environment_metadata(apparmor=b'N\n', restrict=b'0\n', access=False,
                                                   which='/private/secret-bwrap', samefile=False)
        self.assertFalse(detail['system_bwrap_executable'])
        self.assertFalse(detail['parent_path_bwrap_is_system'])
        self.assertFalse(detail['apparmor_enabled'])
        self.assertEqual(detail['restrict_unprivileged_userns'], 0)
        self.assertNotIn('secret-bwrap', json.dumps(detail))
        detail, _, _, same = self.environment_metadata(which=None)
        self.assertIsNone(detail['parent_path_bwrap_is_system'])
        same.assert_not_called()

    def test_runtime_environment_missing_denied_malformed_and_bounded_reads(self):
        for error, expected in [(FileNotFoundError('private'), False), (PermissionError('private'), None)]:
            with self.subTest(error=type(error).__name__):
                detail, executable, _, _ = self.environment_metadata(stat_error=error, samefile=error)
                self.assertIs(detail['system_bwrap_executable'], expected)
                self.assertIs(detail['bwrap_profile_file_present'], expected)
                self.assertIsNone(detail['parent_path_bwrap_is_system'])
                executable.assert_not_called()
        for apparmor, restrict in [(b'', b''), (b'yes', b'2'), (b'y', b'-1'), (b'\xff', b'\xff'),
                                  (b'Y       secret', b'1       secret')]:
            with self.subTest(apparmor=apparmor, restrict=restrict):
                detail, _, _, _ = self.environment_metadata(apparmor=apparmor, restrict=restrict)
                self.assertIsNone(detail['apparmor_enabled'])
                self.assertIsNone(detail['restrict_unprivileged_userns'])
                self.assertNotIn('secret', json.dumps(detail))
        for error in (FileNotFoundError('private'), PermissionError('private'), OSError('private')):
            with mock.patch('builtins.open', side_effect=error):
                detail = runtime_environment_metadata()
            self.assertIsNone(detail['apparmor_enabled'])
            self.assertIsNone(detail['restrict_unprivileged_userns'])
            self.assertNotIn('private', json.dumps(detail))

    def test_runtime_environment_collected_once_only_for_opted_in_linux_fixture(self):
        for enabled, platform in [(False, 'linux'), (False, 'darwin'), (True, 'darwin'), (True, 'linux')]:
            with self.subTest(enabled=enabled, platform=platform), mock.patch(
                    __name__ + '.runtime_environment_metadata', return_value={'apparmor_enabled': None}) as metadata:
                status, report, provider, _ = self.diagnostic_fixture(
                    [{'exitCode': 1}, {'exitCode': 0}, {'exitCode': 0}], enabled=enabled, platform=platform)
            self.assertEqual(status, 1)
            if enabled and platform == 'linux':
                metadata.assert_called_once_with()
                self.assertEqual(report['runtime_environment'], {'apparmor_enabled': None})
            else:
                metadata.assert_not_called()
                self.assertNotIn('runtime_environment', report)
            provider.close.assert_called_once()

    def test_runtime_diagnostics_malformed_responses_and_errors_stop_probes(self):
        cases = [(None, 'malformed_result'), ([], 'malformed_result'),
                 ({}, 'malformed_result'), ({'exitCode': True}, 'malformed_result'),
                 ({'exitCode': 2 ** 31}, 'malformed_result'),
                 (ProofFailure('fixture_provider_request_error'), 'rpc_error'),
                 (ProofFailure('fixture_provider_deadline'), 'deadline'),
                 (ProofFailure('fixture_output_bound'), 'bound'),
                 (ProofFailure('fixture_stderr_bound'), 'bound'),
                 (ProofFailure('fixture_pending_bound'), 'bound'),
                 (ProofFailure('fixture_provider_exited'), 'provider_exit'),
                 (ProofFailure('process_inspection_unavailable'), 'ownership_unverified'),
                 (ValueError('private malformed JSON'), 'malformed_result'),
                 (BrokenPipeError('private transport'), 'transport_error'),
                 (RuntimeError('private unexpected'), 'transport_error')]
        for response, outcome in cases:
            with self.subTest(outcome=outcome):
                status, report, provider, _ = self.diagnostic_fixture([{'exitCode': 1}, response])
                self.assertEqual(status, 1)
                self.assertEqual(report['diagnostic'], 'fixture_tool_failed_null')
                self.assertEqual(provider.request.call_count, 2)
                self.assertEqual(report['runtime_diagnostics']['true']['outcome'], outcome)
                self.assertEqual(report['runtime_diagnostics']['python_startup']['outcome'], 'not_run')
                self.assertNotIn('private', json.dumps(report))
                provider.close.assert_called_once()
        for malformed in (None, [], {}, {'exitCode': True}, {'exitCode': 2 ** 31}):
            with self.subTest(original=malformed):
                status, report, provider, _ = self.diagnostic_fixture([malformed])
                self.assertEqual(status, 1)
                self.assertEqual(provider.request.call_count, 1)
                self.assertNotIn('runtime_diagnostics', report)
                provider.close.assert_called_once()

    def test_runtime_diagnostics_budget_inspection_and_provider_exit_stop_before_request(self):
        original = {'exitCode': 1}
        for failure, outcome in [(ProofFailure('process_inspection_unavailable'), 'ownership_unverified'),
                                 (None, 'provider_exit')]:
            provider = mock.Mock()
            provider.child.poll.return_value = 1
            with mock.patch(__name__ + '.observe_owned', side_effect=failure):
                detail = diagnose_provider_runtime(provider, Path('/unused'), '/python', original)
            self.assertEqual(detail['true']['outcome'], outcome)
            provider.request.assert_not_called()
        provider = mock.Mock()
        provider.child.poll.return_value = None
        provider.response.return_value = {'exitCode': 0}
        # Account for the ownership check before starting each response deadline.
        with mock.patch(__name__ + '.observe_owned'), mock.patch(
                __name__ + '.time.monotonic', side_effect=[0, 0, 0, 0, 31, 65]):
            detail = diagnose_provider_runtime(provider, Path('/unused'), '/python', original)
        self.assertEqual(provider.request.call_count, 1)
        self.assertEqual(detail['python_startup']['outcome'], 'deadline')
        self.assertEqual(provider.response.call_args.kwargs['timeout'], 30)

    def test_runtime_diagnostics_budget_accounts_for_request_send_time(self):
        provider = mock.Mock()
        provider.child.poll.return_value = None
        provider.response.return_value = {'exitCode': 0}
        with mock.patch(__name__ + '.observe_owned'), mock.patch(
                __name__ + '.time.monotonic', side_effect=[0, 0, 0, 60, 64, 65]):
            detail = diagnose_provider_runtime(provider, Path('/unused'), '/python', {'exitCode': 1})
        self.assertEqual(provider.request.call_count, 1)
        self.assertEqual(provider.response.call_args.kwargs['timeout'], 5)
        self.assertEqual(detail['python_startup']['outcome'], 'deadline')

    def test_runtime_diagnostics_python_marker_is_exact_and_cleanup_stays_uncertain(self):
        for code, stdout, started in [(0, 'HERDR_DIAG_PYTHON_STARTED\n', True),
                                      (1, 'HERDR_DIAG_PYTHON_STARTED\n', False),
                                      (0, 'HERDR_DIAG_PYTHON_STARTED\nprivate', False),
                                      (0, 'HERDR_DIAG_PYTHON_STARTED', False)]:
            status, report, provider, root = self.diagnostic_fixture([
                {'exitCode': 1}, {'exitCode': 1}, {'exitCode': code, 'stdout': stdout}], cleanup_error=True)
            self.assertEqual(status, 1)
            self.assertEqual(report['runtime_diagnostics']['python_started'], started)
            self.assertEqual(report['owned_cleanup'], 'UNVERIFIED')
            self.assertEqual(report['diagnostic'], 'fixture_tool_failed_null')
            self.assertTrue(root.exists())
            provider.close.assert_called_once()

    def test_runtime_diagnostics_workflow_enables_only_linux(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/integrated-agents.yml').read_text()
        code = workflow.split("python3 - <<'PY'\n", 1)[1].rsplit('\n          PY', 1)[0]
        import textwrap
        for platform in ('Linux', 'Darwin'):
            calls = []
            with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {'RUNNER_TEMP': temporary}), mock.patch(
                    'pathlib.Path.glob', return_value=[Path('/native/codex')]), mock.patch(
                    'subprocess.run', side_effect=lambda argv, **kwargs: calls.append(argv) or mock.Mock(returncode=0)), mock.patch(
                    'os.uname', return_value=mock.Mock(sysname=platform)):
                exec(textwrap.dedent(code), {})
            self.assertEqual(len(calls), 2)
            for argv in calls:
                self.assertEqual('--diagnose-provider-runtime' in argv, platform == 'Linux')
                self.assertIn('--provider-fixtures-only', argv)

    def closing_provider(self, provider_type=DirectProvider):
        provider = object.__new__(provider_type)
        provider.closed = False
        provider.cleanup_failure = None
        provider.owned_children = {222}
        provider.input = mock.Mock()
        provider.child = mock.Mock(pid=111)
        provider.child.poll.return_value = None
        return provider

    def test_failed_close_stays_failed_and_closes_resources_once(self):
        provider = self.closing_provider()
        with mock.patch(__name__ + '.process_parents', return_value={222: 1}), mock.patch(
                __name__ + '.eventually', side_effect=ProofFailure('fixture_owned_tree_cleanup')):
            for _ in range(2):
                with self.assertRaisesRegex(ProofFailure, '^fixture_owned_tree_cleanup$'):
                    provider.close()
        provider.input.close.assert_called_once()
        provider.child.wait.assert_called_once()
        provider.child.stdout.close.assert_called_once()
        provider.child.stderr.close.assert_called_once()

    def test_unexpected_exit_cleanup_failure_is_sticky(self):
        provider = self.closing_provider()
        provider.child.poll.return_value = 1
        with mock.patch(__name__ + '.process_parents', return_value={}):
            for _ in range(2):
                with self.assertRaisesRegex(ProofFailure, '^fixture_unexpected_exit_cleanup_unverified$'):
                    provider.close()

    def test_failed_initialization_keeps_owner_and_failed_cleanup_result(self):
        owners = []
        child = mock.Mock(pid=111)
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary, mock.patch('subprocess.Popen', return_value=child), mock.patch(
                __name__ + '.DirectProvider.call', side_effect=ProofFailure('fixture_initialize_failure')), mock.patch(
                __name__ + '.process_parents', side_effect=ProofFailure('process_inspection_unavailable')):
            with self.assertRaisesRegex(ProofFailure, '^process_inspection_unavailable$'):
                DirectProvider('/unused', Path(temporary), owners=owners)
            self.assertEqual(len(owners), 1)
            with self.assertRaisesRegex(ProofFailure, '^process_inspection_unavailable$'):
                owners[0].close()
        self.assertTrue(owners[0].input.closed)
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_intermediate_cleanup_failures_retain_scratch_and_never_report_pass(self):
        for failing_instance in (0, 1):
            with self.subTest(instance=failing_instance), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve() / ('herdr-codex-' + 'b' * 32)
                args = argparse.Namespace(session='codex-proof-' + 'b' * 32, scratch=root,
                                          provider_path=Path('/unused'))
                providers = []
                def start(*args, **kwargs):
                    provider = self.closing_provider()
                    provider.control_identity = [7, 8, 9]
                    index = len(providers)
                    providers.append(provider)
                    if kwargs.get('owners') is not None:
                        kwargs['owners'].append(provider)
                    def call(method, params):
                        if method == 'hooks/list':
                            return {'data': [{'hooks': [{'command': shlex.join([
                                str(Path(os.sys.executable).resolve()), str(root / 'descriptor_child.py'),
                                'hook', str(root / 'hook-descriptors.json')]), 'eventName': 'sessionStart',
                                'key': 'owned-key', 'currentHash': 'owned-hash'}]}]}
                        return {}
                    def request(method, params):
                        provider.mode = params.get('tty', False)
                        provider.null = not params.get('streamStdin', False) and not provider.mode
                        return 'owned-request'
                    provider.call = call
                    provider.request = request
                    provider.output = lambda process: b'READY\n' + json.dumps({
                        'fds': [[0, 1, 2, 3]], 'input': 'pty-ok' if provider.mode else 'child-only'}).encode()
                    provider.response = lambda request: {'exitCode': 0, 'stdout': json.dumps({
                        'fds': [[0, 1, 2, 3]], 'input': ''})}
                    real_close = provider.close
                    def close():
                        if index == failing_instance:
                            with mock.patch(__name__ + '.eventually', side_effect=ProofFailure('fixture_owned_tree_cleanup')):
                                real_close()
                        else:
                            real_close()
                    provider.close = close
                    return provider
                output = io.StringIO()
                with mock.patch(__name__ + '.validate_provider', return_value='/unused'), mock.patch(
                        __name__ + '.process_parents', return_value={}), mock.patch(
                        __name__ + '.DirectProvider', side_effect=start), redirect_stdout(output):
                    result = provider_fixtures(args)
                report = json.loads(output.getvalue())
                self.assertEqual(result, 1)
                self.assertEqual(len(providers), failing_instance + 1)
                self.assertEqual(report['owned_cleanup'], 'UNVERIFIED')
                self.assertTrue(root.is_dir())

    def test_command_failure_details_classify_without_exposing_private_output(self):
        private = 'private-provider-text-/private/path-secret-value'
        cases = [
            ('bwrap: No permissions to create new namespace', 'namespace_setup'),
            ('bwrap: Creating new namespace failed: Operation not permitted', 'namespace_setup'),
            ('python: error while loading shared libraries: libpython3.14.so.1.0: cannot open shared object file', 'python_shared_library_loader'),
            ('exec: Permission denied', 'executable_or_permission'),
            ('exec: Exec format error', 'executable_or_permission'),
            (private, 'unclassified'),
        ]
        for stderr, expected in cases:
            with self.subTest(cause=expected):
                detail = fixture_command_failure({'exitCode': 127, 'stderr': stderr + private,
                                                  'stdout': private})
                self.assertEqual(detail, {'tool_failure_exit_code': 127, 'tool_failure_cause': expected})
                self.assertNotIn(private, json.dumps(detail))

    def test_command_failure_details_bound_exit_status_and_diagnostic_input(self):
        for code in ('private-exit-value', True, None, 2 ** 31, -(2 ** 31) - 1):
            with self.subTest(code=code):
                detail = fixture_command_failure({'exitCode': code, 'stderr': {'private': 'value'}})
                self.assertEqual(detail, {'tool_failure_cause': 'unclassified'})
        for code in (-(2 ** 31), -9, 1, 2 ** 31 - 1):
            self.assertEqual(fixture_command_failure({'exitCode': code})['tool_failure_exit_code'], code)
        detail = fixture_command_failure({'exitCode': 1, 'stderr': 'x' * 65536 + 'bwrap: No permissions to create new namespace'})
        self.assertEqual(detail['tool_failure_cause'], 'unclassified')

    def test_failed_descriptor_command_reports_only_categories_and_preserves_failure(self):
        private = 'private-provider-stdout-stderr-path-marker'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / ('herdr-codex-' + 'd' * 32)
            args = argparse.Namespace(session='codex-proof-' + 'd' * 32, scratch=root,
                                      provider_path=Path('/unused'))
            provider = mock.Mock()
            provider.response.return_value = {'exitCode': 1, 'stdout': private, 'stderr': private}
            def start(*args, **kwargs):
                kwargs['owners'].append(provider)
                return provider
            output = io.StringIO()
            with mock.patch(__name__ + '.validate_provider', return_value='/unused'), mock.patch(
                    __name__ + '.process_parents', return_value={}), mock.patch(
                    __name__ + '.DirectProvider', side_effect=start), redirect_stdout(output):
                result = provider_fixtures(args)
            report = json.loads(output.getvalue())
            self.assertEqual(result, 1)
            self.assertEqual(report['diagnostic'], 'fixture_tool_failed_null')
            self.assertEqual(report['tool_failure_exit_code'], 1)
            self.assertEqual(report['tool_failure_cause'], 'unclassified')
            self.assertEqual(report['qualification'], 'UNVERIFIED')
            self.assertEqual(report['tool_fd_isolation'], 'UNVERIFIED')
            self.assertEqual(report['owned_cleanup'], 'PASS')
            self.assertNotIn(private, output.getvalue())
            self.assertFalse(root.exists())
            provider.close.assert_called_once()

    def test_process_inspection_denial_is_redacted(self):
        with mock.patch('subprocess.run', side_effect=PermissionError('private diagnostic sentinel')):
            with self.assertRaisesRegex(ProofFailure, '^process_inspection_unavailable$'):
                process_parents()

    def test_inspection_preflight_launches_nothing_and_returns_structured_result(self):
        for descriptor in (False, True):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve() / ('herdr-codex-' + 'c' * 32)
                argv = ['proof', '--session', 'codex-proof-' + 'c' * 32, '--scratch', str(root),
                        '--provider-path', '/unused/provider', '--herdr-bin', '/unused/herdr']
                if descriptor:
                    argv.append('--provider-fixtures-only')
                output = io.StringIO()
                with mock.patch.object(os.sys, 'argv', argv), mock.patch(__name__ + '.validate_binary', return_value='/unused'), mock.patch(
                        'subprocess.run', side_effect=PermissionError('private diagnostic sentinel')) as run, mock.patch(
                        'subprocess.Popen') as spawn, redirect_stdout(output):
                    self.assertEqual(main(), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report['diagnostic'], 'process_inspection_unavailable')
                self.assertEqual(report['qualification'], 'UNVERIFIED')
                self.assertEqual(report['owned_cleanup'], 'UNVERIFIED')
                self.assertFalse(root.exists())
                spawn.assert_not_called()
                self.assertEqual(run.call_args.args[0][0], 'ps')

    def test_provider_cleanup_reaps_known_process_when_inspection_is_denied(self):
        provider = self.closing_provider()
        with mock.patch('subprocess.run', side_effect=PermissionError('private diagnostic sentinel')):
            for _ in range(2):
                with self.assertRaisesRegex(ProofFailure, '^process_inspection_unavailable$'):
                    provider.close()
        provider.input.close.assert_called_once()
        provider.child.wait.assert_called_once()
        provider.child.stdout.close.assert_called_once()

    def test_live_cleanup_reaps_known_processes_when_inspection_is_denied(self):
        session = object.__new__(Session)
        session.server = mock.Mock(pid=111)
        session.server.poll.return_value = None
        session.client = mock.Mock()
        session.client.poll.return_value = None
        session.client_pty = None
        session.owned_children = {222}
        session.closed = False
        session.cleanup_failure = None
        session.command = ['/unused', '--session', 'owned']
        session.env = {}
        session.workspace = Path('/tmp')
        with mock.patch('subprocess.run', side_effect=PermissionError('private diagnostic sentinel')):
            with self.assertRaisesRegex(ProofFailure, '^process_inspection_unavailable$'):
                session.close()
        session.client.terminate.assert_called_once()
        session.client.wait.assert_called_once()
        session.server.terminate.assert_called_once()
        session.server.wait.assert_called_once()

    def test_live_cleanup_keeps_previously_observed_reparented_children(self):
        session = object.__new__(Session)
        session.server = mock.Mock(pid=111)
        session.server.poll.return_value = 0
        session.client = None
        session.client_pty = None
        session.closed = False
        session.cleanup_failure = None
        session.owned_children = set()
        session.sequence = 0
        session.command = ['/unused']
        session.env = {}
        session.workspace = Path('/tmp')
        response = mock.Mock(returncode=0, stdout=b'{"id":"qualification-1","result":{}}')
        with mock.patch(__name__ + '.process_parents', return_value={222: 111}), mock.patch(
                'subprocess.run', return_value=response):
            session.api('ping')
        def verify_once(check, category, timeout):
            if not check():
                raise ProofFailure(category)
        with mock.patch(__name__ + '.process_parents', return_value={222: 1}), mock.patch(
                __name__ + '.eventually', side_effect=verify_once):
            for _ in range(2):
                with self.assertRaisesRegex(ProofFailure, '^owned_descendant_cleanup_unverified$'):
                    session.close()
        session.server.wait.assert_called_once()
        session.server.terminate.assert_not_called()

    def test_targets_reject_existing_relative_mismatched_and_symlink_paths(self):
        nonce = 'a' * 32
        session = 'codex-proof-' + nonce
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            fresh = parent / ('herdr-codex-' + nonce)
            validate_targets(session, fresh)
            for bad_session, path in [('default', fresh), (session, Path('relative')), (session, parent / 'other')]:
                with self.assertRaises(ProofFailure):
                    validate_targets(bad_session, path)
            fresh.mkdir()
            with self.assertRaises(ProofFailure):
                validate_targets(session, fresh)
            fresh.rmdir()
            fresh.symlink_to(parent / 'absent')
            with self.assertRaises(ProofFailure):
                validate_targets(session, fresh)

    def test_environment_isolates_catalog_and_keeps_home_and_auth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = isolated_environment(root, '/absolute/provider')
            for key in ('HOME', 'CODEX_HOME', 'OPENAI_API_KEY'):
                self.assertEqual(env.get(key), os.environ.get(key))
            self.assertTrue(all(key not in env for key in ROUTING))
            for key in ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'HERDR_CONFIG_PATH', 'CODEX_SQLITE_HOME'):
                self.assertTrue(Path(env[key]).is_relative_to(root))
            self.assertEqual((root / 'bin/codex').readlink(), Path('/absolute/provider'))

    def test_descriptor_environment_has_fresh_provider_home_and_no_auth(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {
                'OPENAI_API_KEY': 'sentinel', 'CODEX_API_KEY': 'sentinel',
                'CODEX_ACCESS_TOKEN': 'sentinel', 'OPENAI_IDENTITY_TOKEN_FILE': '/sentinel'}):
            root = Path(temporary)
            env = descriptor_environment(root)
            self.assertEqual(env['HOME'], os.environ['HOME'])
            self.assertEqual(env['CODEX_HOME'], str(root / 'codex-home'))
            self.assertFalse(any(key.startswith('OPENAI_') for key in env))
            self.assertNotIn('CODEX_API_KEY', env)
            self.assertNotIn('CODEX_ACCESS_TOKEN', env)

    def test_preview_reads_typed_pane_read_envelope(self):
        session = object.__new__(Session)
        session.pane = 'p_1_1'
        session.result = lambda method, params: {'type': 'pane_read', 'read': {'text': 'visible'}}
        self.assertEqual(session.preview(), 'visible')

    def test_consent_requires_exact_visible_command_and_current_turn(self):
        command = "printf herdr-codex-proof > /private/tmp/owned/allow.txt"
        request = {'id': 17, 'method': 'item/commandExecution/requestApproval',
                   'params': {'threadId': 'thread', 'turnId': 'turn', 'command': command,
                              'cwd': '/private/tmp/owned', 'availableDecisions': ['accept', 'decline']}}
        preview = 'HERDR PERMISSION — item/commandExecution/requestApproval\n' + json.dumps({'request': request, 'operation': None}, indent=2)
        self.assertEqual(consent_request(preview, 'thread', 'turn', command, '/private/tmp/owned')['id'], 17)
        for changed in [preview.replace('"turn"', '"old"'), preview.replace(command, command + '; touch /tmp/other'), preview[:100]]:
            with self.assertRaises(ProofFailure):
                consent_request(changed, 'thread', 'turn', command, '/private/tmp/owned')

    def test_process_ownership_excludes_unrelated_and_parent_processes(self):
        self.assertEqual(descendants(10, {10: 1, 11: 10, 12: 11, 20: 1, 21: 20}), {11, 12})

    def test_direct_observer_keeps_out_of_order_responses_correlated(self):
        observer = object.__new__(DirectProvider)
        observer.responses = {}
        observer.notifications = []
        frames = iter([{'id': 'exec', 'result': {'exitCode': 0}}, {'id': 'write', 'result': {}}])
        observer.frame = lambda deadline: next(frames)
        self.assertEqual(observer.response('write'), {})
        self.assertEqual(observer.response('exec'), {'exitCode': 0})

    def test_child_fd_check_detects_inherited_control_at_any_descriptor(self):
        assert_isolated({'fds': [[0, 1, 2, 3], [1, 4, 5, 6]]}, [7, 8, 9])
        for fds in ([], [[0, 1, 2, 3], [19, 7, 8, 9]]):
            with self.assertRaises(ProofFailure):
                assert_isolated({'fds': fds}, [7, 8, 9])

    def test_provider_spawn_failure_closes_both_control_pipe_ends(self):
        read_fd, write_fd = os.pipe()
        try:
            with tempfile.TemporaryDirectory() as temporary, mock.patch('os.pipe', return_value=(read_fd, write_fd)), mock.patch('subprocess.Popen', side_effect=OSError('fixture')):
                with self.assertRaises(OSError):
                    DirectProvider('/absent', Path(temporary))
            for fd in (read_fd, write_fd):
                with self.assertRaises(OSError):
                    os.fstat(fd)
        finally:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_strict_policy_is_only_in_owned_exec_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            provider = root / 'provider'
            provider.write_text('#!' + os.sys.executable + '\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
            provider.chmod(0o700)
            env = isolated_environment(root, str(provider), strict_test_policy=True)
            launcher = root / 'bin/codex'
            self.assertFalse(launcher.is_symlink())
            result = subprocess.run([str(launcher), 'app-server', '--listen', 'stdio://'], capture_output=True, check=True, env=env)
            self.assertEqual(json.loads(result.stdout), ['-c', 'approval_policy="on-request"', '-c', 'approvals_reviewer="user"', 'app-server', '--listen', 'stdio://'])
            self.assertEqual(env.get('HOME'), os.environ.get('HOME'))

    def test_binary_requires_absolute_existing_executable(self):
        for path in (Path('codex'), Path('/absent/herdr-provider')):
            with self.assertRaises(ProofFailure):
                validate_binary(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict-test-policy', action='store_true', help='user-approved disposable-only on-request/manual consent; never changes saved settings or sandbox policy')
    parser.add_argument('--provider-fixtures-only', action='store_true', help='opt-in shipped-binary tool/hook/MCP descriptor fixtures; no model calls')
    parser.add_argument('--require-linux-enforcement', action='store_true', help='reviewed Linux CI provider fixtures only: require child enforcement and owned denial evidence')
    parser.add_argument('--diagnose-provider-runtime', action='store_true', help='Linux provider-fixtures-only: two bounded supplemental probes after a failed null control')
    parser.add_argument('--session', required=True, help='new codex-proof-<32 random hex> session')
    parser.add_argument('--scratch', required=True, type=Path, help='nonexistent canonical absolute /.../herdr-codex-<same hex>')
    parser.add_argument('--consent-scratch', type=Path, help='optional distinct fresh herdr-codex-<same hex> directory outside normal writable roots for approval exercises')
    parser.add_argument('--provider-path', required=True, type=Path, help='absolute existing Codex 0.154.0 executable; never auto-installs')
    parser.add_argument('--herdr-bin', required=True, type=Path, help='absolute freshly built Herdr executable')
    args = parser.parse_args()
    if args.diagnose_provider_runtime and (not args.provider_fixtures_only or os.sys.platform != 'linux'):
        parser.error('--diagnose-provider-runtime requires --provider-fixtures-only on Linux')
    if args.require_linux_enforcement:
        if (not args.provider_fixtures_only or os.sys.platform != 'linux' or args.diagnose_provider_runtime or
                os.environ.get('CI') != 'true' or os.environ.get('GITHUB_ACTIONS') != 'true' or
                os.environ.get('GITHUB_REPOSITORY') != 'bfirestone/herdr' or
                os.environ.get('GITHUB_REF') != 'refs/heads/feat/desktop-exact-delivery' or os.geteuid() == 0):
            parser.error('--require-linux-enforcement requires the nonroot reviewed Linux CI candidate')
    try:
        return provider_fixtures(args) if args.provider_fixtures_only else live(args)
    except (ProofFailure, subprocess.TimeoutExpired) as error:
        print(json.dumps({'qualification': 'UNVERIFIED', 'owned_cleanup': 'UNVERIFIED',
                          'diagnostic': str(error) if isinstance(error, ProofFailure) else 'subprocess_timeout'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
