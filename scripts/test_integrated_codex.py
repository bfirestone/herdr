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
import subprocess
import tempfile
import time
import unittest
import io
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
            if result['exitCode'] != 0:
                report.update(fixture_command_failure(result))
                raise ProofFailure('fixture_tool_failed_' + mode)
            output = client.output(process_id).split(b'READY\n', 1)[-1] if mode != 'null' else result['stdout']
            observation = json.loads(output)
            assert_isolated(observation, client.control_identity)
            if observation['input'] != ('child-only' if mode == 'pipe' else 'pty-ok' if mode == 'pty' else ''):
                raise ProofFailure('fixture_tool_input_mismatch')
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
            report['diagnostic'] = str(errors[0])
        print(json.dumps(report, sort_keys=True))
    return 0 if all(report[key].startswith('PASS') for key in ('tool_fd_isolation', 'hook_fd_isolation', 'mcp_fd_isolation', 'owned_cleanup')) else 1


class SafetyTests(unittest.TestCase):
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
    parser.add_argument('--session', required=True, help='new codex-proof-<32 random hex> session')
    parser.add_argument('--scratch', required=True, type=Path, help='nonexistent canonical absolute /.../herdr-codex-<same hex>')
    parser.add_argument('--consent-scratch', type=Path, help='optional distinct fresh herdr-codex-<same hex> directory outside normal writable roots for approval exercises')
    parser.add_argument('--provider-path', required=True, type=Path, help='absolute existing Codex 0.154.0 executable; never auto-installs')
    parser.add_argument('--herdr-bin', required=True, type=Path, help='absolute freshly built Herdr executable')
    args = parser.parse_args()
    try:
        return provider_fixtures(args) if args.provider_fixtures_only else live(args)
    except (ProofFailure, subprocess.TimeoutExpired) as error:
        print(json.dumps({'qualification': 'UNVERIFIED', 'owned_cleanup': 'UNVERIFIED',
                          'diagnostic': str(error) if isinstance(error, ProofFailure) else 'subprocess_timeout'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
