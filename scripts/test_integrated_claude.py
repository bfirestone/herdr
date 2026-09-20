#!/usr/bin/env python3
"""Opt-in Claude 2.1.276 qualification; never installs or changes saved policy/auth.

Raw protocol observation is a prerequisite, not integrated delivery qualification.
Only fresh explicitly named scratch/session targets are accepted. Diagnostics
contain fixed categories and booleans, never provider frames or prompt bodies.
"""
import argparse
import contextlib
import ctypes
import io
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

try:
    from .test_integrated_codex import (ProofFailure, descendants,
                                        reap_owned, eventually, ROUTING, Session as CodexSession, validate_binary)
except ImportError:
    from test_integrated_codex import (ProofFailure, descendants,
                                       reap_owned, eventually, ROUTING, Session as CodexSession, validate_binary)

VERSION = '2.1.276'
SDK_VERSION = '0.3.276'


def fd_identity(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino, value.st_mode]


def descriptor_observation(receipt, control, input_kind):
    result = {'schema_valid': False, 'input_kind_matches': False, 'stdin_present': False,
              'provider_input_matches': 0, 'descriptor_count': 0}
    if not isinstance(receipt, dict):
        return result
    result['input_kind_matches'] = receipt.get('input_kind') == input_kind
    fds = receipt.get('fds')
    if (not isinstance(fds, list) or not 0 < len(fds) <= 4096
            or any(not isinstance(row, list) or len(row) != 4
                   or any(type(value) is not int for value in row)
                   or any(row[index] < 0 for index in (0, 2, 3)) for row in fds)):
        return result
    # Darwin Unix sockets report a signed st_dev of -1. Do not confuse that
    # valid metadata with an invalid descriptor or strip it from the identity.
    numbers = [row[0] for row in fds]
    result.update(schema_valid=len(set(numbers)) == len(numbers), stdin_present=0 in numbers,
                  provider_input_matches=sum(row[1:] == control for row in fds),
                  descriptor_count=len(fds))
    return result


def isolated_receipt(receipt, control, input_kind):
    observation = descriptor_observation(receipt, control, input_kind)
    return (all(observation[key] for key in ('schema_valid', 'input_kind_matches', 'stdin_present'))
            and observation['provider_input_matches'] == 0)


def descriptor_observation_control():
    """Prove pipe metadata survives inheritance and distinguishes another pipe."""
    first = os.pipe()
    second = os.pipe()
    try:
        identity = fd_identity(first[0])
        result = subprocess.run([sys.executable, '-c',
            'import os,json; s=os.fstat(0); print(json.dumps([s.st_dev,s.st_ino,s.st_mode]))'],
            stdin=first[0], capture_output=True, check=True, timeout=5)
        if identity == fd_identity(second[0]) or json.loads(result.stdout) != identity:
            raise ProofFailure('descriptor_observation_unverified')
    finally:
        for fd in (*first, *second):
            os.close(fd)


# The owned child never reads credentials, configuration or ordinary prompt text.
# It receives only its SessionStart hook envelope or MCP initialization/tool RPCs.
DESCRIPTOR_CHILD = r'''
import json,os,signal,sys
from pathlib import Path
signal.alarm(60)
mode,receipt,session=sys.argv[1:]
def record(kind):
 fds=[]
 for name in os.listdir('/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'):
  try:
   fd=int(name);s=os.fstat(fd)
   fds.append([fd,s.st_dev,s.st_ino,s.st_mode])
  except (ValueError,OSError): pass
 target=Path(receipt);pending=target.with_suffix('.pending')
 pending.write_text(json.dumps({'input_kind':kind,'fds':fds}))
 pending.replace(target)
def read_frame():
 line=sys.stdin.buffer.readline(1048577)
 if not line:return None
 assert len(line)<=1048576 and line.endswith(b'\n')
 value=json.loads(line)
 assert isinstance(value,dict)
 return value
if mode=='hook':
 value=read_frame()
 assert value.get('hook_event_name')=='SessionStart' and value.get('session_id')==session
 record('SessionStart')
 print('{}',flush=True)
elif mode=='bash':
 record('Bash')
 print('owned descriptor fixture complete',flush=True)
elif mode=='mcp':
 initialized=False
 for _ in range(4096):
  value=read_frame()
  if value is None:break
  method=value.get('method')
  if method=='initialize':
   assert not initialized
   initialized=True
   record('initialize')
   result={'protocolVersion':value['params']['protocolVersion'],'capabilities':{'tools':{}},
           'serverInfo':{'name':'herdr-owned-descriptor-fixture','version':'1'}}
  elif method=='tools/list':
   result={'tools':[{'name':'descriptor','description':'Observe owned descriptor metadata',
                    'inputSchema':{'type':'object','properties':{},'additionalProperties':False}}]}
  elif method=='tools/call':
   assert initialized and value['params']['name']=='descriptor' and value['params'].get('arguments',{})=={}
   record('tools/call')
   result={'content':[{'type':'text','text':'owned descriptor fixture complete'}]}
  elif method=='ping':result={}
  elif method=='notifications/initialized':continue
  else:raise AssertionError('unexpected fixture RPC')
  if 'id' in value:
   print(json.dumps({'jsonrpc':'2.0','id':value['id'],'result':result}),flush=True)
else:raise AssertionError('unknown fixture mode')
'''


def process_snapshot():
    """Inspect identities/state only; never collect argv or environment."""
    try:
        result = subprocess.run(['ps', '-axo', 'pid=,ppid=,lstart=,stat='],
                                capture_output=True, check=True, timeout=5)
        records = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) != 8:
                raise ValueError('invalid process metadata')
            records[int(fields[0])] = (int(fields[1]), tuple(fields[2:7]), fields[7].startswith(b'Z'))
        return records
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise ProofFailure('process_inspection_unavailable') from error


def classify_child_role(same_binary, command_name):
    # No full argv/environment inspection. The embedded rg source sets argv0=rg.
    if not same_binary:
        return 'other'
    return 'embedded_rg' if command_name == 'rg' else 'unknown_same_binary'


def child_role(pid, birth, binary):
    try:
        before = process_snapshot().get(pid)
        if before is None or before[1] != birth or before[2]:
            return 'exited_before_observation'
        if sys.platform == 'darwin':
            libproc = ctypes.CDLL('/usr/lib/libproc.dylib')
            buffer = ctypes.create_string_buffer(4096)
            length = libproc.proc_pidpath(pid, buffer, len(buffer))
            if length <= 0:
                return 'unobserved'
            executable = Path(os.fsdecode(buffer.value))
        elif sys.platform.startswith('linux'):
            executable = Path(os.readlink('/proc/' + str(pid) + '/exe'))
        else:
            return 'unobserved'
        # comm is the command name only, never the args/command column.
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'comm='],
                                capture_output=True, timeout=3)
        after = process_snapshot().get(pid)
        if result.returncode or after is None or after[1] != birth or len(result.stdout) > 4096:
            return 'exited_during_observation'
        return classify_child_role(os.path.samefile(executable, binary),
                                   os.fsdecode(result.stdout).strip())
    except (ProofFailure, OSError, subprocess.SubprocessError):
        return 'unobserved'


def field_type(value, key):
    if not isinstance(value, dict) or key not in value:
        return 'absent'
    field = value[key]
    if field is None:
        return 'null'
    return {dict: 'object', list: 'array', str: 'string', bool: 'boolean',
            int: 'number', float: 'number'}.get(type(field), 'other')


def initialization_observation(frame, request_id):
    response = frame.get('response', {})
    body = response.get('response', {}) if isinstance(response, dict) else None
    kind = frame.get('type')
    subtype = frame.get('subtype')
    mode = body.get('current_permission_mode') if isinstance(body, dict) else None
    return {'frame_type': kind if kind in ('control_response', 'control_request', 'system',
                                         'user', 'assistant', 'result', 'keep_alive') else 'other',
            'system_subtype': subtype if subtype in ('init', 'notification', 'informational',
                                                     'hook_started', 'hook_response', 'status',
                                                     'environment', 'project_scan') else 'other',
            'request_matches': isinstance(response, dict) and response.get('request_id') == request_id,
            'success': isinstance(response, dict) and response.get('subtype') == 'success',
            'response_fields': {key: field_type(response, key) for key in
                                ('response', 'pending_permission_requests', 'pending_user_dialog_requests')},
            'body_fields': {key: field_type(body, key) for key in
                            ('commands', 'models', 'agents', 'output_style', 'version',
                             'current_permission_mode')},
            'permission_mode': mode if mode in ('default', 'acceptEdits', 'bypassPermissions',
                                                'plan', 'auto', 'dontAsk') else 'other',
            'pending_permissions_empty': isinstance(response, dict) and response.get('pending_permission_requests') == [],
            'pending_dialogs_empty': isinstance(response, dict) and response.get('pending_user_dialog_requests') == []}


def validate_targets(session, scratch):
    match = re.fullmatch(r'claude-proof-([0-9a-f]{32})', session)
    if (not match or not scratch.is_absolute()
            or scratch.name != 'herdr-claude-' + match[1]
            or scratch.exists() or scratch.is_symlink()
            or scratch.parent.resolve(strict=True) != scratch.parent):
        raise ProofFailure('invalid_disposable_target')


def provider_command(binary, session, manual_write_policy=False, descriptor_root=None,
                     manual_bash_policy=False):
    command = [str(binary), '--print', '--input-format', 'stream-json',
            '--output-format', 'stream-json', '--verbose', '--replay-user-messages',
            '--session-id', session, '--permission-prompt-tool', 'stdio',
            '--disallowedTools', 'EnterPlanMode,ExitPlanMode']
    if manual_write_policy:
        command += ['--permission-mode', 'default', '--settings',
                    '{"permissions":{"ask":["Write"]}}']
    if manual_bash_policy:
        command += ['--tools', 'Bash', '--permission-mode', 'default', '--settings',
                    '{"permissions":{"ask":["Bash"]}}']
    if descriptor_root is not None:
        hook = shlex.join([sys.executable, str(descriptor_root / 'descriptor_child.py'),
                          'hook', str(descriptor_root / 'hook.json'), session])
        command += ['--settings', json.dumps({'hooks': {'SessionStart': [
            {'hooks': [{'type': 'command', 'command': hook, 'timeout': 10}]}]}}),
            '--mcp-config', str(descriptor_root / 'mcp.json'), '--strict-mcp-config']
    return command


def matched_replay(frame, session, message_id, text):
    return (isinstance(frame, dict) and frame.get('type') == 'user'
            and frame.get('session_id') == session and frame.get('uuid') == message_id
            and frame.get('isReplay') is True and 'parent_tool_use_id' in frame
            and frame['parent_tool_use_id'] is None and frame.get('isSynthetic') is not True
            and isinstance(frame.get('message'), dict)
            and frame['message'].get('role') == 'user'
            and frame['message'].get('content') == text)


def startup_hook(frame, session):
    subtype = frame.get('subtype')
    if (frame.get('type') != 'system' or frame.get('session_id') != session
            or frame.get('parent_tool_use_id') is not None
            or 'subagent_type' in frame or 'agent_id' in frame
            or any(not isinstance(frame.get(key), str) or not 0 < len(frame[key]) <= 256
                   for key in ('uuid', 'hook_id'))
            or not isinstance(frame.get('hook_name'), str)
            or frame.get('hook_event') not in ('SessionStart', 'Setup')):
        return False
    if subtype == 'hook_started':
        return True
    if subtype not in ('hook_progress', 'hook_response'):
        return False
    return (all(isinstance(frame.get(key), str) for key in ('stdout', 'stderr', 'output'))
            and (subtype == 'hook_progress'
                 or (frame.get('outcome') in ('success', 'error', 'cancelled')
                     and ('exit_code' not in frame or type(frame['exit_code']) is int))))


def permission_response(frame, path, decision):
    """Allow/deny exactly one requested Write, after verifying all visible scope."""
    request = frame.get('request', {})
    original = request.get('input')
    if (frame.get('type') != 'control_request' or request.get('subtype') != 'can_use_tool'
            or not isinstance(frame.get('request_id'), str)
            or not 0 < len(frame['request_id']) <= 256
            or request.get('tool_name') != 'Write'
            or original != {'file_path': str(path), 'content': 'herdr-claude-proof'}
            or decision not in ('allow', 'deny') or path.exists() or path.is_symlink()):
        raise ProofFailure('consent_scope_unverified')
    body = ({'behavior': 'allow', 'updatedInput': original} if decision == 'allow'
            else {'behavior': 'deny', 'message': 'User declined integrated operation'})
    return {'type': 'control_response', 'response': {'subtype': 'success',
            'request_id': frame['request_id'], 'response': body}}


def bash_descriptor_response(frame, command):
    request = frame.get('request')
    original = request.get('input') if isinstance(request, dict) else None
    if (frame.get('type') != 'control_request' or not isinstance(request, dict)
            or request.get('subtype') != 'can_use_tool' or request.get('tool_name') != 'Bash'
            or 'agent_id' in request or 'subagent_type' in request
            or not isinstance(frame.get('request_id'), str)
            or not 0 < len(frame['request_id']) <= 256
            or not isinstance(original, dict) or original.get('command') != command
            or set(original) - {'command', 'timeout', 'description', 'run_in_background'}
            or ('timeout' in original and (type(original['timeout']) is not int
                                           or not 0 < original['timeout'] <= 10000))
            or original.get('run_in_background', False) is not False
            or ('description' in original and not isinstance(original['description'], str))):
        raise ProofFailure('bash_descriptor_consent_scope_unverified')
    return {'type': 'control_response', 'response': {'subtype': 'success',
            'request_id': frame['request_id'], 'response': {
                'behavior': 'allow', 'updatedInput': original}}}


class Provider:
    def __init__(self, binary, root, session, manual_write_policy=False, descriptor_fixture=False,
                 manual_bash_policy=False):
        self.binary = binary
        self.observe_child_roles = descriptor_fixture
        # Establish cleanup observability before creating a process (ps may be
        # denied by the caller's outer sandbox).
        process_snapshot()
        self.buffer = b''
        self.stderr_bytes = 0
        self.owned = {}
        self.diagnostics = {}
        self.session = session
        env = os.environ.copy()
        for key in ROUTING:
            env.pop(key, None)
        read_fd, write_fd = os.pipe()
        self.control_identity = fd_identity(read_fd)
        try:
            self.child = subprocess.Popen(provider_command(binary, session, manual_write_policy,
                                            root if descriptor_fixture else None,
                                            manual_bash_policy), cwd=root, env=env,
                                          stdin=read_fd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, start_new_session=True)
        except BaseException:
            os.close(write_fd)
            raise
        finally:
            os.close(read_fd)
        self.child.stdin = os.fdopen(write_fd, 'wb', buffering=0)
        os.set_blocking(self.child.stdin.fileno(), False)

    def observe(self):
        snapshot = process_snapshot()
        for pid in descendants(self.child.pid, {pid: item[0] for pid, item in snapshot.items()}):
            if pid not in self.owned:
                birth = snapshot[pid][1]
                self.owned[pid] = birth
                if self.observe_child_roles:
                    role = child_role(pid, birth, self.binary)
                    self.diagnostics.setdefault('owned_child_roles', []).append(
                        {'pid': pid, 'birth_identity': hashlib.sha256(b'\0'.join(birth)).hexdigest(), 'role': role})

    def send(self, frame):
        data = (json.dumps(frame) + '\n').encode()
        if len(data) > 512 * 1024:
            raise ProofFailure('input_bound')
        deadline = time.monotonic() + 10
        while data:
            self.observe()
            if time.monotonic() >= deadline:
                raise ProofFailure('write_deadline')
            if select.select([], [self.child.stdin], [], .05)[1]:
                try:
                    written = os.write(self.child.stdin.fileno(), data)
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise ProofFailure('write_failed')
                data = data[written:]

    def frame(self, deadline):
        while b'\n' not in self.buffer:
            self.observe()
            if time.monotonic() >= deadline:
                raise ProofFailure('provider_deadline')
            for stream in select.select([self.child.stdout, self.child.stderr], [], [], .05)[0]:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    if self.child.poll() is not None:
                        raise ProofFailure('provider_exited')
                    continue
                if stream is self.child.stderr:
                    self.stderr_bytes += len(chunk)
                    if self.stderr_bytes > 65536:
                        raise ProofFailure('stderr_bound')
                else:
                    self.buffer += chunk
                    if len(self.buffer) > 1024 * 1024:
                        raise ProofFailure('output_bound')
        line, self.buffer = self.buffer.split(b'\n', 1)
        try:
            frame = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise ProofFailure('invalid_provider_frame') from error
        if not isinstance(frame, dict):
            raise ProofFailure('invalid_provider_frame')
        if 'session_id' in frame and frame['session_id'] != self.session:
            raise ProofFailure('session_changed')
        if frame.get('type') == 'conversation_reset':
            raise ProofFailure('conversation_reset')
        return frame

    def initialize(self):
        for request_id, subtype in [('initialize', 'initialize'), ('version', 'get_binary_version')]:
            self.send({'type': 'control_request', 'request_id': request_id,
                       'request': {'subtype': subtype}})
            deadline = time.monotonic() + 30
            while True:
                frame = self.frame(deadline)
                if frame.get('type') == 'keep_alive':
                    continue
                if startup_hook(frame, self.session):
                    key = 'startup_hook_events'
                    self.diagnostics[key] = self.diagnostics.get(key, 0) + 1
                    if self.diagnostics[key] > 4096:
                        raise ProofFailure('event_bound')
                    continue
                response = frame.get('response', {})
                self.diagnostics.setdefault('initialization_observations', {})[request_id] = initialization_observation(frame, request_id)
                if (frame.get('type') != 'control_response'
                        or not isinstance(response, dict)
                        or response.get('subtype') != 'success'
                        or response.get('request_id') != request_id):
                    raise ProofFailure('initialization_unverified')
                body = response.get('response', {})
                if not isinstance(body, dict):
                    raise ProofFailure('initialization_unverified')
                if request_id == 'initialize':
                    if (any(not isinstance(body.get(key), list) for key in ('commands', 'models', 'agents'))
                            or not isinstance(body.get('output_style'), str)
                            or response.get('pending_permission_requests') != []
                            or response.get('pending_user_dialog_requests') != []):
                        raise ProofFailure('initialization_unverified')
                elif body.get('version') != VERSION:
                    raise ProofFailure('unsupported_provider_version')
                break

    def turn(self, text, consent=None, consent_required=True):
        message_id = str(uuid.uuid4())
        self.send({'type': 'user', 'session_id': self.session, 'uuid': message_id,
                   'parent_tool_use_id': None, 'message': {'role': 'user', 'content': text}})
        replay = False
        settled = None
        deadline = time.monotonic() + 120
        count = 0
        while True:
            frame = self.frame(deadline)
            count += 1
            if count > 4096:
                raise ProofFailure('event_bound')
            kind = frame.get('type')
            kinds = self.diagnostics.setdefault('turn_event_types', {})
            label = kind if kind in ('user', 'assistant', 'result', 'control_request',
                'control_response', 'control_cancel_request', 'system', 'keep_alive',
                'rate_limit_event', 'tool_progress', 'tool_use_summary', 'command_lifecycle') else 'other'
            kinds[label] = kinds.get(label, 0) + 1
            if kind == 'user' and (frame.get('isReplay') is True or frame.get('uuid') == message_id):
                if replay or not matched_replay(frame, self.session, message_id, text):
                    raise ProofFailure('raw_replay_unverified')
                replay = True
            elif kind == 'control_request':
                if consent is None or settled is not None:
                    raise ProofFailure('unexpected_consent')
                settled = consent(frame) if callable(consent) else permission_response(frame, *consent)
                self.send(settled)
            elif kind == 'control_response':
                if frame != settled:
                    raise ProofFailure('consent_settlement_unverified')
            elif kind == 'result':
                if not replay:
                    raise ProofFailure('result_without_replay')
                if frame.get('subtype') != 'success' or frame.get('is_error') is not False:
                    raise ProofFailure('provider_turn_failed')
                if consent and consent_required and settled is None:
                    raise ProofFailure('consent_not_requested')
                return settled is not None

    def descriptor_call(self):
        request_id = 'owned-descriptor'
        self.send({'type': 'control_request', 'request_id': request_id,
                   'request': {'subtype': 'mcp_call',
                               'tool': 'mcp__herdr_descriptor__descriptor', 'arguments': {}}})
        deadline = time.monotonic() + 40
        for _ in range(4096):
            frame = self.frame(deadline)
            if frame.get('type') == 'keep_alive' or startup_hook(frame, self.session):
                continue
            response = frame.get('response')
            if (frame.get('type') != 'control_response' or not isinstance(response, dict)
                    or response.get('request_id') != request_id
                    or response.get('subtype') != 'success'):
                raise ProofFailure('descriptor_call_unverified')
            body = response.get('response')
            if (not isinstance(body, dict) or body.get('content') != [
                    {'type': 'text', 'text': 'owned descriptor fixture complete'}]):
                raise ProofFailure('descriptor_result_unverified')
            return
        raise ProofFailure('event_bound')

    def close(self):
        errors = []
        def attempt(category, action):
            try:
                action()
            except (ProofFailure, OSError, subprocess.SubprocessError):
                errors.append(category)
        try:
            self.observe()
        except (ProofFailure, OSError):
            errors.append('cleanup_observation_failed')
        attempt('cleanup_stdin_close_failed', self.child.stdin.close)
        attempt('cleanup_reap_failed', lambda: reap_owned(self.child, graceful=True))
        attempt('cleanup_stdout_close_failed', self.child.stdout.close)
        attempt('cleanup_stderr_close_failed', self.child.stderr.close)
        try:
            def gone():
                snapshot = process_snapshot()
                same = [item for pid, birth in self.owned.items()
                        if (item := snapshot.get(pid)) and item[1] == birth]
                self.diagnostics['cleanup_observation'] = {'observed_children': len(self.owned),
                    'remaining_alive': sum(not item[2] for item in same),
                    'remaining_zombie': sum(item[2] for item in same)}
                return all(item[2] for item in same)
            eventually(gone, 'owned_descendant_cleanup_unverified', timeout=5)
        except ProofFailure:
            errors.append('owned_descendant_cleanup_unverified')
        self.diagnostics['cleanup_errors'] = errors
        if errors:
            raise ProofFailure(errors[0])


def protocol_probe(args):
    validate_targets(args.session, args.scratch)
    binary = args.provider_path.resolve(strict=True)
    if not args.provider_path.is_absolute() or not os.access(binary, os.X_OK):
        raise ProofFailure('invalid_executable')
    args.scratch.mkdir(mode=0o700)
    provider = None
    evidence = {'cli_version': VERSION, 'sdk_declarations': SDK_VERSION,
                'platform': os.uname().sysname, 'qualification': False,
                'test_policy': 'manual_write' if args.manual_write_policy else 'unchanged',
                'initialize': False, 'raw_replay': False, 'allow': False, 'deny': False,
                'owned_cleanup': False}
    try:
        provider = Provider(binary, args.scratch,
                            str(uuid.UUID(args.session.removeprefix('claude-proof-'))),
                            args.manual_write_policy)
        provider.initialize()
        evidence['initialize'] = True
        if (args.manual_write_policy and provider.diagnostics.get('initialization_observations', {})
                .get('initialize', {}).get('permission_mode') != 'default'):
            raise ProofFailure('manual_policy_mode_unverified')
        if not args.initialize_only:
            provider.turn('Reply with the single word READY. Do not use tools or change files.')
            evidence['raw_replay'] = True
        for decision in (() if args.initialize_only else ('deny', 'allow')):
            path = args.scratch / (decision + '.txt')
            text = ('Use the Write tool exactly once to create the file ' + str(path)
                    + ' with exactly herdr-claude-proof as its complete content. Request permission. '
                    'Do not use any other tools or modify any other file. If denied, stop without retrying.')
            provider.turn(text, (path, decision))
            if decision == 'deny' and path.exists():
                raise ProofFailure('denied_scratch_changed')
            if decision == 'allow' and (not path.is_file() or path.read_bytes() != b'herdr-claude-proof'):
                raise ProofFailure('allowed_effect_unverified')
            evidence[decision] = True
    except ProofFailure as error:
        evidence['failure'] = str(error)
    except (OSError, subprocess.SubprocessError, ValueError):
        evidence['failure'] = 'environment_unverified'
    finally:
        try:
            if provider:
                provider.close()
            evidence['owned_cleanup'] = True
        except (ProofFailure, OSError, subprocess.SubprocessError):
            evidence['cleanup_failure'] = 'owned_cleanup_unverified'
        if provider:
            evidence.update(provider.diagnostics)
    print(json.dumps(evidence, sort_keys=True))
    required = ('initialize', 'owned_cleanup') if args.initialize_only else ('initialize', 'raw_replay', 'allow', 'deny', 'owned_cleanup')
    return 0 if all(evidence[key] for key in required) else 1


def descriptor_probe(args):
    validate_targets(args.session, args.scratch)
    if args.manual_write_policy or args.initialize_only:
        raise ProofFailure('incompatible_probe_modes')
    binary = args.provider_path.resolve(strict=True)
    if not args.provider_path.is_absolute() or not os.access(binary, os.X_OK):
        raise ProofFailure('invalid_executable')
    process_snapshot()
    descriptor_observation_control()
    args.scratch.mkdir(mode=0o700)
    session = str(uuid.UUID(args.session.removeprefix('claude-proof-')))
    bash = args.bash_descriptor_probe_only
    (args.scratch / 'descriptor_child.py').write_text(DESCRIPTOR_CHILD)
    config = {'mcpServers': {'herdr_descriptor': {'type': 'stdio',
        'command': sys.executable, 'args': [str(args.scratch / 'descriptor_child.py'),
                                          'mcp', str(args.scratch / 'mcp-receipt.json'), session]}}}
    if not bash:
        (args.scratch / 'mcp.json').write_text(json.dumps(config))
    evidence = {'cli_version': VERSION, 'sdk_declarations': SDK_VERSION,
                'platform': os.uname().sysname, 'qualification': False,
                'probe': 'owned_bash_descriptors' if bash else 'owned_hook_mcp_descriptors',
                'model_requested': bash,
                'test_config': 'default_mode_ask_bash_tools_bash_only' if bash
                    else 'additive_session_start_hook_and_strict_owned_mcp',
                'descriptor_observation_control': True, 'initialize': False,
                'owned_cleanup': False}
    cases = ([('bash_fd_isolation', 'bash.json', 'Bash')] if bash else [
        ('hook_fd_isolation', 'hook.json', 'SessionStart'),
        ('mcp_fd_isolation', 'mcp-receipt.json', 'tools/call')])
    evidence.update({key: False for key, _, _ in cases})
    provider = None
    try:
        provider = Provider(binary, args.scratch, session, descriptor_fixture=not bash,
                            manual_bash_policy=bash)
        evidence['provider_input_identity'] = provider.control_identity
        provider.initialize()
        evidence['initialize'] = True
        if bash:
            if (provider.diagnostics.get('initialization_observations', {}).get('initialize', {})
                    .get('permission_mode') != 'default'):
                raise ProofFailure('manual_policy_mode_unverified')
            command = shlex.join([sys.executable, str(args.scratch / 'descriptor_child.py'),
                                  'bash', str(args.scratch / 'bash.json'), session])
            def approve(frame):
                if (args.scratch / 'descriptor_child.py').read_text() != DESCRIPTOR_CHILD:
                    raise ProofFailure('descriptor_fixture_changed')
                return bash_descriptor_response(frame, command)
            evidence['bash_consent_requested'] = provider.turn(
                'Run the Bash tool exactly once with this exact command: ' + command
                + '. Use timeout 10000 and do not run in the background. '
                'It records only numeric descriptor metadata in the owned scratch file. '
                'Do not run any other command or tool or modify any other file. Then reply DONE.',
                approve, consent_required=False)
            evidence['raw_replay'] = True
        else:
            provider.descriptor_call()
        for key, name, kind in cases:
            receipt_path = args.scratch / name
            if (not receipt_path.is_file() or receipt_path.is_symlink()
                    or receipt_path.stat().st_size > 1024 * 1024):
                raise ProofFailure('descriptor_receipt_unverified')
            receipt = json.loads(receipt_path.read_bytes())
            evidence.setdefault('descriptor_observations', {})[key] = descriptor_observation(
                receipt, provider.control_identity, kind)
            if not isolated_receipt(receipt, provider.control_identity, kind):
                raise ProofFailure(key + '_unverified')
            evidence[key] = True
    except ProofFailure as error:
        evidence['failure'] = str(error)
    except (OSError, subprocess.SubprocessError, ValueError):
        evidence['failure'] = 'environment_unverified'
    finally:
        try:
            if provider:
                provider.close()
            evidence['owned_cleanup'] = True
        except (ProofFailure, OSError, subprocess.SubprocessError):
            evidence['cleanup_failure'] = 'owned_cleanup_unverified'
        if provider:
            evidence.update(provider.diagnostics)
    print(json.dumps(evidence, sort_keys=True))
    required = ['initialize', 'owned_cleanup', *(key for key, _, _ in cases)]
    return 0 if all(evidence[key] for key in required) else 1


def integrated_environment(root, provider):
    env = os.environ.copy()
    for key in ROUTING:
        env.pop(key, None)
    bindir = root / 'bin'
    bindir.mkdir(mode=0o700)
    launcher = bindir / 'claude'
    # Test-only stricter policy. Existing deny rules, hooks and authentication remain.
    launcher.write_text('#!' + sys.executable + '\nimport os,sys\n' +
        'os.execv(' + repr(str(provider)) + ', [' + repr(str(provider)) +
        ', \'--permission-mode\', \'default\', \'--settings\', ' +
        repr(json.dumps({'permissions': {'ask': ['Write']}})) + ', *sys.argv[1:]])\n')
    launcher.chmod(0o700)
    config = root / 'herdr.toml'
    config.write_text('onboarding = false\n[terminal]\ndefault_shell = "/bin/sh"\nshell_mode = "non_login"\n')
    env.update(XDG_CONFIG_HOME=str(root / 'c'), XDG_STATE_HOME=str(root / 's'),
               HERDR_CONFIG_PATH=str(config), TERM='xterm-256color',
               PATH=str(bindir) + os.pathsep + env.get('PATH', ''))
    return env


def integrated_consent_matches(preview, path):
    if 'HERDR PERMISSION' not in preview:
        return False
    text = '\n'.join(line.strip().strip('│').rstrip() for line in preview.splitlines())
    try:
        card, _ = json.JSONDecoder().raw_decode(text[text.index('{'):])
        if not isinstance(card, dict) or any(key in card for key in ('agent_id', 'subagent_type')):
            return False
        response = permission_response({'type': 'control_request', 'request_id': 'card',
                                        'request': card}, path, 'deny')
        return response['response']['request_id'] == 'card'
    except (ProofFailure, ValueError, KeyError, TypeError):
        return False


class IntegratedSession(CodexSession):
    # Reuse only the public bridge/UI conveniences, not Codex qualification claims.
    def __init__(self, binary, session, root, provider):
        process_snapshot()
        self.command = [str(binary), '--session', session]
        self.root = root
        self.workspace = root / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.state_root = Path(tempfile.mkdtemp(prefix='hx-ci-', dir='/tmp'))
        self.env = integrated_environment(self.state_root, provider)
        self.sequence = 0
        self.server = self.client = self.client_pty = None
        self.owned = {}
        self.diagnostics = {}
        self.closed = False

    def observe(self):
        if self.server is None:
            return
        snapshot = process_snapshot()
        for pid in descendants(self.server.pid, {pid: item[0] for pid, item in snapshot.items()}):
            self.owned.setdefault(pid, snapshot[pid][1])
        if self.client is not None:
            for pid in descendants(self.client.pid, {pid: item[0] for pid, item in snapshot.items()}):
                self.owned.setdefault(pid, snapshot[pid][1])

    def api(self, method, params=None):
        self.observe()
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
        if not isinstance(value, dict) or value.get('id') != request['id']:
            raise ProofFailure('uncorrelated_bridge_response')
        return value

    def start(self):
        self.server = subprocess.Popen(self.command + ['server'], env=self.env, cwd=self.workspace,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def ready():
            if self.server.poll() is not None:
                raise ProofFailure('owned_server_exited')
            try:
                return self.result('ping')
            except ProofFailure:
                return False
        eventually(ready, 'owned_server_start_timeout')
        ws = self.result('workspace.create', {'cwd': str(self.workspace),
            'label': 'Claude disposable qualification', 'focus': True})['workspace']
        started = self.result('agent.start_integrated', {'provider': 'claude',
            'workspace_id': ws['workspace_id'], 'cwd': str(self.workspace)})
        self.pane = started['agent']['pane_id']
        self.identity = {key: started[key] for key in ('server_instance', 'recipient_token')}
        self.identity['terminal_id'] = started['agent']['terminal_id']
        self.open_consent_view()
        def initialized():
            self.drain_client()
            return 'AwaitingSessionConfirmation' in self.preview()
        eventually(initialized, 'integrated_initialization_unverified', timeout=30)
        self.unqualified()

    def unqualified(self):
        info = self.result('agent.get', {'target': self.pane})['agent']
        if info.get('exact_prompt') is not None:
            raise ProofFailure('premature_capability_advertisement')

    def local_submit(self, text):
        self.drain_client()
        before = self.preview().count('Local submission: Accepted')
        self.result('pane.send_input', {'pane_id': self.pane, 'text': text, 'keys': ['Enter']})
        def acknowledged():
            self.drain_client()
            return self.preview().count('Local submission: Accepted') > before
        eventually(acknowledged, 'integrated_local_replay_unverified', timeout=30)

    def permission_exercise(self, decision):
        path = self.root / (decision + '.txt')
        self.local_submit('Use the Write tool exactly once to create the file ' + str(path)
            + ' with exactly herdr-claude-proof as its complete content. Request permission. '
            'Do not use any other tools or modify any other file. If denied, stop without retrying.')
        def visible():
            self.drain_client()
            return self.status() == 'blocked' and integrated_consent_matches(self.preview(), path)
        eventually(visible, 'integrated_consent_scope_unverified_' + decision, timeout=90)
        self.unqualified()
        if path.exists():
            raise ProofFailure('scratch_changed_before_consent')
        self.result('pane.send_input', {'pane_id': self.pane, 'text': decision, 'keys': ['Enter']})
        def completed():
            self.drain_client()
            return self.status() == 'idle'
        eventually(completed, 'integrated_permission_completion_unverified_' + decision, timeout=90)
        if decision == 'allow':
            if not path.is_file() or path.read_bytes() != b'herdr-claude-proof':
                raise ProofFailure('allowed_effect_unverified')
        elif path.exists():
            raise ProofFailure('denied_scratch_changed')
        self.unqualified()

    def close(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        def attempt(category, action):
            try:
                action()
            except (ProofFailure, OSError, subprocess.SubprocessError):
                errors.append(category)
        attempt('cleanup_observation_failed', self.observe)
        if self.client is not None:
            attempt('cleanup_client_reap_failed', lambda: reap_owned(self.client))
        if self.client_pty is not None:
            attempt('cleanup_pty_close_failed', lambda: os.close(self.client_pty))
        if self.server is not None:
            def stop():
                result = subprocess.run(self.command + ['server', 'stop'], env=self.env, cwd=self.workspace,
                                        capture_output=True, timeout=10)
                if result.returncode:
                    raise ProofFailure('owned_stop_failed')
                self.server.wait(timeout=10)
            attempt('cleanup_server_stop_failed', stop)
            attempt('cleanup_server_reap_failed', lambda: reap_owned(self.server))
        def gone():
            snapshot = process_snapshot()
            same = [item for pid, birth in self.owned.items()
                    if (item := snapshot.get(pid)) and item[1] == birth]
            self.diagnostics['cleanup_observation'] = {'observed_children': len(self.owned),
                'remaining_alive': sum(not item[2] for item in same),
                'remaining_zombie': sum(item[2] for item in same)}
            return not same
        attempt('owned_descendant_cleanup_unverified',
                lambda: eventually(gone, 'owned_descendant_cleanup_unverified', timeout=5))
        self.diagnostics['cleanup_errors'] = errors
        if errors:
            raise ProofFailure(errors[0])


def integrated_probe(args):
    validate_targets(args.session, args.scratch)
    if not args.manual_write_policy or args.initialize_only or args.herdr_bin is None:
        raise ProofFailure('integrated_probe_requires_manual_write_policy_and_herdr')
    binary = validate_binary(args.herdr_bin)
    provider = validate_binary(args.provider_path)
    process_snapshot()
    args.scratch.mkdir(mode=0o700)
    session = None
    evidence = {'qualification': False, 'probe': 'integrated_local_prerequisite',
                'test_policy': 'manual_write', 'initialize': False,
                'local_replay': False, 'allow': False, 'deny': False,
                'capability_absent': False, 'owned_cleanup': False}
    try:
        session = IntegratedSession(binary, args.session, args.scratch, provider)
        session.start()
        evidence['initialize'] = True
        session.local_submit('Reply with the single word HERDR_CLAUDE_PROOF_OK. Do not use tools or change files.')
        evidence['local_replay'] = True
        def completed():
            session.drain_client()
            return session.status() == 'idle'
        eventually(completed, 'integrated_harmless_turn_unverified', timeout=90)
        if 'HERDR_CLAUDE_PROOF_OK' not in session.preview():
            raise ProofFailure('integrated_response_unverified')
        if 'Claude configured permission mode: "default"' not in session.preview():
            raise ProofFailure('integrated_manual_mode_unverified')
        for decision in ('deny', 'allow'):
            session.permission_exercise(decision)
            evidence[decision] = True
        session.unqualified()
        evidence['capability_absent'] = True
    except ProofFailure as error:
        evidence['failure'] = str(error)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        evidence['failure'] = 'environment_unverified'
    finally:
        try:
            if session:
                session.close()
            evidence['owned_cleanup'] = True
        except (ProofFailure, OSError, subprocess.SubprocessError):
            evidence['cleanup_failure'] = 'owned_cleanup_unverified'
        if session:
            evidence.update(session.diagnostics)
    print(json.dumps(evidence, sort_keys=True))
    return 0 if all(evidence[key] for key in ('initialize', 'local_replay', 'deny', 'allow',
                                             'capability_absent', 'owned_cleanup')) else 1


class SafetyTests(unittest.TestCase):
    def test_child_role_evidence_serializes_real_ps_birth_identity(self):
        provider = object.__new__(Provider)
        provider.child = mock.Mock(pid=1)
        provider.owned = {}
        provider.diagnostics = {}
        provider.binary = Path('/pinned/claude')
        provider.observe_child_roles = True
        birth = (b'Sat', b'Sep', b'19', b'01:23:45', b'2026')
        with mock.patch(__name__ + '.process_snapshot', return_value={2: (1, birth, False)}), \
             mock.patch(__name__ + '.child_role', return_value='embedded_rg'):
            provider.observe()
        encoded = json.dumps(provider.diagnostics)
        self.assertIn('embedded_rg', encoded)
        self.assertEqual(provider.owned[2], birth)

    def test_child_role_requires_same_executable_and_exact_argv0(self):
        self.assertEqual(classify_child_role(True, 'rg'), 'embedded_rg')
        self.assertEqual(classify_child_role(False, 'rg'), 'other')
        self.assertEqual(classify_child_role(True, 'rg --secret'), 'unknown_same_binary')
        self.assertEqual(classify_child_role(True, '/private/claude'), 'unknown_same_binary')

    def test_integrated_policy_and_consent_are_disposable_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider = '/existing/pinned/claude'
            env = integrated_environment(root, provider)
            self.assertEqual(env.get('HOME'), os.environ.get('HOME'))
            self.assertTrue(env['PATH'].startswith(str(root / 'bin') + os.pathsep))
            launcher = (root / 'bin/claude').read_text()
            self.assertIn("'--permission-mode', 'default'", launcher)
            self.assertIn('"ask": ["Write"]', launcher)
            self.assertNotIn('--dangerously-skip-permissions', launcher)
            path = root / 'deny.txt'
            card = {'subtype': 'can_use_tool', 'tool_name': 'Write',
                    'tool_use_id': 'owned-tool', 'input': {'file_path': str(path),
                    'content': 'herdr-claude-proof'}}
            preview = 'HERDR PERMISSION — Write\n' + json.dumps(card)
            self.assertTrue(integrated_consent_matches(preview, path))
            for key, value in [('content', 'extra'), ('file_path', str(root / 'elsewhere'))]:
                changed = json.loads(json.dumps(card))
                changed['input'][key] = value
                self.assertFalse(integrated_consent_matches('HERDR PERMISSION\n' + json.dumps(changed), path))
            card['agent_id'] = 'child'
            self.assertFalse(integrated_consent_matches('HERDR PERMISSION\n' + json.dumps(card), path))

    def test_descriptor_identity_is_observable_and_distinguishes_pipes(self):
        first = os.pipe()
        second = os.pipe()
        try:
            identity = fd_identity(first[0])
            self.assertNotEqual(identity, fd_identity(second[0]))
            result = subprocess.run([sys.executable, '-c',
                'import os,json; s=os.fstat(0); print(json.dumps([s.st_dev,s.st_ino,s.st_mode]))'],
                stdin=first[0], capture_output=True, check=True, timeout=5)
            self.assertEqual(json.loads(result.stdout), identity)
        finally:
            for fd in (*first, *second):
                os.close(fd)

    def test_descriptor_receipts_refuse_control_inheritance_and_missing_stdin(self):
        control = [1, 2, 3]
        receipt = {'input_kind': 'initialize', 'fds': [[0, 4, 5, 6], [1, 7, 8, 9]]}
        self.assertTrue(isolated_receipt(receipt, control, 'initialize'))
        for fds in ([[0, *control]], [[0, 4, 5, 6], [9, *control]], [[1, 4, 5, 6]], []):
            self.assertFalse(isolated_receipt(dict(receipt, fds=fds), control, 'initialize'))

    def test_darwin_socket_device_number_is_signed_metadata(self):
        receipt = {'input_kind': 'SessionStart', 'fds': [[0, -1, 555232, 49152],
                                                        [1, -1, 555234, 49590]]}
        self.assertTrue(isolated_receipt(receipt, [0, 123456789, 4528], 'SessionStart'))
        self.assertFalse(isolated_receipt(receipt, [-1, 555232, 49152], 'SessionStart'))

    def test_owned_descriptor_children_only_record_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / 'child.py'
            script.write_text(DESCRIPTOR_CHILD)
            cases = [('hook', [{'hook_event_name': 'SessionStart', 'session_id': 'session',
                               'private_data': 'must-not-be-recorded'}], 'SessionStart'),
                     ('bash', [], 'Bash'),
                     ('mcp', [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                               'params': {'protocolVersion': '2025-03-26'}},
                              {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                               'params': {'name': 'descriptor', 'arguments': {}}}], 'tools/call')]
            for mode, frames, kind in cases:
                receipt = root / (mode + '.json')
                subprocess.run([sys.executable, str(script), mode, str(receipt), 'session'],
                    input=''.join(json.dumps(frame) + '\n' for frame in frames).encode(),
                    capture_output=True, check=True, timeout=5)
                value = json.loads(receipt.read_bytes())
                self.assertEqual(set(value), {'input_kind', 'fds'})
                self.assertTrue(isolated_receipt(value, [-1, -1, -1], kind))
                self.assertNotIn('must-not-be-recorded', receipt.read_text())

    def test_descriptor_exchange_cannot_emit_text_or_accept_unrelated_response(self):
        provider = Provider.__new__(Provider)
        provider.session = 'session'
        with mock.patch.object(provider, 'send') as send:
            with mock.patch.object(provider, 'frame', return_value={
                    'type': 'control_response', 'response': {'request_id': 'unrelated',
                                                           'subtype': 'success'}}):
                with self.assertRaisesRegex(ProofFailure, 'descriptor_call_unverified'):
                    provider.descriptor_call()
            send.assert_called_once_with({'type': 'control_request', 'request_id': 'owned-descriptor',
                'request': {'subtype': 'mcp_call', 'tool': 'mcp__herdr_descriptor__descriptor',
                            'arguments': {}}})

    def test_startup_hook_requires_original_context_and_schema(self):
        frame = {'type': 'system', 'subtype': 'hook_started', 'session_id': 'session',
                 'uuid': 'event', 'hook_id': 'hook', 'hook_name': 'private', 'hook_event': 'SessionStart'}
        self.assertTrue(startup_hook(frame, 'session'))
        for key, value in [('session_id', 'replacement'), ('parent_tool_use_id', 'child'),
                           ('hook_id', None), ('hook_name', []), ('hook_event', 'unknown'),
                           ('subtype', 'hook_response')]:
            self.assertFalse(startup_hook(dict(frame, **{key: value}), 'session'))

    def test_stdin_close_failure_cannot_skip_child_reaping(self):
        provider = Provider.__new__(Provider)
        provider.child = mock.Mock()
        provider.child.stdin.close.side_effect = BrokenPipeError()
        provider.diagnostics = {}
        provider.owned = {}
        with mock.patch.object(provider, 'observe'):
            with mock.patch(__name__ + '.process_snapshot', return_value={}):
                with mock.patch(__name__ + '.reap_owned') as reap:
                    with self.assertRaisesRegex(ProofFailure, 'cleanup_stdin_close_failed'):
                        provider.close()
                    reap.assert_called_once_with(provider.child, graceful=True)
        self.assertEqual(provider.diagnostics['cleanup_errors'], ['cleanup_stdin_close_failed'])

    def test_process_inspection_precedes_spawn(self):
        with mock.patch(__name__ + '.process_snapshot', side_effect=ProofFailure('process_inspection_unavailable')):
            with mock.patch('subprocess.Popen') as spawn:
                with self.assertRaises(ProofFailure):
                    Provider('/provider', Path('/scratch'), 'session')
                spawn.assert_not_called()

    def test_initialization_diagnostics_do_not_expose_values(self):
        frame = {'type': 'credential-private', 'subtype': 'secret-private',
                 'response': {'request_id': 'private-request', 'subtype': 'private',
                              'response': {'commands': ['private-prompt'], 'version': 'private-version'}}}
        encoded = json.dumps(initialization_observation(frame, 'initialize'))
        self.assertNotIn('private', encoded)
        self.assertIn('array', encoded)

    def test_permission_mode_diagnostic_is_allowlisted(self):
        for value, expected in [('default', 'default'), ('acceptEdits', 'acceptEdits'),
                                ('private-policy', 'other'), (['private-policy'], 'other')]:
            frame = {'response': {'response': {'current_permission_mode': value}}}
            observation = initialization_observation(frame, 'initialize')
            self.assertEqual(observation['permission_mode'], expected)
            self.assertNotIn('private', json.dumps(observation))

    def test_malformed_initialize_fails_with_safe_category(self):
        for response in (None, [], 'private', {'subtype': 'success',
                          'request_id': 'initialize', 'response': []}):
            provider = Provider.__new__(Provider)
            provider.session = 'session'
            provider.diagnostics = {}
            with mock.patch.object(provider, 'send'):
                with mock.patch.object(provider, 'frame', return_value={
                        'type': 'control_response', 'response': response}):
                    with self.assertRaisesRegex(ProofFailure, 'initialization_unverified'):
                        provider.initialize()

    def test_exact_raw_replay_identity(self):
        frame = {'type': 'user', 'uuid': 'message', 'session_id': 'session', 'isReplay': True,
                 'parent_tool_use_id': None, 'message': {'role': 'user', 'content': 'text'}}
        self.assertTrue(matched_replay(frame, 'session', 'message', 'text'))
        for key, value in [('uuid', 'other'), ('session_id', 'other'), ('isReplay', False),
                           ('parent_tool_use_id', 'child'), ('isSynthetic', True),
                           ('message', {'role': 'user', 'content': 'other'}),
                           ('message', {'role': 'assistant', 'content': 'text'})]:
            self.assertFalse(matched_replay(dict(frame, **{key: value}), 'session', 'message', 'text'))
        for key in ('uuid', 'session_id', 'isReplay', 'parent_tool_use_id', 'message'):
            candidate = frame.copy()
            candidate.pop(key)
            self.assertFalse(matched_replay(candidate, 'session', 'message', 'text'))

    def test_no_policy_or_auth_overrides(self):
        command = provider_command(Path('/provider'), 'session')
        self.assertNotIn('--permission-mode', command)
        self.assertNotIn('--dangerously-skip-permissions', command)
        self.assertNotIn('--settings', command)
        self.assertNotIn('--resume', command)
        self.assertNotIn('--continue', command)

    def test_disposable_manual_policy_only_adds_write_ask_and_default_mode(self):
        baseline = provider_command(Path('/provider'), 'session')
        command = provider_command(Path('/provider'), 'session', manual_write_policy=True)
        self.assertEqual(command[:len(baseline)], baseline)
        self.assertEqual(command[len(baseline):], ['--permission-mode', 'default', '--settings',
                                                  '{"permissions":{"ask":["Write"]}}'])

    def test_unverified_manual_mode_stops_before_any_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            nonce = uuid.uuid4().hex
            args = argparse.Namespace(session='claude-proof-' + nonce,
                scratch=Path(temporary).resolve() / ('herdr-claude-' + nonce),
                provider_path=Path('/usr/bin/true'), manual_write_policy=True,
                initialize_only=False)
            with mock.patch(__name__ + '.Provider') as provider_type:
                provider = provider_type.return_value
                provider.diagnostics = {'initialization_observations': {
                    'initialize': {'permission_mode': 'acceptEdits'}}}
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(protocol_probe(args), 1)
                provider.turn.assert_not_called()
                provider.close.assert_called_once()
                self.assertEqual(json.loads(output.getvalue())['failure'],
                                 'manual_policy_mode_unverified')

    def test_unknown_consent_cannot_be_allowed(self):
        frame = {'type': 'control_request', 'request_id': 'control',
                 'request': {'subtype': 'can_use_tool', 'tool_name': 'Bash',
                             'input': {'command': 'unapproved'}}}
        with self.assertRaises(ProofFailure):
            permission_response(frame, Path('/nonexistent'), 'allow')

    def test_bash_descriptor_consent_only_allows_exact_owned_command(self):
        baseline = provider_command(Path('/provider'), 'session')
        self.assertEqual(provider_command(Path('/provider'), 'session', manual_bash_policy=True),
                         baseline + ['--tools', 'Bash', '--permission-mode', 'default', '--settings',
                                     '{"permissions":{"ask":["Bash"]}}'])
        frame = {'type': 'control_request', 'request_id': 'control', 'request': {
            'subtype': 'can_use_tool', 'tool_name': 'Bash', 'input': {
                'command': 'owned-command', 'timeout': 10000, 'description': 'metadata'}}}
        response = bash_descriptor_response(frame, 'owned-command')
        self.assertEqual(response['response']['response'], {
            'behavior': 'allow', 'updatedInput': frame['request']['input']})
        for key, value in [('command', 'different-command'), ('timeout', 60000),
                           ('run_in_background', True), ('dangerouslyDisableSandbox', True)]:
            candidate = json.loads(json.dumps(frame))
            candidate['request']['input'][key] = value
            with self.assertRaises(ProofFailure):
                bash_descriptor_response(candidate, 'owned-command')

    def test_existing_and_mismatched_targets_refused(self):
        for session, path in [('default', '/tmp'), ('claude-proof-' + '0' * 32, '/tmp'),
                              ('claude-proof-' + '0' * 32, 'herdr-claude-' + '0' * 32)]:
            with self.assertRaises(ProofFailure):
                validate_targets(session, Path(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--protocol-probe-only', action='store_true',
                        help='explicit opt-in raw replay/consent prerequisite; does not qualify integrated Send')
    mode.add_argument('--descriptor-probe-only', action='store_true',
                        help='owned hook/MCP descriptor fixture only; no text or model call')
    mode.add_argument('--bash-descriptor-probe-only', action='store_true',
                        help='one owned Bash descriptor command via model; explicit process-only manual policy')
    mode.add_argument('--integrated-local-probe-only', action='store_true',
                        help='explicit local composer prerequisite, not remote exact Send qualification')
    parser.add_argument('--herdr-bin', type=Path)
    parser.add_argument('--initialize-only', action='store_true',
                        help='bounded protocol diagnostics only: no model prompt or tool request')
    parser.add_argument('--manual-write-policy', action='store_true',
                        help='explicit disposable-only default mode plus additive Write ask rule; preserves saved settings and hooks')
    parser.add_argument('--session', required=True, help='fresh claude-proof-<32 random hex> target')
    parser.add_argument('--scratch', required=True, type=Path,
                        help='fresh canonical absolute herdr-claude-<same hex> directory')
    parser.add_argument('--provider-path', required=True, type=Path,
                        help='existing absolute Claude 2.1.276 executable; no install or update')
    args = parser.parse_args()
    try:
        if args.integrated_local_probe_only:
            return integrated_probe(args)
        return descriptor_probe(args) if (args.descriptor_probe_only or args.bash_descriptor_probe_only) else protocol_probe(args)
    except (ProofFailure, OSError, ValueError):
        print(json.dumps({'qualification': False, 'failure': 'preflight_unverified'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
