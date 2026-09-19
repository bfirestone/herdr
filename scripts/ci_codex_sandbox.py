#!/usr/bin/env python3
"""Bounded, disposable Ubuntu CI experiment; never a host setup utility.

Root modes operate only on constants below. Journal data cannot select paths or
commands. No package installation, sysctl writes, profile replacement or service
reload is supported. Fixture modes always run as the original nonroot CI user.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import uuid

VERSION = '0.154.0'
RESOURCE_HASH = '01fb705f067bd5365b63d8ad2323a61c8d007733ca5e649437e086f3fb9935d8'
RESOURCE_SIZE = 529776
REGISTRY_INTEGRITY = 'sha512-a4FI3A8sGtwGrOqltrPbrS2hajrHQG591EwmRfiRoLMb10VxdBtUGW4gu6IJVYENiYGA7k3P4jlRHEoCZU/s9Q=='
PROFILE_HASH = '11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9'
PACKAGE_VERSION = '4.0.1really4.0.1-0ubuntu0.24.04.7'
RUNTIME_PARENT = Path('/opt/herdr-codex-runtime')
RUNTIME = RUNTIME_PARENT / VERSION
BWRAP = RUNTIME / 'bwrap'
PROFILE = Path('/etc/apparmor.d/herdr-codex-bwrap-0154')
STATE = Path('/run/herdr-codex-runtime-0154')
JOURNAL = STATE / 'journal.json'
PARSER = '/sbin/apparmor_parser'
PROFILE_LIST = Path('/sys/kernel/security/apparmor/profiles')
POLICY = Path('/sys/kernel/security/apparmor/policy/profiles')
SCALARS = {
    'apparmor_enabled': Path('/sys/module/apparmor/parameters/enabled'),
    'restrict_userns': Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns'),
    'restrict_unconfined': Path('/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined'),
    'userns_clone': Path('/proc/sys/kernel/unprivileged_userns_clone'),
}
OWNED_PROFILES = {'bwrap (enforce)', 'unpriv_bwrap (enforce)'}


class Refused(Exception):
    """Only fixed categories are allowed in public output."""


def require(value, category):
    if not value:
        raise Refused(category)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, *, cwd=None, data=None):
    # All callers provide fixed argument shapes; raw command output is private.
    result = subprocess.run(argv, cwd=cwd, input=data, capture_output=True, timeout=60,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        category = ({'-Q': 'profile_parse_failed', '-a': 'profile_add_failed', '-R': 'profile_remove_failed'}.get(argv[1], 'operation_failed')
                    if argv[0] == PARSER else 'profile_download_failed' if argv[0] == '/usr/bin/apt-get' else 'profile_extract_failed')
        raise Refused(category)
    return result.stdout


def target(root=False):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'wrong_target')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and
            release.get('VERSION_ID', '').strip('"') == '24.04', 'wrong_target')
    require(os.environ.get('CI') == 'true' and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('GITHUB_REPOSITORY') == 'bfirestone/herdr' and
            os.environ.get('GITHUB_REF') == 'refs/heads/feat/desktop-exact-delivery', 'wrong_ci_target')
    uid = int(os.environ.get('SUDO_UID', '-1')) if root else os.getuid()
    require(uid > 0 and (os.geteuid() == 0 if root else os.geteuid() == uid), 'wrong_fixture_user')
    return uid


def identity(path, *, directory=False, mode=None, root=True):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), 'unsafe_file_type')
    require(not st.st_mode & (stat.S_ISUID | stat.S_ISGID), 'unsafe_file_mode')
    if root:
        require(st.st_uid == 0 and not st.st_mode & 0o022, 'unsafe_file_owner')
    if mode is not None:
        require(stat.S_IMODE(st.st_mode) == mode, 'unsafe_file_mode')
    require('security.capability' not in os.listxattr(path, follow_symlinks=False), 'file_capability')
    return [st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)]


def chain(path):
    for parent in reversed((path, *path.parents)):
        identity(parent, directory=True)


def restrictions():
    result = {}
    for key, path in SCALARS.items():
        try:
            value = path.read_text().strip()
        except FileNotFoundError:
            require(key not in ('apparmor_enabled', 'restrict_userns'), 'mandatory_restriction_missing')
            value = None
        require(value in ('Y', 'N') if key == 'apparmor_enabled' else value in ('0', '1', None), 'unknown_restriction')
        result[key] = value
    require(result['apparmor_enabled'] == 'Y' and result['restrict_userns'] == '1', 'restrictions_disabled')
    require(result['userns_clone'] in ('1', None), 'incompatible_restrictions')
    return result


def profiles():
    values = PROFILE_LIST.read_text().splitlines()
    require(len(values) == len(set(values)), 'profile_inventory_uncertain')
    return sorted(values)


def attachments():
    require(POLICY.is_dir(), 'attachment_inventory_unavailable')
    result = []
    def visit(parent):
        for entry in parent.iterdir():
            if not entry.is_dir():
                continue
            name = (entry / 'name').read_text().strip()
            attach = (entry / 'attach').read_text().strip()
            result.append((name, attach))
            children = entry / 'profiles'
            if children.exists():
                visit(children)
    visit(POLICY)
    return result


def no_customization():
    for name in ('bwrap-userns-restrict', 'unpriv_bwrap'):
        path = Path('/etc/apparmor.d/local') / name
        require(not path.exists() and not path.is_symlink(), 'profile_customization_present')


def resource():
    prefix = Path(os.environ['RUNNER_TEMP']) / 'herdr-codex-provider/node_modules/@openai'
    require(prefix.is_absolute() and prefix.resolve() == prefix, 'provider_path_uncertain')
    candidates = list(prefix.glob('codex-*/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap'))
    require(len(candidates) == 1, 'provider_resource_count')
    path = candidates[0]
    require(path.resolve() == path, 'provider_path_uncertain')
    package = json.loads((path.parents[3] / 'package.json').read_text())
    require(package.get('version') == VERSION + '-linux-x64' and package.get('name') == '@openai/codex', 'provider_package_mismatch')
    identity(path, root=False)
    data = path.read_bytes()
    require(os.access(path, os.X_OK) and len(data) == RESOURCE_SIZE and digest(data) == RESOURCE_HASH, 'provider_resource_mismatch')
    return path, data


def derived_profile(data):
    require(digest(data) == PROFILE_HASH and data.count(b'/usr/bin/bwrap') == 1, 'profile_source_mismatch')
    return data.replace(b'/usr/bin/bwrap', str(BWRAP).encode())


def download_profile(record):
    # APT authenticates its archive indices/download; never execute maintainer scripts.
    run(['/usr/bin/apt-get', '-o', 'APT::Get::AllowUnauthenticated=false', '-o',
         'Acquire::AllowInsecureRepositories=false', 'download', 'apparmor-profiles=' + PACKAGE_VERSION], cwd=STATE)
    files = list(STATE.glob('apparmor-profiles_*.deb'))
    require(len(files) == 1, 'profile_archive_count')
    archive = files[0]
    record['files']['archive'] = {'identity': identity(archive), 'hash': digest(archive.read_bytes())}
    write_journal(record)
    fields = run(['/usr/bin/dpkg-deb', '-f', str(archive), 'Package', 'Version']).decode().splitlines()
    require(fields == ['Package: apparmor-profiles', 'Version: ' + PACKAGE_VERSION], 'profile_package_mismatch')
    data = run(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(archive)])
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        members = [m for m in tar if m.name.lstrip('./') == 'usr/share/apparmor/extra-profiles/bwrap-userns-restrict']
        require(len(members) == 1 and members[0].isfile() and members[0].size < 16384, 'profile_member_mismatch')
        result = tar.extractfile(members[0]).read()
    derived_profile(result)
    return result, archive


def attachment_may_match(attachment):
    """Prove disjointness by literal prefix, expanding finite brace alternatives.

    Anything not understood remains a collision. AppArmor may use a broader glob
    grammar than Python; we deliberately do not approximate it with fnmatch.
    """
    if attachment == '<unknown>' or not attachment:
        return True
    if re.fullmatch(r'[a-zA-Z0-9_.:+ -]+', attachment):
        # apparmorfs returns the plain profile name when no xmatch is present.
        return False
    pending = [attachment]
    expanded = []
    while pending:
        value = pending.pop()
        match = re.search(r'\{([^{}]+)\}', value)
        if match:
            parts = match[1].split(',')
            if len(parts) < 2 or len(pending) + len(expanded) + len(parts) > 128:
                return True
            pending.extend(value[:match.start()] + part + value[match.end():] for part in parts)
        else:
            expanded.append(value)
    for value in expanded:
        prefix = re.split(r'[*?\[{}\\@]', value, maxsplit=1)[0]
        if not prefix.startswith('/') or str(BWRAP).startswith(prefix):
            return True
    return False


def fixture_status_path():
    parent = Path(os.environ['RUNNER_TEMP'])
    require(parent.is_absolute() and parent.resolve() == parent, 'fixture_status_parent_uncertain')
    return parent / 'herdr-codex-runtime-fixtures.json'


def fixture_status_write(status, *, first=False):
    path = fixture_status_path()
    # In-place same-fd updates: interruption leaves malformed evidence and cleanup
    # fails closed. Never rename over an unowned record.
    with path.open('x' if first else 'r+') as handle:
        if first:
            os.fchmod(handle.fileno(), 0o600)
        require(identity(path, mode=0o600, root=False)[2] == os.getuid(), 'fixture_status_owner')
        handle.seek(0)
        json.dump({'schema': 1, 'reaped': status}, handle)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())


def fixture_status_verified(record):
    path = fixture_status_path()
    if not path.exists() and not path.is_symlink():
        return None  # The wrapper registers before its first candidate launch.
    observed = identity(path, mode=0o600, root=False)
    require(observed[2] == record['uid'] and path.stat().st_size < 256, 'fixture_status_owner')
    data = json.loads(path.read_text())
    require(data == {'schema': 1, 'reaped': [True, True]} and
            all(type(value) is bool for value in data['reaped']), 'fixture_cleanup_unverified')
    return observed


def preflight():
    uid = target(root=True)
    for path in (RUNTIME, PROFILE, STATE, fixture_status_path()):
        require(not path.exists() and not path.is_symlink(), 'owned_path_collision')
    chain(RUNTIME_PARENT if RUNTIME_PARENT.exists() else RUNTIME_PARENT.parent)
    chain(PROFILE.parent)
    chain(STATE.parent)
    no_customization()
    require(Path(PARSER).is_file() and os.access(PARSER, os.X_OK), 'parser_unavailable')
    for name in ('abi/4.0', 'tunables/global'):
        require((PROFILE.parent / name).is_file(), 'profile_include_unavailable')
    original = profiles()
    require(not any(v.split(' (', 1)[0] in ('bwrap', 'unpriv_bwrap') for v in original), 'profile_collision')
    observed = attachments()
    require(len(observed) == len(original), 'attachment_inventory_uncertain')
    require(not any(name in ('bwrap', 'unpriv_bwrap') or attachment_may_match(attach)
                    for name, attach in observed), 'attachment_collision')
    source, data = resource()
    return {'schema': 1, 'uid': uid, 'restrictions': restrictions(), 'profiles': original,
            'source_identity': identity(source, root=False), 'source_hash': digest(data),
            'parents': {}, 'files': {}, 'load_attempted': False, 'loaded': [], 'phase': 'registered'}


def write_journal(record):
    # Atomic replacement only inside our root-owned directory; never a caller path.
    chain(STATE)
    temporary = STATE / 'journal.next'
    with temporary.open('x') as handle:
        os.chmod(temporary, 0o600)
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(JOURNAL)


def read_journal():
    chain(STATE)
    identity(JOURNAL, mode=0o600)
    record = json.loads(JOURNAL.read_text())
    require(record.get('schema') == 1 and record.get('uid') == target(root=True), 'journal_identity_mismatch')
    require(set(record.get('parents', {})) <= {'parent', 'runtime'} and
            set(record.get('files', {})) <= {'binary', 'profile', 'archive'} and
            set(record.get('loaded', [])) <= OWNED_PROFILES and
            record.get('source_hash') == RESOURCE_HASH, 'journal_schema_mismatch')
    return record


def verify_source(record):
    source, _ = resource()
    require(identity(source, root=False) == record['source_identity'], 'provider_identity_changed')
    require(restrictions() == record['restrictions'], 'restriction_drift')
    no_customization()


def verify_owned(record):
    verify_source(record)
    for key, path in (('parent', RUNTIME_PARENT), ('runtime', RUNTIME)):
        if key in record['parents']:
            require(identity(path, directory=True, mode=0o755) == record['parents'][key], 'owned_parent_changed')
    chain(RUNTIME)
    require(identity(BWRAP, mode=0o755) == record['files']['binary']['identity'] and
            digest(BWRAP.read_bytes()) == RESOURCE_HASH, 'owned_binary_changed')
    require(identity(PROFILE, mode=0o644) == record['files']['profile']['identity'] and
            digest(PROFILE.read_bytes()) == record['files']['profile']['hash'], 'owned_profile_changed')
    require(profiles() == sorted(record['profiles'] + list(OWNED_PROFILES)), 'loaded_profile_drift')
    attached = dict(attachments())
    require(attached.get('bwrap') == str(BWRAP) and attached.get('unpriv_bwrap') == 'unpriv_bwrap', 'owned_attachment_changed')


def apply():
    record = preflight()
    # Register rollback before policy/runtime mutation. STATE itself is exclusive.
    STATE.mkdir(mode=0o700)
    write_journal(record)
    try:
        source_profile, archive = download_profile(record)
        profile = derived_profile(source_profile)
        for key, path in (('parent', RUNTIME_PARENT), ('runtime', RUNTIME)):
            if not path.exists():
                path.mkdir(mode=0o755)
                record['parents'][key] = identity(path, directory=True, mode=0o755)
                write_journal(record)
        chain(RUNTIME)
        _, data = resource()
        for key, path, content, mode in (('binary', BWRAP, data, 0o755), ('profile', PROFILE, profile, 0o644)):
            with path.open('xb') as handle:
                os.fchmod(handle.fileno(), mode)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            record['files'][key] = {'identity': identity(path, mode=mode), 'hash': digest(content)}
            write_journal(record)
        verify_source(record)
        run([PARSER, '-Q', '-T', '-K', str(PROFILE)])
        require(profiles() == record['profiles'], 'preload_profile_drift')
        record['load_attempted'] = True
        write_journal(record)
        try:
            run([PARSER, '-a', '-T', '-K', str(PROFILE)])
        finally:
            record['loaded'] = sorted(set(profiles()) & OWNED_PROFILES)
            write_journal(record)
        verify_owned(record)
        record['phase'] = 'applied'
        write_journal(record)
        return {'apply': 'PASS', 'resource_sha256': RESOURCE_HASH, 'profile_source_sha256': PROFILE_HASH,
                'profile_runtime_sha256': digest(profile), 'package_version': PACKAGE_VERSION}
    except BaseException:
        # Preserve the root journal even if rollback cannot establish ownership.
        cleanup()
        raise


def cleanup():
    target(root=True)
    if not STATE.exists():
        # No state means only that apply did not register. Require pristine paths.
        preflight()
        return {'cleanup': 'PASS_no_apply'}
    record = read_journal()
    fixture_identity = fixture_status_verified(record)
    verify_source(record)
    current = set(profiles())
    require(current - OWNED_PROFILES == set(record['profiles']), 'cleanup_profile_drift')
    added = current & OWNED_PROFILES
    require(not added or record['load_attempted'], 'cleanup_unowned_profile')
    if added:
        item = record['files'].get('profile')
        require(item and identity(PROFILE, mode=0o644) == item['identity'] and
                digest(PROFILE.read_bytes()) == item['hash'], 'cleanup_profile_changed')
        attached = dict(attachments())
        require('bwrap (enforce)' not in added or attached.get('bwrap') == str(BWRAP), 'cleanup_attachment_changed')
        # On partial parser success remove only the exact profiles observed added.
        content = PROFILE.read_bytes()
        split = content.index(b'profile unpriv_bwrap ')
        for name, data in (('unpriv_bwrap (enforce)', content[:content.index(b'profile bwrap ')] + content[split:]),
                           ('bwrap (enforce)', content[:split])):
            if name in added:
                run([PARSER, '-R', '-T', '-K'], data=data)
        require(profiles() == record['profiles'], 'cleanup_profiles_not_restored')
    for key, path in (('profile', PROFILE), ('binary', BWRAP)):
        item = record['files'].get(key)
        if item:
            require(identity(path) == item['identity'] and digest(path.read_bytes()) == item['hash'], 'cleanup_file_changed')
            path.unlink()
            del record['files'][key]
            write_journal(record)
        else:
            require(not path.exists() and not path.is_symlink(), 'cleanup_unowned_file')
    for key, path in (('runtime', RUNTIME), ('parent', RUNTIME_PARENT)):
        if key in record['parents']:
            require(identity(path, directory=True, mode=0o755) == record['parents'][key], 'cleanup_parent_changed')
            path.rmdir()
            del record['parents'][key]
            write_journal(record)
    verify_source(record)
    require(profiles() == record['profiles'], 'cleanup_profiles_not_restored')
    # Archive debris is private and fixed-shape, but still identity/hash checked.
    archives = list(STATE.glob('apparmor-profiles_*.deb'))
    item = record['files'].get('archive')
    if item:
        require(len(archives) == 1 and identity(archives[0]) == item['identity'] and
                digest(archives[0].read_bytes()) == item['hash'], 'cleanup_archive_changed')
        archives[0].unlink()
    require(set(STATE.iterdir()) == {JOURNAL}, 'cleanup_unknown_debris')
    if fixture_identity is not None:
        require(identity(fixture_status_path(), mode=0o600, root=False) == fixture_identity, 'fixture_status_owner')
        fixture_status_path().unlink()
    JOURNAL.unlink()
    STATE.rmdir()
    require(not PROFILE.exists() and not RUNTIME.exists() and not STATE.exists(), 'cleanup_paths_not_restored')
    return {'cleanup': 'PASS', 'restrictions_unchanged': True, 'provider_bytes_unchanged': True,
            'profiles_restored': True, 'owned_paths_restored': True}


def safe_fixture_report(report):
    """Whitelist bounded existing harness evidence, never arbitrary nested JSON."""
    def enum(value, allowed, fallback):
        return value if type(value) is str and value in allowed else fallback
    statuses = {'UNVERIFIED', 'PASS', 'PASS_no_account_empty_home', 'PASS_null_private_pipe_and_pty'}
    result = {}
    for key in ('qualification', 'tool_fd_isolation', 'hook_fd_isolation', 'mcp_fd_isolation',
                'owned_cleanup', 'provider_authentication', 'hook_stopped_before_model_output'):
        if key in report:
            result[key] = report[key] if isinstance(report[key], str) and report[key] in statuses else 'UNVERIFIED'
    result['failure_observed'] = 'diagnostic' in report
    diagnostics = {'fixture_enforcement_malformed', 'fixture_enforcement_not_proven',
                   'fixture_candidate_environment', 'fixture_candidate_not_first', 'fixture_candidate_ineligible',
                   'fixture_denial_target_invalid', 'fixture_parent_write_control', 'fixture_parent_network_control',
                   'fixture_outside_canary_changed', 'fixture_listener_reached', 'fixture_tool_failed_null',
                   'fixture_tool_failed_pipe', 'fixture_tool_failed_pty', 'fixture_timeout',
                   'fixture_owned_tree_cleanup', 'process_inspection_unavailable'}
    if 'diagnostic' in report:
        result['diagnostic'] = enum(report['diagnostic'], diagnostics, 'unclassified')
    enforcement = report.get('linux_enforcement')
    if isinstance(enforcement, dict):
        keys = ('stacked_enforce', 'effective_caps_zero', 'permitted_caps_zero', 'no_new_privs', 'seccomp_filter',
                'python_started', 'nonroot', 'outside_write_denied', 'loopback_connect_denied',
                'parent_write_control', 'parent_connect_control', 'canary_unchanged', 'parent_listener_unreached')
        result['linux_enforcement'] = {key: enforcement.get(key) is True for key in keys}
    detail = report.get('runtime_diagnostics')
    if isinstance(detail, dict):
        # Use the exact existing diagnostic category list, but never its literals.
        try:
            from test_integrated_codex import RUNTIME_SIGNATURES
        except ModuleNotFoundError:
            from scripts.test_integrated_codex import RUNTIME_SIGNATURES
        labels = {name for name, _ in RUNTIME_SIGNATURES}
        outcomes = {'not_run', 'response', 'malformed_result', 'transport_error', 'rpc_error',
                    'deadline', 'bound', 'provider_exit', 'ownership_unverified'}
        clean = {'python_started': detail.get('python_started') is True}
        for name in ('original_control', 'true', 'python_startup'):
            item = detail.get(name, {})
            item = item if isinstance(item, dict) else {}
            code = item.get('exit_code')
            observed = {'exit_code': code if type(code) is int and -(2 ** 31) <= code < 2 ** 31 else None,
                        'outcome': enum(item.get('outcome'), outcomes, 'malformed_result')}
            for stream in ('stdout', 'stderr'):
                data = item.get(stream, {})
                data = data if isinstance(data, dict) else {}
                signatures = data.get('signatures', [])
                observed[stream] = {
                    'type': enum(data.get('type'), ('absent', 'string', 'other'), 'other'),
                    'signatures': sorted(labels.intersection(v for v in signatures if isinstance(v, str))) if isinstance(signatures, list) else [],
                    'scan_truncated': data.get('scan_truncated') is True,
                    'unmatched_nonempty': data.get('unmatched_nonempty') is True,
                }
                for key, bound in (('observed_utf8_bytes', 4194305), ('scan_utf8_bytes', 65536)):
                    value = data.get(key)
                    observed[stream][key] = value if type(value) is int and 0 <= value <= bound else None
            clean[name] = observed
        result['runtime_diagnostics'] = clean
    environment = report.get('runtime_environment')
    if isinstance(environment, dict):
        # Only presence/boolean metadata; scalar restriction evidence is separately
        # read by the root helper and checked before/after the runtime experiment.
        keys = ('apparmor_enabled', 'system_bwrap_executable', 'bwrap_profile_file_present', 'parent_path_bwrap_is_system')
        result['runtime_environment'] = {key: environment[key] if type(environment.get(key)) is bool else None for key in keys}
    return result


def fixtures(stage):
    target()
    source, _ = resource()
    prefix = source.parents[4]
    native = list(prefix.glob('codex-*/vendor/x86_64-unknown-linux-musl/bin/codex'))
    require(len(native) == 1, 'provider_native_count')
    wrapper = prefix / 'codex/bin/codex.js'
    if stage == 'candidate':
        chain(RUNTIME)
        identity(BWRAP, mode=0o755)
        require(digest(BWRAP.read_bytes()) == RESOURCE_HASH, 'candidate_hash_mismatch')
    statuses = []
    reaped = [False, False]
    if stage == 'candidate':
        fixture_status_write(reaped, first=True)
    for name, provider in (('native', native[0]), ('npm', wrapper)):
        nonce = uuid.uuid4().hex
        env = os.environ.copy()
        if stage == 'candidate':
            env['PATH'] = str(RUNTIME) + os.pathsep + env['PATH']
        argv = [os.sys.executable, 'scripts/test_integrated_codex.py', '--provider-fixtures-only',
                '--session', 'codex-proof-' + nonce, '--scratch', str(Path('/tmp') / ('herdr-codex-' + nonce)),
                '--provider-path', str(provider.resolve()), '--herdr-bin', str(Path('target/debug/herdr').resolve()),
                '--diagnose-provider-runtime' if stage == 'baseline' else '--require-linux-enforcement']
        result = subprocess.run(argv, env=env, capture_output=True)
        # Existing harness emits categorical JSON. Validate the new public wrapper
        # envelope and never print a subprocess exception, stdout suffix or stderr.
        try:
            report = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise Refused('fixture_report_malformed') from None
        require(isinstance(report, dict), 'fixture_report_malformed')
        print(json.dumps({'stage': stage, 'launcher': name, 'fixture_exit': min(max(result.returncode, -1), 255),
                          'fixture_report': safe_fixture_report(report)}, sort_keys=True), flush=True)
        require(report.get('owned_cleanup') == 'PASS', 'fixture_cleanup_unverified')
        if stage == 'candidate':
            reaped[len(statuses)] = True
            fixture_status_write(reaped)
        statuses.append(result.returncode == 0)
    if stage == 'candidate':
        require(all(statuses), 'candidate_fixtures_failed')
    return {'stage': stage, 'completed': True, 'both_fixtures_passed': all(statuses),
            'baseline_lsm_attribution': 'unknown'}


FAILURE_CATEGORIES = frozenset(('fixture_status_parent_uncertain', 'fixture_status_owner')) | frozenset(('profile_parse_failed', 'profile_add_failed', 'profile_remove_failed', 'profile_download_failed', 'profile_extract_failed')) | frozenset(('attachment_collision', 'attachment_inventory_unavailable', 'attachment_inventory_uncertain', 'candidate_fixtures_failed', 'candidate_hash_mismatch', 'cleanup_archive_changed', 'cleanup_attachment_changed', 'cleanup_file_changed', 'cleanup_parent_changed', 'cleanup_paths_not_restored', 'cleanup_profile_changed', 'cleanup_profile_drift', 'cleanup_profiles_not_restored', 'cleanup_unknown_debris', 'cleanup_unowned_file', 'cleanup_unowned_profile', 'file_capability', 'fixture_cleanup_unverified', 'fixture_report_malformed', 'incompatible_restrictions', 'journal_identity_mismatch', 'journal_schema_mismatch', 'loaded_profile_drift', 'mandatory_restriction_missing', 'operation_failed', 'owned_attachment_changed', 'owned_binary_changed', 'owned_parent_changed', 'owned_path_collision', 'owned_profile_changed', 'parser_unavailable', 'preload_profile_drift', 'profile_archive_count', 'profile_collision', 'profile_customization_present', 'profile_include_unavailable', 'profile_inventory_uncertain', 'profile_member_mismatch', 'profile_package_mismatch', 'profile_source_mismatch', 'provider_identity_changed', 'provider_native_count', 'provider_package_mismatch', 'provider_path_uncertain', 'provider_resource_count', 'provider_resource_mismatch', 'restriction_drift', 'restrictions_disabled', 'setup_missing', 'unknown_restriction', 'unsafe_file_mode', 'unsafe_file_owner', 'unsafe_file_type', 'wrong_ci_target', 'wrong_fixture_user', 'wrong_target'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'apply', 'verify', 'cleanup', 'baseline', 'candidate'))
    args = parser.parse_args()
    try:
        if args.mode in ('baseline', 'candidate'):
            result = fixtures(args.mode)
        elif args.mode == 'apply':
            result = apply()
        elif args.mode == 'cleanup':
            result = cleanup()
        else:
            target(root=True)
            if STATE.exists():
                record = read_journal()
                verify_owned(record)
                result = {'plan': 'PASS_owned_no_change', 'drift': False} if args.mode == 'plan' else {'verify': 'PASS'}
            else:
                require(args.mode == 'plan', 'setup_missing')
                preflight()
                result = {'plan': 'PASS_fresh', 'changes': 'fixed_runtime_and_two_profiles',
                          'rollback': 'exact_owned_cleanup', 'resource_sha256': RESOURCE_HASH,
                          'profile_source_sha256': PROFILE_HASH}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Refused originates only at fixed literal require sites. Do not format
        # raw OS/subprocess/provider exceptions.
        category = str(error) if isinstance(error, Refused) and str(error) in FAILURE_CATEGORIES else 'experiment_gate_failed'
        print(json.dumps({'mode': args.mode, 'result': 'FAIL', 'diagnostic': category}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
