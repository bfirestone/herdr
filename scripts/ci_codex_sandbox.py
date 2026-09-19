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
RUNTIME_PARENT = Path('/var/lib/herdr-codex-runtime')
RUNTIME = RUNTIME_PARENT / VERSION
BWRAP = RUNTIME / 'bwrap'
PROFILE = Path('/etc/apparmor.d/herdr-codex-bwrap-0154')
STATE = Path('/run/herdr-codex-runtime-0154')
JOURNAL = STATE / 'journal.json'
PARSER = '/sbin/apparmor_parser'
PROFILE_LIST = Path('/sys/kernel/security/apparmor/profiles')
POLICY = Path('/sys/kernel/security/apparmor/policy/profiles')
REVISION = Path('/sys/kernel/security/apparmor/revision')
MAX_PROFILES = 4096
MAX_DEPTH = 64
MAX_METADATA = 4096
MODES = {'enforce', 'complain', 'kill', 'unconfined', 'user'}
SCALARS = {
    'hash_policy': Path('/sys/module/apparmor/parameters/hash_policy'),
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
            require(key not in ('apparmor_enabled', 'restrict_userns', 'hash_policy'), 'mandatory_restriction_missing')
            value = None
        require(value in ('Y', 'N') if key in ('apparmor_enabled', 'hash_policy') else value in ('0', '1', None), 'unknown_restriction')
        result[key] = value
    require(result['apparmor_enabled'] == 'Y' and result['restrict_userns'] == '1', 'restrictions_disabled')
    require(result['hash_policy'] == 'Y', 'policy_hash_disabled')
    require(result['userns_clone'] in ('1', None), 'incompatible_restrictions')
    return result


def bounded_text(path, limit, category):
    # securityfs metadata has finite content; read only one bounded chunk.
    try:
        with path.open('rb') as handle:
            data = handle.read(limit + 2)
        require(data.endswith(b'\n') and len(data) <= limit + 1, category)
        value = data[:-1].decode('utf-8')
        require(value and not any(ord(c) < 32 or ord(c) == 127 for c in value), category)
        return value
    except (OSError, UnicodeError):
        raise Refused(category) from None


def policy_epoch():
    # A read-until-EOF can wait for the NEXT policy revision. Never poll/retry.
    try:
        fd = os.open(REVISION, os.O_RDONLY | os.O_NONBLOCK)
        try:
            data = os.read(fd, 32)
        finally:
            os.close(fd)
    except OSError:
        raise Refused('policy_revision_unavailable') from None
    require(len(data) < 32 and re.fullmatch(rb'[0-9]+\n', data), 'policy_revision_invalid')
    return int(data[:-1])


def profiles():
    try:
        with PROFILE_LIST.open('rb') as handle:
            data = handle.read(MAX_PROFILES * (MAX_METADATA + 16) + 1)
        require(len(data) <= MAX_PROFILES * (MAX_METADATA + 16), 'profile_inventory_uncertain')
        values = data.decode('utf-8').splitlines()
    except (OSError, UnicodeError):
        raise Refused('profile_inventory_uncertain') from None
    require(len(values) <= MAX_PROFILES and len(values) == len(set(values)), 'profile_inventory_uncertain')
    return sorted(values)


def attachments():
    """Private hierarchical metadata; no raw values are public diagnostics."""
    require(POLICY.is_dir(), 'attachment_inventory_unavailable')
    result = {}
    def visit(parent, ancestors=()):
        with os.scandir(parent) as entries:
            for entry in entries:
                require(len(ancestors) < MAX_DEPTH, 'attachment_inventory_invalid')
                require(len(result) < MAX_PROFILES and entry.is_dir(follow_symlinks=False),
                        'attachment_inventory_invalid')
                path = Path(entry.path)
                name = bounded_text(path / 'name', MAX_METADATA, 'attachment_inventory_invalid')
                require('//' not in name and not name.startswith(':') and ' (' not in name,
                        'attachment_inventory_invalid')
                full = '//'.join((*ancestors, name))
                require(len(full.encode()) <= MAX_METADATA and full not in result, 'attachment_inventory_invalid')
                mode = bounded_text(path / 'mode', 16, 'attachment_inventory_invalid')
                require(mode in MODES, 'attachment_inventory_invalid')
                attach = bounded_text(path / 'attach', MAX_METADATA, 'attachment_inventory_invalid')
                try:
                    # Missing baseline hashes may be unknown; present malformed hashes never are.
                    with (path / 'sha256').open('rb') as handle:
                        raw_hash = handle.read(66)
                except FileNotFoundError:
                    kernel_hash = None
                else:
                    require(re.fullmatch(rb'[0-9a-f]{64}\n', raw_hash), 'policy_hash_invalid')
                    kernel_hash = raw_hash[:-1].decode('ascii')
                result[full] = {'mode': mode, 'attach': attach, 'sha256': kernel_hash}
                children = path / 'profiles'
                if children.exists():
                    require(children.is_dir() and not children.is_symlink(), 'attachment_inventory_invalid')
                    visit(children, (*ancestors, name))
    try:
        visit(POLICY)
    except OSError:
        raise Refused('attachment_inventory_unavailable') from None
    return result


def snapshot():
    before = policy_epoch()
    listed = profiles()
    inventory = attachments()
    after = policy_epoch()
    require(before == after, 'policy_revision_changed')
    require(sorted(name + ' (' + item['mode'] + ')' for name, item in inventory.items()) == listed,
            'attachment_inventory_uncertain')
    return {'epoch': after, 'inventory': inventory}


def inventory_summary(observed):
    inventory = observed['inventory']
    opaque = any(item['attach'] == '<unknown>' for item in inventory.values())
    overlaps = any(item['attach'] != '<unknown>' and attachment_may_match(item['attach'])
                   for item in inventory.values())
    owned_names = any(part in ('bwrap', 'unpriv_bwrap') for name in inventory for part in name.split('//'))
    hashes = sum(item['sha256'] is not None for item in inventory.values())
    return {'inventory': 'complete', 'owned_names': 'present' if owned_names else 'absent',
            'attachment_overlap': 'mixed' if opaque and overlaps else 'known_or_possible' if overlaps else
                                  'opaque_only' if opaque else 'none',
            'sha256_support': 'all' if hashes == len(inventory) else 'some' if hashes else 'none',
            'revision': 'stable', 'profile_count': len(inventory)}


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
    # Character classes are unsupported; reject even with a disjoint prefix.
    # Balanced counts alone do not validate ordering or class contents.
    if any(token in attachment for token in ('@', '\\', '[', ']')) or any(ord(c) < 32 or ord(c) == 127 for c in attachment):
        return True
    pending = [attachment]
    expanded = []
    while pending:
        value = pending.pop()
        match = re.search(r'\{([^{}]+)\}', value)
        if match:
            parts = match[1].split(',')
            if any(not part for part in parts) or len(parts) < 2 or len(pending) + len(expanded) + len(parts) > 128:
                return True
            pending.extend(value[:match.start()] + part + value[match.end():] for part in parts)
        else:
            expanded.append(value)
    for value in expanded:
        if '{' in value or '}' in value:
            return True
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
    for path, category in (
            (RUNTIME_PARENT if RUNTIME_PARENT.exists() else RUNTIME_PARENT.parent, 'preflight_runtime_parent_chain'),
            (PROFILE.parent, 'preflight_profile_parent_chain'),
            (STATE.parent, 'preflight_state_parent_chain')):
        try:
            chain(path)
        except (Refused, OSError):
            raise Refused(category) from None
    no_customization()
    require(Path(PARSER).is_file() and os.access(PARSER, os.X_OK), 'parser_unavailable')
    for name in ('abi/4.0', 'tunables/global'):
        require((PROFILE.parent / name).is_file(), 'profile_include_unavailable')
    try:
        source, data = resource()
        source_identity = identity(source, root=False)
    except (Refused, OSError, ValueError, KeyError):
        raise Refused('preflight_provider_resource') from None
    scalar_values = restrictions()
    try:
        observed = snapshot()
    except Refused as error:
        category = str(error)
        summary = {'inventory': 'changed' if category == 'policy_revision_changed' else
                   'unavailable' if category.endswith('_unavailable') else 'invalid',
                   'owned_names': 'unknown', 'attachment_overlap': 'invalid',
                   'sha256_support': 'invalid' if category == 'policy_hash_invalid' else 'unavailable',
                   'revision': 'changed' if category == 'policy_revision_changed' else
                   'invalid' if category == 'policy_revision_invalid' else 'unavailable'}
        print(json.dumps({'preflight_metadata': summary}, sort_keys=True), flush=True)
        raise
    summary = inventory_summary(observed)
    print(json.dumps({'preflight_metadata': summary}, sort_keys=True), flush=True)
    require(summary['owned_names'] == 'absent', 'profile_collision')
    require(summary['attachment_overlap'] in ('none', 'opaque_only'), 'attachment_collision')
    return {'schema': 2, 'uid': uid, 'restrictions': scalar_values,
            'baseline': observed['inventory'], 'epoch': observed['epoch'], 'owned_metadata': {},
            'pending_removal': None,
            'source_identity': source_identity, 'source_hash': digest(data),
            'parents': {}, 'files': {}, 'load_attempted': False, 'load_observed': False,
            'loaded': [], 'phase': 'registered'}


def write_journal(record):
    # Atomic replacement only inside our root-owned directory; never a caller path.
    chain(STATE)
    # Retain a marker across any failed commit, including rename/directory fsync.
    # Clearing it is the final syscall; a crash can conservatively retain it.
    pending = STATE / 'journal.pending'
    with pending.open('x') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.flush()
        os.fsync(handle.fileno())
    temporary = STATE / 'journal.next'
    with temporary.open('x') as handle:
        os.chmod(temporary, 0o600)
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(JOURNAL)
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    pending.unlink()


def read_journal():
    chain(STATE)
    require(not (STATE / 'journal.pending').exists() and not (STATE / 'journal.pending').is_symlink(),
            'journal_write_uncertain')
    identity(JOURNAL, mode=0o600)
    record = json.loads(JOURNAL.read_text())
    require(record.get('schema') == 2 and record.get('uid') == target(root=True), 'journal_identity_mismatch')
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


def observed_owned(record, remaining, epoch, category):
    observed = snapshot()
    require(observed['epoch'] == epoch, 'policy_revision_changed')
    expected_names = {name.split(' (', 1)[0] for name in remaining}
    inventory = observed['inventory']
    baseline = {name: item for name, item in inventory.items() if name not in expected_names}
    require(baseline == record['baseline'], category)
    owned = {name: item for name, item in inventory.items() if name in expected_names}
    require(set(owned) == expected_names, category)
    for name, item in owned.items():
        require(item['mode'] == 'enforce', category)
        require(item['sha256'] is not None and re.fullmatch(r'[0-9a-f]{64}', item['sha256']), 'owned_policy_hash_missing')
        allowed = (str(BWRAP), '<unknown>') if name == 'bwrap' else ('unpriv_bwrap',)
        require(item['attach'] in allowed, category)
    return owned


def verify_owned_files(record):
    for key, path in (('parent', RUNTIME_PARENT), ('runtime', RUNTIME)):
        if key in record['parents']:
            require(identity(path, directory=True, mode=0o755) == record['parents'][key], 'owned_parent_changed')
    for key, path, mode in (('binary', BWRAP, 0o755), ('profile', PROFILE, 0o644)):
        item = record['files'].get(key)
        if item:
            chain(path.parent)
            require(identity(path, mode=mode) == item['identity'] and digest(path.read_bytes()) == item['hash'],
                    'owned_binary_changed' if key == 'binary' else 'owned_profile_changed')
        else:
            require(not path.exists() and not path.is_symlink(), 'cleanup_unowned_file')


def verify_owned(record):
    verify_source(record)
    require(record.get('load_observed') is True and set(record['loaded']) == OWNED_PROFILES and
            record.get('pending_removal') is None, 'loaded_profile_drift')
    verify_owned_files(record)
    require(set(record['files']) >= {'binary', 'profile'}, 'loaded_profile_drift')
    owned = observed_owned(record, record['loaded'], record['epoch'], 'owned_attachment_changed')
    require(owned == record['owned_metadata'], 'owned_attachment_changed')


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
        require(snapshot() == {'epoch': record['epoch'], 'inventory': record['baseline']}, 'preload_profile_drift')
        record['load_attempted'] = True
        write_journal(record)
        run([PARSER, '-a', '-T', '-K', str(PROFILE)])
        # Appearing names after any failed/uncertain compound add are NOT owned.
        owned = observed_owned(record, OWNED_PROFILES, record['epoch'] + 2, 'owned_attachment_changed')
        record['loaded'] = sorted(OWNED_PROFILES)
        record['owned_metadata'] = owned
        record['epoch'] += 2
        record['load_observed'] = True
        write_journal(record)
        verify_owned(record)
        record['phase'] = 'applied'
        write_journal(record)
        return {'apply': 'PASS', 'resource_sha256': RESOURCE_HASH, 'profile_source_sha256': PROFILE_HASH,
                'profile_runtime_sha256': digest(profile), 'package_version': PACKAGE_VERSION,
                'owned_policy_hashes': 'confirmed', 'owned_policy_epoch': 'confirmed_plus_two',
                'bwrap_attachment': 'opaque' if owned['bwrap']['attach'] == '<unknown>' else 'literal'}
    except BaseException as original:
        # Preserve both failures, without formatting private exception text.
        try:
            cleanup()
        except BaseException as rollback_error:
            raise CleanupFailed(original, rollback_error) from None
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
    # Uncertain compound add or an uncheckpointed remove never authorizes unload.
    require(not record['load_attempted'] or record.get('load_observed') is True, 'cleanup_unowned_profile')
    require(record.get('pending_removal') is None, 'cleanup_removal_uncertain')
    verify_owned_files(record)
    added = set(record['loaded'])
    owned = observed_owned(record, added, record['epoch'], 'cleanup_attachment_changed')
    require(owned == record['owned_metadata'], 'cleanup_attachment_changed')
    if added:
        content = PROFILE.read_bytes()
        split = content.index(b'profile unpriv_bwrap ')
        for name, data in (('unpriv_bwrap (enforce)', content[:content.index(b'profile bwrap ')] + content[split:]),
                           ('bwrap (enforce)', content[:split])):
            if name in added:
                # Recheck before EACH destructive operation, then journal intent.
                verify_source(record)
                verify_owned_files(record)
                require(observed_owned(record, added, record['epoch'], 'cleanup_attachment_changed') ==
                        record['owned_metadata'], 'cleanup_attachment_changed')
                record['pending_removal'] = name
                write_journal(record)
                run([PARSER, '-R', '-T', '-K'], data=data)
                remaining = added - {name}
                expected = {key: value for key, value in record['owned_metadata'].items()
                            if key != name.split(' (', 1)[0]}
                observed = observed_owned(record, remaining, record['epoch'] + 1, 'cleanup_profiles_not_restored')
                require(observed == expected, 'cleanup_attachment_changed')
                record['loaded'] = sorted(remaining)
                record['owned_metadata'] = expected
                record['epoch'] += 1
                record['pending_removal'] = None
                write_journal(record)
                added = remaining
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
    require(snapshot() == {'epoch': record['epoch'], 'inventory': record['baseline']}, 'cleanup_profiles_not_restored')
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
    result['failure_observed'] = any(key in report for key in ('diagnostic', 'candidate_failure', 'candidate_cleanup_failure'))
    try:
        from test_integrated_codex import CANDIDATE_FAILURE_STAGES, FIXTURE_DIAGNOSTICS, RUNTIME_SIGNATURES
    except ModuleNotFoundError:
        from scripts.test_integrated_codex import CANDIDATE_FAILURE_STAGES, FIXTURE_DIAGNOSTICS, RUNTIME_SIGNATURES
    diagnostics = FIXTURE_DIAGNOSTICS
    labels = {name for name, _ in RUNTIME_SIGNATURES}
    outcomes = {'not_run', 'not_observed', 'response', 'malformed_result', 'transport_error', 'rpc_error',
                'deadline', 'bound', 'provider_exit', 'ownership_unverified'}

    def runtime(item):
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
                'signatures': sorted(labels.intersection(v for v in signatures if isinstance(v, str)))
                              if isinstance(signatures, list) and len(signatures) <= len(labels) else [],
                'scan_truncated': data.get('scan_truncated') is True,
                'unmatched_nonempty': data.get('unmatched_nonempty') is True,
            }
            for key, bound in (('observed_utf8_bytes', 4194305), ('scan_utf8_bytes', 65536)):
                value = data.get(key)
                observed[stream][key] = value if type(value) is int and 0 <= value <= bound else None
        return observed

    for key in ('candidate_failure', 'candidate_cleanup_failure'):
        if key not in report:
            continue
        detail = report[key] if isinstance(report[key], dict) else {}
        modes = detail.get('tool_modes')
        modes = modes if isinstance(modes, dict) else {}
        command = detail.get('command')
        command = command if isinstance(command, dict) else {}
        result[key] = {
            'stage': enum(detail.get('stage'), CANDIDATE_FAILURE_STAGES, 'unknown'),
            'diagnostic': enum(detail.get('diagnostic'), diagnostics, 'unclassified'),
            'tool_modes': {mode: modes.get(mode) is True for mode in ('null', 'pipe', 'pty')},
            'command': {'presence': enum(command.get('presence'), ('observed', 'not_observed'), 'not_observed'),
                        'validity': enum(command.get('validity'), ('valid', 'malformed', 'unknown'), 'unknown'),
                        'runtime': runtime(command.get('runtime'))},
        }
    if 'diagnostic' in report:
        result['diagnostic'] = enum(report['diagnostic'], diagnostics, 'unclassified')
    enforcement = report.get('linux_enforcement')
    if isinstance(enforcement, dict):
        keys = ('stacked_enforce', 'effective_caps_zero', 'permitted_caps_zero', 'no_new_privs', 'seccomp_filter',
                'python_started', 'nonroot', 'outside_write_denied', 'loopback_connect_denied',
                'parent_write_control', 'parent_connect_control', 'canary_unchanged', 'parent_listener_unreached')
        result['linux_enforcement'] = {key: enforcement.get(key) is True for key in keys}
    if 'candidate_paths' in report:
        paths = report['candidate_paths'] if isinstance(report['candidate_paths'], dict) else {}
        result['candidate_paths'] = {key: paths.get(key) is True for key in ('safe_parent', 'outside_temp', 'provider_alias')}
    detail = report.get('runtime_diagnostics')
    if isinstance(detail, dict):
        clean = {'python_started': detail.get('python_started') is True}
        for name in ('original_control', 'true', 'python_startup'):
            clean[name] = runtime(detail.get(name))
        result['runtime_diagnostics'] = clean
    environment = report.get('runtime_environment')
    if isinstance(environment, dict):
        # Only presence/boolean metadata; scalar restriction evidence is separately
        # read by the root helper and checked before/after the runtime experiment.
        keys = ('apparmor_enabled', 'system_bwrap_executable', 'bwrap_profile_file_present', 'parent_path_bwrap_is_system')
        result['runtime_environment'] = {key: environment[key] if type(environment.get(key)) is bool else None for key in keys}
    return result


# Candidate-only filesystem checks. These never repair or read inherited homes.
CANDIDATE_PATH_DIAGNOSTICS = frozenset({
    'candidate_home_invalid', 'candidate_temp_invalid', 'candidate_home_unsafe',
    'candidate_temp_overlap', 'candidate_project_marker', 'candidate_parent_changed',
    'candidate_scratch_changed', 'candidate_alias_unverified',
})


def candidate_directory(path, uid, *, scratch=False):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0, uid) and
            not st.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID), 'candidate_home_unsafe')
    if scratch:
        require(st.st_uid == uid and stat.S_IMODE(st.st_mode) == 0o700, 'candidate_scratch_changed')
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))


def candidate_canonical(value, category):
    require(isinstance(value, str) and value and Path(value).is_absolute() and
            '..' not in Path(value).parts, category)
    path = Path(value)
    try:
        require(path.resolve(strict=True) == path and path.is_dir(), category)
        for parent in (path, *path.parents):
            require(stat.S_ISDIR(parent.lstat().st_mode), category)
    except (OSError, RuntimeError):
        raise Refused(category) from None
    return path


def candidate_temp_roots():
    # Rust Unix std::env::temp_dir uses TMPDIR when present, otherwise /tmp.
    # Python tempfile has different probing/fallback and TEMP/TMP semantics.
    temporary = candidate_canonical(os.environ.get('TMPDIR', '/tmp'), 'candidate_temp_invalid')
    return (temporary, Path('/tmp').resolve(strict=True))


def candidate_outside(path, roots):
    return all(path != root and root not in path.parents for root in roots)


def candidate_parent():
    uid = target()
    home = candidate_canonical(os.environ.get('HOME'), 'candidate_home_invalid')
    require(home != Path('/') and Path.home() == home, 'candidate_home_invalid')
    roots = candidate_temp_roots()
    require(candidate_outside(home, roots), 'candidate_temp_overlap')
    parents = {}
    for parent in reversed((home, *home.parents)):
        parents[parent] = candidate_directory(parent, uid)
        # Metadata only; inaccessible markers are uncertainty, not absence.
        try:
            (parent / '.git').lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise Refused('candidate_project_marker') from None
        else:
            raise Refused('candidate_project_marker')
    require(parents[home][2] == uid, 'candidate_home_unsafe')
    return home, parents


class CandidateScratch:
    """One fresh runner-home child; retained identities guard creation/removal."""
    def __init__(self, path):
        self.home, self.parents = candidate_parent()
        self.path = path
        self.created = None
        require(path.parent == self.home and candidate_outside(path, candidate_temp_roots()),
                'candidate_temp_overlap')
        require(not os.path.lexists(path), 'owned_path_collision')

    def recheck_parent(self):
        home, parents = candidate_parent()
        require(home == self.home and parents == self.parents, 'candidate_parent_changed')

    def create(self):
        self.recheck_parent()
        self.path.mkdir(mode=0o700)
        # Capture immediately: failures after mkdir still enter caller cleanup.
        self.created = candidate_directory(self.path, os.getuid(), scratch=True)
        self.recheck_parent()

    def remove(self):
        self.recheck_parent()
        require(self.created is not None and
                candidate_directory(self.path, os.getuid(), scratch=True) == self.created,
                'candidate_scratch_changed')
        shutil.rmtree(self.path)


def candidate_alias_directory(path, uid, *, private=False):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == uid and
            not st.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID),
            'candidate_alias_unverified')
    if private:
        require(stat.S_IMODE(st.st_mode) == 0o700, 'candidate_alias_unverified')


def candidate_alias(root):
    """Metadata only, once after initialization while the provider is alive."""
    # The task-owned scratch keeps its exact mode; provider metadata has its own
    # contract and must not be reported as scratch replacement.
    uid = os.getuid()
    try:
        candidate_directory(root, uid, scratch=True)
    except (Refused, OSError):
        raise Refused('candidate_scratch_changed') from None
    source, _ = resource()
    native = source.parent.parent / 'bin/codex'
    try:
        require(native.resolve(strict=True) == native and native.is_file() and os.access(native, os.X_OK),
                'candidate_alias_unverified')
        home = root / 'codex-home'
        directory = home / 'tmp/arg0'
        require(directory.resolve(strict=True) == directory, 'candidate_alias_unverified')
        for parent in (home, home / 'tmp', directory):
            candidate_alias_directory(parent, uid, private=parent == directory)
        # One live provider at a time. Bound enumeration; never scan inherited HOME.
        with os.scandir(directory) as entries:
            children = []
            for entry in entries:
                require(len(children) < 16, 'candidate_alias_unverified')
                children.append(Path(entry.path))
        aliases = []
        for child in children:
            if child.name.startswith('codex-arg0'):
                # Codex makes arg0 private, but tempfile's child mode follows umask.
                candidate_alias_directory(child, uid)
                alias = child / 'codex-linux-sandbox'
                require(alias.is_symlink() and alias.resolve(strict=True) == native,
                        'candidate_alias_unverified')
                aliases.append(alias)
        require(len(aliases) == 1, 'candidate_alias_unverified')
    except (OSError, RuntimeError):
        raise Refused('candidate_alias_unverified') from None


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
    parent = candidate_parent()[0] if stage == 'candidate' else Path('/tmp')
    launches = []
    for name, provider in (('native', native[0]), ('npm', wrapper)):
        nonce = uuid.uuid4().hex
        scratch = parent / ('herdr-codex-' + nonce)
        if stage == 'candidate':
            CandidateScratch(scratch)
        launches.append((name, provider, nonce, scratch))
    statuses = []
    reaped = [False, False]
    if stage == 'candidate':
        fixture_status_write(reaped, first=True)
    for name, provider, nonce, scratch in launches:
        if stage == 'candidate':
            CandidateScratch(scratch)
        env = os.environ.copy()
        if stage == 'candidate':
            env['PATH'] = str(RUNTIME) + os.pathsep + env['PATH']
        argv = [os.sys.executable, 'scripts/test_integrated_codex.py', '--provider-fixtures-only',
                '--session', 'codex-proof-' + nonce, '--scratch', str(scratch),
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


FAILURE_CATEGORIES = CANDIDATE_PATH_DIAGNOSTICS | frozenset(('attachment_inventory_invalid', 'policy_hash_disabled', 'policy_hash_invalid', 'policy_revision_unavailable', 'policy_revision_invalid', 'policy_revision_changed', 'owned_policy_hash_missing', 'cleanup_removal_uncertain', 'journal_write_uncertain')) | frozenset(('preflight_runtime_parent_chain', 'preflight_profile_parent_chain', 'preflight_state_parent_chain', 'preflight_provider_resource')) | frozenset(('fixture_status_parent_uncertain', 'fixture_status_owner')) | frozenset(('profile_parse_failed', 'profile_add_failed', 'profile_remove_failed', 'profile_download_failed', 'profile_extract_failed')) | frozenset(('attachment_collision', 'attachment_inventory_unavailable', 'attachment_inventory_uncertain', 'candidate_fixtures_failed', 'candidate_hash_mismatch', 'cleanup_archive_changed', 'cleanup_attachment_changed', 'cleanup_file_changed', 'cleanup_parent_changed', 'cleanup_paths_not_restored', 'cleanup_profile_changed', 'cleanup_profile_drift', 'cleanup_profiles_not_restored', 'cleanup_unknown_debris', 'cleanup_unowned_file', 'cleanup_unowned_profile', 'file_capability', 'fixture_cleanup_unverified', 'fixture_report_malformed', 'incompatible_restrictions', 'journal_identity_mismatch', 'journal_schema_mismatch', 'loaded_profile_drift', 'mandatory_restriction_missing', 'operation_failed', 'owned_attachment_changed', 'owned_binary_changed', 'owned_parent_changed', 'owned_path_collision', 'owned_profile_changed', 'parser_unavailable', 'preload_profile_drift', 'profile_archive_count', 'profile_collision', 'profile_customization_present', 'profile_include_unavailable', 'profile_inventory_uncertain', 'profile_member_mismatch', 'profile_package_mismatch', 'profile_source_mismatch', 'provider_identity_changed', 'provider_native_count', 'provider_package_mismatch', 'provider_path_uncertain', 'provider_resource_count', 'provider_resource_mismatch', 'restriction_drift', 'restrictions_disabled', 'setup_missing', 'unknown_restriction', 'unsafe_file_mode', 'unsafe_file_owner', 'unsafe_file_type', 'wrong_ci_target', 'wrong_fixture_user', 'wrong_target'))


def failure_category(error):
    return str(error) if isinstance(error, Refused) and str(error) in FAILURE_CATEGORIES else 'experiment_gate_failed'


class CleanupFailed(Refused):
    def __init__(self, original, cleanup_error):
        self.original = failure_category(original)
        self.cleanup_error = failure_category(cleanup_error)
        super().__init__(self.original)


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
        failure = {'mode': args.mode, 'result': 'FAIL', 'diagnostic': failure_category(error)}
        if isinstance(error, CleanupFailed):
            failure['original_operation_failure'] = error.original
            failure['cleanup_failure'] = error.cleanup_error
        print(json.dumps(failure))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
