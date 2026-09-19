"""Offline fault tests. Linux state is simulated, never host kernel proof."""
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import ci_codex_sandbox as sandbox

PROFILE_SOURCE = b"# This profile allows almost everything and only exists to allow\n# bwrap to work on a system with user namespace restrictions\n# being enforced.\n# bwrap is allowed access to user namespaces and capabilities\n# within the user namespace, but its children do not have\n# capabilities, blocking bwrap from being able to be used to\n# arbitrarily by-pass the user namespace restrictions.\n#\n# Note: the bwrap child is stacked against the bwrap profile due to\n# bwraps use of no-new-privs\n\n# disabled by default as it can break some use cases on a system that\n# doesn't have or has disable user namespace restrictions for unconfined\n# use aa-enforce to enable it\n\nabi <abi/4.0>,\n\ninclude <tunables/global>\n\nprofile bwrap /usr/bin/bwrap flags=(attach_disconnected) {\n  allow capability,\n  # not allow all, to allow for pix stack\n  # sadly we have to allow  m every where to allow children to work under\n  # stacking.\n  allow file rwlkm /{**,},\n  allow network,\n  allow unix,\n  allow ptrace,\n  allow signal,\n  allow mqueue,\n  allow io_uring,\n  allow userns,\n  allow mount,\n  allow umount,\n  allow pivot_root,\n  allow dbus,\n  allow px /** -> bwrap//&unpriv_bwrap,\n\n  # the local include should not be used without understanding the userns\n  # restriction.\n  # Site-specific additions and overrides. See local/README for details.\n  include if exists <local/bwrap-userns-restrict>\n}\n\nprofile unpriv_bwrap flags=(attach_disconnected) {\n  # not allow all, to allow for pix stack\n  allow file rwlkm /{**,},\n  allow network,\n  allow unix,\n  allow ptrace,\n  allow signal,\n  allow mqueue,\n  allow io_uring,\n  allow userns,\n  allow mount,\n  allow umount,\n  allow pivot_root,\n  allow dbus,\n\n  allow pix /** -> &unpriv_bwrap,\n\n  audit deny capability,\n\n  # the local include should not be used without understanding the userns\n  # restriction.\n  # Site-specific additions and overrides. See local/README for details.\n  include if exists <local/unpriv_bwrap>\n}\n"


REAL_DOWNLOAD_PROFILE = sandbox.download_profile


class SimulatedCandidateHome:
    """Real owned files; only host ancestors, /tmp and Linux target are simulated."""
    def __enter__(self):
        self.stack = ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.temp = self.root / 'rust-temp'
        self.temp.mkdir(mode=0o700)
        self.scratch = self.home / ('herdr-codex-' + 'a' * 32)
        lstat, resolve = Path.lstat, Path.resolve
        def metadata(path):
            st = lstat(path)
            if path in self.root.parents:
                return SimpleNamespace(st_dev=st.st_dev, st_ino=st.st_ino, st_uid=0,
                                       st_mode=stat.S_IFDIR | 0o755)
            return st
        def canonical(path, strict=False):
            return Path('/simulated-system-tmp') if path == Path('/tmp') else resolve(path, strict=strict)
        self.stack.enter_context(mock.patch.object(Path, 'lstat', metadata))
        self.stack.enter_context(mock.patch.object(Path, 'resolve', canonical))
        self.stack.enter_context(mock.patch.object(sandbox, 'target', return_value=os.getuid()))
        self.stack.enter_context(mock.patch.dict(os.environ, {'HOME': str(self.home), 'TMPDIR': str(self.temp)}))
        return self

    def __exit__(self, *args):
        self.stack.close()


class CandidateHomeTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(os, 'listxattr', return_value=[], create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_exact_candidate_target_rejects_before_home_lookup_or_provider(self):
        env = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'bfirestone/herdr',
               'GITHUB_REF': 'refs/heads/feat/desktop-exact-delivery'}
        with mock.patch.object(sandbox.platform, 'system', return_value='Linux') as system, mock.patch.object(
                sandbox.platform, 'machine', return_value='x86_64') as machine, mock.patch.object(
                Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID=24.04\n') as release, mock.patch.dict(
                os.environ, env, clear=True), mock.patch.object(os, 'getuid', return_value=1001) as uid, mock.patch.object(
                os, 'geteuid', return_value=1001) as euid, mock.patch.object(Path, 'home') as home, mock.patch.object(subprocess, 'run') as launch:
            self.assertEqual(sandbox.target(), 1001)
            for boundary, invalid in ((system, 'Darwin'), (machine, 'aarch64'), (release, 'ID=debian\nVERSION_ID=24.04'),
                                      (release, 'ID=ubuntu\nVERSION_ID=22.04'), (uid, 0), (euid, 0), (euid, 1002)):
                original = boundary.return_value
                boundary.return_value = invalid
                with self.assertRaises(sandbox.Refused):
                    sandbox.candidate_parent()
                boundary.return_value = original
            for key in env:
                with mock.patch.dict(os.environ, {key: 'wrong'}), self.assertRaises(sandbox.Refused):
                    sandbox.candidate_parent()
            home.assert_not_called()
            launch.assert_not_called()

    def test_inherited_home_and_rust_temp_must_be_explicit_canonical_directories(self):
        with SimulatedCandidateHome() as host:
            link = host.root / 'link'
            link.symlink_to(host.home, target_is_directory=True)
            file = host.root / 'file'
            file.write_text('unrelated')
            for key in ('HOME', 'TMPDIR'):
                for value in ('', 'relative', str(host.root / 'missing'), str(file), str(link),
                              str(host.home / '..' / 'home')):
                    with self.subTest(key=key, value=value), mock.patch.dict(os.environ, {key: value}), self.assertRaises(sandbox.Refused):
                        sandbox.candidate_parent()
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(Path, 'home') as fallback:
                with self.assertRaisesRegex(sandbox.Refused, 'candidate_home_invalid'):
                    sandbox.candidate_parent()
                fallback.assert_not_called()
            with mock.patch.dict(os.environ, {'HOME': str(host.home)}, clear=True):
                # Missing TMPDIR uses Rust's fixed /tmp, never Python TEMP/TMP.
                with mock.patch.object(sandbox, 'candidate_canonical', wraps=sandbox.candidate_canonical) as canonical:
                    with self.assertRaises(sandbox.Refused):
                        sandbox.candidate_temp_roots()  # simulated /tmp spelling is noncanonical on this host
                    canonical.assert_called_once_with('/tmp', 'candidate_temp_invalid')
            with mock.patch.object(Path, 'home', return_value=host.root), self.assertRaises(sandbox.Refused):
                sandbox.candidate_parent()
            with mock.patch.dict(os.environ, {'HOME': '/'}), self.assertRaises(sandbox.Refused):
                sandbox.candidate_parent()

    def test_temp_containment_is_component_based_and_never_changes_environment(self):
        with SimulatedCandidateHome() as host:
            before = dict(os.environ)
            home, _ = sandbox.candidate_parent()
            self.assertEqual(home, host.home)
            self.assertEqual(dict(os.environ), before)
            for temporary in (host.home, host.root):
                with mock.patch.dict(os.environ, {'TMPDIR': str(temporary)}), self.assertRaisesRegex(sandbox.Refused, 'candidate_temp_overlap'):
                    sandbox.candidate_parent()
            self.assertTrue(sandbox.candidate_outside(Path('/tmp-other/home'), (Path('/tmp'),)))
            self.assertFalse(sandbox.candidate_outside(Path('/tmp'), (Path('/tmp'),)))
            self.assertFalse(sandbox.candidate_outside(Path('/tmp/home'), (Path('/tmp'),)))

    def test_parent_owner_modes_and_ancestor_git_markers_fail_closed(self):
        with SimulatedCandidateHome() as host:
            for directory in (host.home, host.root):
                for mode in (0o777, 0o775, 0o2700, 0o4700):
                    original = Path.lstat
                    def unsafe_mode(path):
                        st = original(path)
                        return SimpleNamespace(st_dev=st.st_dev, st_ino=st.st_ino, st_uid=st.st_uid,
                                               st_mode=stat.S_IFDIR | mode) if path == directory else st
                    with mock.patch.object(Path, 'lstat', unsafe_mode), self.assertRaisesRegex(sandbox.Refused, 'candidate_home_unsafe'):
                        sandbox.candidate_parent()
                original = Path.lstat
                def wrong_owner(path):
                    st = original(path)
                    return SimpleNamespace(st_dev=st.st_dev, st_ino=st.st_ino, st_mode=st.st_mode,
                                           st_uid=os.getuid() + 123) if path == directory else st
                with mock.patch.object(Path, 'lstat', wrong_owner), self.assertRaises(sandbox.Refused):
                    sandbox.candidate_parent()
                for kind in ('file', 'directory', 'symlink'):
                    marker = directory / '.git'
                    if kind == 'file':
                        marker.write_text('must not read project configuration')
                    elif kind == 'directory':
                        marker.mkdir()
                    else:
                        marker.symlink_to(directory / 'missing')
                    with self.assertRaisesRegex(sandbox.Refused, 'candidate_project_marker'):
                        sandbox.candidate_parent()
                    marker.rmdir() if kind == 'directory' else marker.unlink()
                original = Path.lstat
                def inaccessible_marker(path):
                    if path == directory / '.git':
                        raise PermissionError('metadata unavailable')
                    return original(path)
                with mock.patch.object(Path, 'lstat', inaccessible_marker), self.assertRaisesRegex(sandbox.Refused, 'candidate_project_marker'):
                    sandbox.candidate_parent()

    def test_scratch_collision_and_creation_recheck_do_not_remove_existing_paths(self):
        with SimulatedCandidateHome() as host:
            for kind in ('file', 'directory', 'symlink'):
                if kind == 'file':
                    host.scratch.write_text('keep')
                elif kind == 'directory':
                    host.scratch.mkdir()
                else:
                    host.scratch.symlink_to(host.home / 'missing')
                with self.assertRaisesRegex(sandbox.Refused, 'owned_path_collision'):
                    sandbox.CandidateScratch(host.scratch)
                self.assertTrue(os.path.lexists(host.scratch))
                host.scratch.rmdir() if kind == 'directory' else host.scratch.unlink()
            guard = sandbox.CandidateScratch(host.scratch)
            old = host.root / 'old-home'
            host.home.rename(old)
            host.home.mkdir(mode=0o700)
            with self.assertRaisesRegex(sandbox.Refused, 'candidate_parent_changed'):
                guard.create()
            self.assertFalse(host.scratch.exists())

    def test_scratch_cleanup_requires_original_parent_child_and_modes(self):
        for drift in ('scratch_inode', 'scratch_symlink', 'scratch_mode', 'parent_inode', 'parent_mode'):
            with self.subTest(drift=drift), SimulatedCandidateHome() as host:
                guard = sandbox.CandidateScratch(host.scratch)
                guard.create()
                sentinel = host.scratch / 'keep'
                sentinel.write_text('owned')
                if drift.startswith('scratch_'):
                    if drift == 'scratch_mode':
                        host.scratch.chmod(0o750)
                    else:
                        host.scratch.rename(host.home / 'original')
                        if drift == 'scratch_inode':
                            host.scratch.mkdir(mode=0o700)
                        else:
                            host.scratch.symlink_to(host.home / 'original', target_is_directory=True)
                elif drift == 'parent_inode':
                    host.home.rename(host.root / 'original-home')
                    host.home.mkdir(mode=0o700)
                else:
                    host.home.chmod(0o750)
                with mock.patch.object(sandbox.shutil, 'rmtree') as remove, self.assertRaises(sandbox.Refused):
                    guard.remove()
                remove.assert_not_called()

    def test_success_removes_entire_owned_child_only(self):
        with SimulatedCandidateHome() as host:
            guard = sandbox.CandidateScratch(host.scratch)
            guard.create()
            for relative in ('codex-home/tmp/arg0/provider', 'sqlite/state'):
                path = host.scratch / relative
                path.parent.mkdir(parents=True)
                path.write_text('owned')
            other = host.home / 'unrelated'
            other.write_text('keep')
            guard.remove()
            self.assertFalse(host.scratch.exists())
            self.assertEqual(other.read_text(), 'keep')

    def test_provider_alias_is_observed_without_creating_or_reading_it(self):
        with SimulatedCandidateHome() as host:
            host.scratch.mkdir(mode=0o700)
            source = host.root / 'provider/codex-resources/bwrap'
            source.parent.mkdir(parents=True)
            native = source.parent.parent / 'bin/codex'
            native.parent.mkdir()
            native.write_text('pinned executable')
            native.chmod(0o755)
            directory = host.scratch / 'codex-home/tmp/arg0/codex-arg0owned'
            directory.mkdir(parents=True, mode=0o700)
            alias = directory / 'codex-linux-sandbox'
            with mock.patch.object(sandbox, 'resource', return_value=(source, b'')):
                with self.assertRaises(sandbox.Refused):
                    sandbox.candidate_alias(host.scratch)
                alias.symlink_to(native)
                with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('alias content read')), mock.patch.object(
                        subprocess, 'run', side_effect=AssertionError('provider invocation')):
                    sandbox.candidate_alias(host.scratch)
                alias.unlink()
                alias.symlink_to(host.root / 'unrelated')
                with self.assertRaises((sandbox.Refused, OSError)):
                    sandbox.candidate_alias(host.scratch)

    def test_wrapper_launches_distinct_nonce_children_and_preserves_inherited_environment(self):
        for stage in ('baseline', 'candidate'):
            with self.subTest(stage=stage), SimulatedLinux() as host, SimulatedCandidateHome() as home:
                # Model the existing pinned package layout; subprocesses are not invoked.
                source = host.root / 'prefix/codex-linux/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap'
                source.parent.mkdir(parents=True)
                native = source.parent.parent / 'bin/codex'
                native.parent.mkdir()
                native.write_text('native')
                reports = [subprocess.CompletedProcess([], 0, json.dumps({'owned_cleanup': 'PASS'})) for _ in range(2)]
                sandbox.RUNTIME.mkdir(parents=True)
                sandbox.BWRAP.write_bytes(b'pinned')
                sandbox.BWRAP.chmod(0o755)
                before = dict(os.environ)
                with mock.patch.object(sandbox, 'resource', return_value=(source, b'')), mock.patch.object(
                        sandbox, 'chain'), mock.patch.object(sandbox, 'digest', return_value=sandbox.RESOURCE_HASH), mock.patch.object(
                        sandbox, 'fixture_status_write') as record, mock.patch.object(subprocess, 'run', side_effect=reports) as launch, redirect_stdout(io.StringIO()):
                    sandbox.fixtures(stage)
                self.assertEqual(dict(os.environ), before)
                paths = []
                for call in launch.call_args_list:
                    argv, env = call.args[0], call.kwargs['env']
                    scratch = Path(argv[argv.index('--scratch') + 1])
                    session = argv[argv.index('--session') + 1]
                    self.assertEqual(scratch.name, 'herdr-codex-' + session.removeprefix('codex-proof-'))
                    self.assertEqual(scratch.parent, home.home if stage == 'candidate' else Path('/tmp'))
                    self.assertEqual(env['HOME'], before['HOME'])
                    self.assertEqual(env['TMPDIR'], before['TMPDIR'])
                    expected = dict(before)
                    if stage == 'candidate':
                        expected['PATH'] = str(sandbox.RUNTIME) + os.pathsep + expected['PATH']
                    self.assertEqual(env, expected)
                    paths.append(scratch)
                self.assertNotEqual(*paths)
                self.assertEqual(record.call_count, 3 if stage == 'candidate' else 0)

    def test_wrapper_parent_refusal_precedes_record_and_second_failure_retains_incomplete_record(self):
        with SimulatedLinux() as host:
            source = host.root / 'prefix/codex-linux/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap'
            native = source.parent.parent / 'bin/codex'
            native.parent.mkdir(parents=True)
            native.write_text('native')
            sandbox.RUNTIME.mkdir(parents=True)
            sandbox.BWRAP.write_bytes(b'pinned')
            sandbox.BWRAP.chmod(0o755)
            with mock.patch.object(sandbox, 'resource', return_value=(source, b'')), mock.patch.object(
                    sandbox, 'chain'), mock.patch.object(sandbox, 'digest', return_value=sandbox.RESOURCE_HASH), mock.patch.object(
                    sandbox, 'fixture_status_write') as record, mock.patch.object(subprocess, 'run') as launch:
                with mock.patch.object(sandbox, 'candidate_parent', side_effect=sandbox.Refused('candidate_home_invalid')):
                    with self.assertRaises(sandbox.Refused):
                        sandbox.fixtures('candidate')
                record.assert_not_called()
                launch.assert_not_called()
                with SimulatedCandidateHome():
                    snapshots = []
                    record.side_effect = lambda value, **kwargs: snapshots.append(list(value))
                    launch.side_effect = [subprocess.CompletedProcess([], 0, '{"owned_cleanup":"PASS"}'),
                                          subprocess.CompletedProcess([], 1, '{"owned_cleanup":"UNVERIFIED"}')]
                    with self.assertRaisesRegex(sandbox.Refused, 'fixture_cleanup_unverified'), redirect_stdout(io.StringIO()):
                        sandbox.fixtures('candidate')
                    self.assertEqual(snapshots, [[False, False], [True, False]])



class SimulatedLinux:
    """Real scratch files with mocked root identity and kernel/parser boundaries."""
    def __enter__(self):
        self.stack = ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.loaded = ['unrelated (enforce)']
        self.epoch = 100
        self.opaque = False
        self.hashes = {}
        self.commands = []
        self.fail = None
        self.source = self.root / 'provider-bwrap'
        self.source.write_bytes(b'simulated pinned resource')
        self.source.chmod(0o755)
        self.patch = lambda name, value: self.stack.enter_context(mock.patch.object(sandbox, name, value))
        for name, relative in [('RUNTIME_PARENT', 'var/lib/herdr-codex-runtime'), ('RUNTIME', 'var/lib/herdr-codex-runtime/0.154.0'),
                               ('BWRAP', 'var/lib/herdr-codex-runtime/0.154.0/bwrap'), ('PROFILE', 'etc/apparmor.d/herdr-codex-bwrap-0154'),
                               ('STATE', 'run/herdr-codex-runtime-0154'), ('JOURNAL', 'run/herdr-codex-runtime-0154/journal.json')]:
            self.patch(name, self.root / relative)
        for directory in (self.root / 'var/lib', sandbox.PROFILE.parent, sandbox.STATE.parent):
            directory.mkdir(parents=True)
        for relative in ('abi/4.0', 'tunables/global'):
            path = sandbox.PROFILE.parent / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('simulated include')
        parser = self.root / 'parser'
        parser.write_text('simulated parser')
        parser.chmod(0o755)
        self.patch('PARSER', str(parser))
        self.stack.enter_context(mock.patch.dict(os.environ, {'RUNNER_TEMP': str(self.root)}))
        self.patch('RESOURCE_HASH', sandbox.digest(self.source.read_bytes()))
        self.patch('resource', lambda: (self.source, self.source.read_bytes()))
        self.patch('target', lambda root=False: os.getuid())
        original_identity = sandbox.identity
        self.patch('identity', lambda path, **kwargs: original_identity(path, **dict(kwargs, root=False)))
        self.patch('no_customization', lambda: None)
        self.scalars = {'hash_policy': 'Y', 'apparmor_enabled': 'Y', 'restrict_userns': '1', 'restrict_unconfined': None, 'userns_clone': '1'}
        self.patch('restrictions', lambda: dict(self.scalars))
        self.patch('profiles', lambda: sorted(self.loaded))
        self.patch('attachments', self.attachments)
        self.patch('policy_epoch', lambda: self.epoch)
        self.patch('download_profile', self.download)
        self.patch('run', self.run)
        return self

    def __exit__(self, *args):
        self.stack.close()

    def attachments(self):
        return {value.split(' (')[0]: {'mode': value.split(' (')[1][:-1],
                'attach': ('<unknown>' if self.opaque else str(sandbox.BWRAP)) if value.startswith('bwrap (') else value.split(' (')[0],
                'sha256': self.hashes.get(value.split(' (')[0], 'a' * 64)} for value in self.loaded}

    def download(self, record):
        archive = sandbox.STATE / 'apparmor-profiles_simulated.deb'
        archive.write_bytes(b'simulated authenticated archive')
        record['files']['archive'] = {'identity': sandbox.identity(archive), 'hash': sandbox.digest(archive.read_bytes())}
        sandbox.write_journal(record)
        return PROFILE_SOURCE, archive

    def run(self, argv, **kwargs):
        self.commands.append((argv, kwargs))
        if '-a' in argv:
            if self.fail == 'partial_add':
                self.loaded.append('bwrap (enforce)')
                self.epoch += 1
                raise sandbox.Refused('profile_add_failed')
            self.loaded.extend(sandbox.OWNED_PROFILES)
            self.epoch += 2
        if '-R' in argv:
            name = 'unpriv_bwrap' if b'profile unpriv_bwrap ' in kwargs['data'] else 'bwrap'
            self.loaded.remove(name + ' (enforce)')
            self.epoch += 1
        if self.fail and self.fail in argv:
            raise sandbox.Refused('profile_parse_failed')
        return b''


class SandboxTests(unittest.TestCase):
    def setUp(self):
        # Linux xattrs are simulated even when tests run on macOS.
        self.xattrs = mock.patch.object(os, 'listxattr', return_value=[], create=True)
        self.xattrs.start()
        self.addCleanup(self.xattrs.stop)

    def test_exact_profile_digest_and_sole_attachment_substitution(self):
        self.assertEqual(sandbox.digest(PROFILE_SOURCE), sandbox.PROFILE_HASH)
        changed = sandbox.derived_profile(PROFILE_SOURCE)
        self.assertEqual(changed.replace(str(sandbox.BWRAP).encode(), b'/usr/bin/bwrap'), PROFILE_SOURCE)
        for token in (b'abi <abi/4.0>', b'allow px /** -> bwrap//&unpriv_bwrap', b'allow pix /** -> &unpriv_bwrap', b'audit deny capability'):
            self.assertIn(token, changed)
        for invalid in (PROFILE_SOURCE + b'\n', PROFILE_SOURCE.replace(b'abi/4.0', b'abi/5.0'),
                        PROFILE_SOURCE.replace(b'audit deny capability', b'allow capability')):
            with self.assertRaises(sandbox.Refused):
                sandbox.derived_profile(invalid)

    def test_attachment_overlap_is_conservative_and_disjoint_paths_are_allowed(self):
        for pattern in ('/usr/{bin,lib}/**', '/snap/**', '/opt/google/chrome/**', 'unrelated', '/usr/bin/bwrap'):
            self.assertFalse(sandbox.attachment_may_match(pattern), pattern)
        for pattern in (str(sandbox.BWRAP), '/var/**', '/{usr,var}/**', '/**', '<unknown>', '@{VAR}/bwrap', '', '/var/lib/herdr-*/**'):
            self.assertTrue(sandbox.attachment_may_match(pattern), pattern)

    def test_unsupported_brackets_refuse_preflight_even_with_disjoint_prefix(self):
        for pattern in ('/else/][', '/else/[]', '/else/[[]]', '/else/[ab]'):
            with self.subTest(pattern=pattern), SimulatedLinux() as host:
                observed = host.attachments()
                observed['unrelated']['attach'] = pattern
                with mock.patch.object(sandbox, 'attachments', return_value=observed), redirect_stdout(io.StringIO()) as output:
                    with self.assertRaisesRegex(sandbox.Refused, '^attachment_collision$'):
                        sandbox.preflight()
                summary = json.loads(output.getvalue())['preflight_metadata']
                self.assertEqual(summary['attachment_overlap'], 'known_or_possible')
                self.assertNotIn(pattern, output.getvalue())
                self.assertNotIn('unrelated', output.getvalue())
                self.assertFalse(sandbox.STATE.exists())
                self.assertFalse(sandbox.RUNTIME.exists())
                self.assertFalse(sandbox.PROFILE.exists())
                self.assertEqual(host.commands, [])

    def test_wrong_target_is_refused_before_any_mutation(self):
        with mock.patch.object(sandbox.platform, 'system', return_value='Darwin'), mock.patch.object(sandbox, 'run') as operation:
            with self.assertRaisesRegex(sandbox.Refused, 'wrong_target'):
                sandbox.apply()
            operation.assert_not_called()

    def test_target_requires_exact_branch_nonroot_fixture_and_ubuntu(self):
        env = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'bfirestone/herdr',
               'GITHUB_REF': 'refs/heads/feat/desktop-exact-delivery', 'SUDO_UID': '1001'}
        with mock.patch.object(sandbox.platform, 'system', return_value='Linux'), mock.patch.object(
                sandbox.platform, 'machine', return_value='x86_64'), mock.patch.object(
                Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"\n'), mock.patch.dict(
                os.environ, env, clear=True), mock.patch.object(os, 'geteuid', return_value=0):
            self.assertEqual(sandbox.target(root=True), 1001)
            for key, value in [('GITHUB_REF', 'refs/heads/master'), ('GITHUB_REPOSITORY', 'other/herdr'), ('CI', 'false'), ('SUDO_UID', '0')]:
                with mock.patch.dict(os.environ, {key: value}), self.assertRaises(sandbox.Refused):
                    sandbox.target(root=True)

    def test_preflight_is_read_only_and_checks_collisions(self):
        with SimulatedLinux() as host:
            record = sandbox.preflight()
            self.assertEqual(record['phase'], 'registered')
            self.assertFalse(sandbox.STATE.exists())
            self.assertEqual(host.commands, [])
            sandbox.RUNTIME.mkdir(parents=True)
            with self.assertRaisesRegex(sandbox.Refused, 'owned_path_collision'):
                sandbox.preflight()

    def test_fixed_runtime_avoids_writable_opt_and_checks_full_var_lib_chain(self):
        self.assertEqual(sandbox.BWRAP, Path('/var/lib/herdr-codex-runtime/0.154.0/bwrap'))
        real_identity = sandbox.identity
        real_lstat = Path.lstat
        with SimulatedLinux() as host:
            checked = []
            opt = host.root / 'opt'
            opt.mkdir(mode=0o777)
            opt.chmod(0o777)  # Scratch fixture only; reproduce the hosted image.
            def rooted_identity(path, **kwargs):
                checked.append(path)
                actual = real_lstat(path)
                # Model root ownership throughout the virtual Linux filesystem,
                # retaining scratch modes and exercising the real identity guard.
                mode = actual.st_mode if path.is_relative_to(host.root) else stat.S_IFDIR | 0o755
                metadata = SimpleNamespace(st_dev=actual.st_dev, st_ino=actual.st_ino,
                                           st_uid=0, st_mode=mode)
                with mock.patch.object(Path, 'lstat', return_value=metadata):
                    return real_identity(path, **kwargs)
            with mock.patch.object(sandbox, 'identity', side_effect=rooted_identity):
                with mock.patch.object(sandbox, 'RUNTIME_PARENT', opt / 'herdr-codex-runtime'):
                    with self.assertRaisesRegex(sandbox.Refused, '^preflight_runtime_parent_chain$'):
                        sandbox.preflight()
                self.assertIn(opt, checked)
                checked.clear()
                self.assertEqual(sandbox.preflight()['phase'], 'registered')
                for parent in (sandbox.RUNTIME_PARENT.parent, *sandbox.RUNTIME_PARENT.parent.parents):
                    self.assertIn(parent, checked)
                # A writable intermediate ancestor still refuses the new path.
                (host.root / 'var').chmod(0o777)
                with self.assertRaisesRegex(sandbox.Refused, '^preflight_runtime_parent_chain$'):
                    sandbox.preflight()
            self.assertEqual(stat.S_IMODE(opt.stat().st_mode), 0o777)
            self.assertFalse(sandbox.STATE.exists())
            self.assertFalse(sandbox.RUNTIME_PARENT.exists())
            self.assertEqual(host.commands, [])

    def test_preflight_guard_failures_have_fixed_redacted_categories(self):
        for guard in ('runtime_parent_chain', 'profile_parent_chain', 'state_parent_chain', 'provider_resource'):
            for error in (sandbox.Refused('unsafe_file_owner'), OSError('private-path uid=123 mode=777')):
                with self.subTest(guard=guard, error=type(error).__name__), SimulatedLinux() as host:
                    real_chain = sandbox.chain
                    paths = {'runtime_parent_chain': sandbox.RUNTIME_PARENT.parent,
                             'profile_parent_chain': sandbox.PROFILE.parent,
                             'state_parent_chain': sandbox.STATE.parent}
                    def chain(path):
                        if path == paths.get(guard):
                            raise error
                        return real_chain(path)
                    resource = mock.Mock(side_effect=error) if guard == 'provider_resource' else sandbox.resource
                    with mock.patch.object(sandbox, 'chain', side_effect=chain), mock.patch.object(
                            sandbox, 'resource', resource), mock.patch('sys.argv', ['helper', 'plan']), redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(sandbox.main(), 1)
                    self.assertEqual(json.loads(output.getvalue()),
                                     {'mode': 'plan', 'result': 'FAIL', 'diagnostic': 'preflight_' + guard})
                    self.assertFalse(sandbox.STATE.exists())
                    self.assertFalse(sandbox.RUNTIME_PARENT.exists())
                    self.assertEqual(host.commands, [])

    def test_profile_collision_and_ambiguous_attachment_stop_preflight(self):
        for loaded in (['bwrap (complain)'], ['other (enforce)']):
            with SimulatedLinux() as host:
                host.loaded = loaded
                observed = host.attachments()
                observed[next(iter(observed))]['attach'] = str(sandbox.RUNTIME_PARENT) + '/**'
                with mock.patch.object(sandbox, 'attachments', return_value=observed):
                    with self.assertRaises(sandbox.Refused):
                        sandbox.preflight()
                self.assertFalse(sandbox.STATE.exists())

    def test_apply_verify_second_preview_cleanup_and_operation_order(self):
        with SimulatedLinux() as host:
            result = sandbox.apply()
            self.assertEqual(result['apply'], 'PASS')
            record = sandbox.read_journal()
            sandbox.verify_owned(record)
            with mock.patch('sys.argv', ['helper', 'plan']), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(sandbox.main(), 0)
            self.assertIn('PASS_owned_no_change', output.getvalue())
            self.assertEqual(len(host.commands), 2)
            self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')
            self.assertEqual([command[0][1] for command in host.commands], ['-Q', '-a', '-R', '-R'])
            for argv, kwargs in host.commands:
                self.assertEqual(argv[0], sandbox.PARSER)
                self.assertIn('-T', argv)
                self.assertIn('-K', argv)
                self.assertNotIn('-r', argv)
            self.assertFalse(sandbox.RUNTIME_PARENT.exists())
            self.assertFalse(sandbox.PROFILE.exists())
            self.assertFalse(sandbox.STATE.exists())
            self.assertEqual(host.loaded, ['unrelated (enforce)'])

    def test_existing_safe_runtime_parent_is_preserved(self):
        with SimulatedLinux():
            sandbox.RUNTIME_PARENT.mkdir(mode=0o755)
            sandbox.apply()
            sandbox.cleanup()
            self.assertTrue(sandbox.RUNTIME_PARENT.is_dir())

    def test_parse_failure_restores_files_but_partial_add_retains_unknown_ownership(self):
        for failure in ('-Q', 'partial_add'):
            with self.subTest(failure=failure), SimulatedLinux() as host:
                host.fail = failure
                with self.assertRaises(sandbox.Refused):
                    sandbox.apply()
                self.assertEqual(sandbox.STATE.exists(), failure == 'partial_add')
                self.assertEqual(sandbox.PROFILE.exists(), failure == 'partial_add')
                self.assertEqual(host.loaded, ['unrelated (enforce)', 'bwrap (enforce)'] if failure == 'partial_add' else ['unrelated (enforce)'])
                self.assertFalse(any('-R' in argv for argv, _ in host.commands))

    def test_partial_add_recovery_refuses_later_unrecorded_profile_before_any_removal(self):
        with SimulatedLinux() as host:
            host.fail = 'partial_add'
            with self.assertRaises(sandbox.Refused):
                sandbox.apply()
            record = sandbox.read_journal()
            self.assertEqual(record['loaded'], [])
            self.assertIs(record['load_observed'], False)
            host.loaded.append('unpriv_bwrap (enforce)')
            for present in (True, False):
                if not present:
                    host.loaded.remove('unpriv_bwrap (enforce)')
                with self.assertRaisesRegex(sandbox.Refused, 'cleanup_unowned_profile'):
                    sandbox.cleanup()
                self.assertFalse(any('-R' in argv for argv, _ in host.commands))
                self.assertEqual(sandbox.read_journal(), record)
                self.assertTrue(sandbox.BWRAP.exists())
                self.assertTrue(sandbox.PROFILE.exists())

    def test_uncertain_load_observation_or_journal_write_retains_recovery_state(self):
        for failure in ('inventory', 'attachments', 'journal'):
            with self.subTest(failure=failure), SimulatedLinux() as host:
                read_profiles = sandbox.profiles
                read_attachments = sandbox.attachments
                write_journal = sandbox.write_journal
                def inventory():
                    if failure == 'inventory' and any('-a' in argv for argv, _ in host.commands):
                        raise OSError('simulated observation failure')
                    return read_profiles()
                def attached():
                    if failure == 'attachments' and any('-a' in argv for argv, _ in host.commands):
                        raise OSError('simulated observation failure')
                    return read_attachments()
                def journal(record):
                    if failure == 'journal' and record['load_observed']:
                        raise OSError('simulated journal failure')
                    write_journal(record)
                with mock.patch.object(sandbox, 'profiles', side_effect=inventory), mock.patch.object(
                        sandbox, 'attachments', side_effect=attached), mock.patch.object(
                        sandbox, 'write_journal', side_effect=journal):
                    with self.assertRaises((OSError, sandbox.Refused)):
                        sandbox.apply()
                record = sandbox.read_journal()
                self.assertIs(record['load_attempted'], True)
                self.assertIs(record['load_observed'], False)
                self.assertEqual(record['loaded'], [])
                for present in (True, False):
                    if not present:
                        host.loaded = ['unrelated (enforce)']
                    with self.assertRaisesRegex(sandbox.Refused, 'cleanup_unowned_profile'):
                        sandbox.cleanup()
                    self.assertEqual(sandbox.read_journal(), record)
                    self.assertTrue(sandbox.BWRAP.exists())
                    self.assertTrue(sandbox.PROFILE.exists())
                self.assertFalse(any('-R' in argv for argv, _ in host.commands))

    def test_cleanup_refuses_changed_or_duplicate_owned_attachments_before_any_removal(self):
        for name in ('bwrap', 'unpriv_bwrap'):
            for duplicate in (False, True):
                with self.subTest(name=name, duplicate=duplicate), SimulatedLinux() as host:
                    sandbox.apply()
                    observed = host.attachments()
                    if duplicate:
                        observed['parent//' + name] = dict(observed[name])
                    else:
                        observed[name]['attach'] = 'unexpected'
                    with mock.patch.object(sandbox, 'attachments', return_value=observed):
                        with self.assertRaisesRegex(sandbox.Refused, 'cleanup_attachment_changed|attachment_inventory_uncertain'):
                            sandbox.cleanup()
                    self.assertFalse(any('-R' in argv for argv, _ in host.commands))
                    self.assertTrue(sandbox.JOURNAL.exists())
                    self.assertTrue(sandbox.PROFILE.exists())
                    self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')

    def test_cleanup_refuses_tamper_and_preserves_recovery_record(self):
        for kind in ('binary', 'profile', 'restriction', 'unrelated_profile'):
            with self.subTest(kind=kind), SimulatedLinux() as host:
                sandbox.apply()
                if kind == 'binary':
                    sandbox.BWRAP.write_bytes(b'tampered')
                elif kind == 'profile':
                    sandbox.PROFILE.write_bytes(b'tampered')
                elif kind == 'restriction':
                    host.scalars['restrict_userns'] = '0'
                else:
                    host.loaded.append('unowned (enforce)')
                with self.assertRaises(sandbox.Refused):
                    sandbox.cleanup()
                self.assertTrue(sandbox.JOURNAL.exists())
                self.assertTrue(sandbox.BWRAP.exists())

    def test_unjournaled_partial_file_is_never_removed(self):
        with SimulatedLinux():
            record = sandbox.preflight()
            sandbox.STATE.mkdir(mode=0o700)
            sandbox.write_journal(record)
            sandbox.PROFILE.write_bytes(b'unknown partial file')
            with self.assertRaisesRegex(sandbox.Refused, 'cleanup_unowned_file'):
                sandbox.cleanup()
            self.assertEqual(sandbox.PROFILE.read_bytes(), b'unknown partial file')
            self.assertTrue(sandbox.JOURNAL.exists())

    def test_journal_cannot_select_arbitrary_privileged_paths(self):
        with SimulatedLinux():
            sandbox.apply()
            record = sandbox.read_journal()
            record['files']['/etc/unrelated'] = record['files']['profile']
            sandbox.write_journal(record)
            with self.assertRaisesRegex(sandbox.Refused, 'journal_schema_mismatch'):
                sandbox.cleanup()
            self.assertTrue(sandbox.PROFILE.exists())

    def test_root_ownership_symlinks_setid_and_filecaps_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'file'
            path.write_text('test')
            metadata = mock.Mock(st_mode=stat.S_IFREG | 0o4755)
            with mock.patch.object(Path, 'lstat', return_value=metadata), self.assertRaisesRegex(sandbox.Refused, 'unsafe_file_mode'):
                sandbox.identity(path, root=False)
            path.chmod(0o755)
            alias = path.with_name('alias')
            alias.symlink_to(path)
            with self.assertRaisesRegex(sandbox.Refused, 'unsafe_file_type'):
                sandbox.identity(alias, root=False)
            with mock.patch.object(os, 'listxattr', return_value=['security.capability']), self.assertRaisesRegex(sandbox.Refused, 'file_capability'):
                sandbox.identity(path, root=False)
            if os.getuid() != 0:
                with self.assertRaisesRegex(sandbox.Refused, 'unsafe_file_owner'):
                    sandbox.identity(path)

    def test_resource_requires_exact_package_identity_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {'RUNNER_TEMP': temporary}):
            package = Path(temporary).resolve() / 'herdr-codex-provider/node_modules/@openai/codex-linux-x64'
            binary = package / 'vendor/x86_64-unknown-linux-musl/codex-resources/bwrap'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'synthetic pinned executable')
            binary.chmod(0o755)
            manifest = package / 'package.json'
            manifest.write_text(json.dumps({'name': '@openai/codex', 'version': '0.154.0-linux-x64'}))
            # Prefix canonicality intentionally rejects macOS /var aliases.
            with mock.patch.dict(os.environ, {'RUNNER_TEMP': str(Path(temporary).resolve())}), mock.patch.object(
                    sandbox, 'RESOURCE_HASH', sandbox.digest(binary.read_bytes())), mock.patch.object(
                    sandbox, 'RESOURCE_SIZE', binary.stat().st_size):
                self.assertEqual(sandbox.resource()[0], binary)
                binary.write_bytes(b'tampered')
                with self.assertRaisesRegex(sandbox.Refused, 'provider_resource_mismatch'):
                    sandbox.resource()
                manifest.write_text('{"name":"other","version":"0.154.0-linux-x64"}')
                with self.assertRaisesRegex(sandbox.Refused, 'provider_package_mismatch'):
                    sandbox.resource()

    def test_candidate_failure_projection_retains_fixed_stages_and_categories(self):
        from scripts.test_integrated_codex import CANDIDATE_FAILURE_STAGES, FIXTURE_DIAGNOSTICS
        for stage in CANDIDATE_FAILURE_STAGES:
            for diagnostic in FIXTURE_DIAGNOSTICS:
                report = sandbox.safe_fixture_report({'diagnostic': diagnostic, 'candidate_failure': {
                    'stage': stage, 'diagnostic': diagnostic, 'tool_modes': {'null': True, 'pipe': False, 'pty': False}}})
                self.assertEqual(report['diagnostic'], diagnostic)
                self.assertEqual(report['candidate_failure']['stage'], stage)
                self.assertEqual(report['candidate_failure']['diagnostic'], diagnostic)
                self.assertEqual(report['candidate_failure']['tool_modes'], {'null': True, 'pipe': False, 'pty': False})

    def test_candidate_projection_rejects_private_malformed_and_oversized_fields(self):
        from scripts.test_integrated_codex import RUNTIME_SIGNATURES
        private = '/private/token'
        for value in (private, [], {}, 2 ** 64, None):
            raw = {'stage': value, 'diagnostic': value, 'tool_modes': {'null': value},
                   'command': {'presence': value, 'validity': value, 'runtime': {
                       'exit_code': value, 'outcome': value, 'stdout': {
                           'type': value, 'observed_utf8_bytes': value, 'scan_utf8_bytes': value,
                           'scan_truncated': value, 'unmatched_nonempty': value,
                           'signatures': [private] * (len(RUNTIME_SIGNATURES) + 1)}}}, 'secret': private}
            safe = sandbox.safe_fixture_report({'candidate_failure': raw, 'candidate_cleanup_failure': raw})
            self.assertTrue(safe['failure_observed'])
            for key in ('candidate_failure', 'candidate_cleanup_failure'):
                item = safe[key]
                self.assertEqual(item['stage'], 'unknown')
                self.assertEqual(item['diagnostic'], 'unclassified')
                self.assertEqual(item['tool_modes'], {'null': False, 'pipe': False, 'pty': False})
                self.assertEqual(item['command']['presence'], 'not_observed')
                self.assertEqual(item['command']['validity'], 'unknown')
                runtime = item['command']['runtime']
                self.assertIsNone(runtime['exit_code'])
                self.assertEqual(runtime['outcome'], 'malformed_result')
                self.assertIsNone(runtime['stdout']['observed_utf8_bytes'])
                self.assertIsNone(runtime['stdout']['scan_utf8_bytes'])
                self.assertEqual(runtime['stdout']['signatures'], [])
            self.assertNotIn(private, json.dumps(safe))
            self.assertLess(len(json.dumps(safe)), 4096)
        # All existing fixed signatures survive in their existing bounded shape.
        labels = [label for label, _ in RUNTIME_SIGNATURES]
        raw = {'command': {'runtime': {'exit_code': -(2 ** 31), 'outcome': 'response',
               'stderr': {'type': 'string', 'signatures': labels, 'observed_utf8_bytes': 4194305,
                          'scan_utf8_bytes': 65536, 'scan_truncated': True, 'unmatched_nonempty': False}}}}
        result = sandbox.safe_fixture_report({'candidate_failure': raw})['candidate_failure']['command']['runtime']
        self.assertEqual(result['exit_code'], -(2 ** 31))
        self.assertEqual(result['stderr']['signatures'], sorted(labels))
        self.assertEqual(result['stderr']['observed_utf8_bytes'], 4194305)
        self.assertEqual(result['stderr']['scan_utf8_bytes'], 65536)

    def test_public_report_discards_arbitrary_strings_paths_pids_and_keys(self):
        report = {'secret': '/private/secret', 'diagnostic': 'token secret', 'owned_cleanup': 'PASS',
                  'tool_fd_isolation': {'secret': True}, 'linux_enforcement': {'stacked_enforce': 'secret', 'pid': 123},
                  'runtime_diagnostics': {'original_control': {'outcome': {}, 'stdout': {'type': [],
                        'signatures': ['secret', '/private', 'bwrap_rtm_newaddr'], 'scan_utf8_bytes': -1}}}}
        rendered = json.dumps(sandbox.safe_fixture_report(report))
        self.assertNotIn('secret', rendered)
        self.assertNotIn('/private', rendered)
        self.assertNotIn('pid', rendered)
        self.assertIn('bwrap_rtm_newaddr', rendered)
        self.assertLess(len(rendered), 3000)

    def test_incomplete_fixture_reap_blocks_cleanup_before_policy_removal(self):
        with SimulatedLinux() as host:
            sandbox.apply()
            sandbox.fixture_status_write([True, False], first=True)
            with self.assertRaisesRegex(sandbox.Refused, 'fixture_cleanup_unverified'):
                sandbox.cleanup()
            self.assertFalse(any('-R' in argv for argv, _ in host.commands))
            self.assertTrue(sandbox.JOURNAL.exists())
            sandbox.fixture_status_write([True, True])
            self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')
            self.assertFalse(sandbox.fixture_status_path().exists())

    def test_download_extracts_only_authenticated_exact_package_data(self):
        import tarfile
        for valid in (True, False):
            with self.subTest(valid=valid), SimulatedLinux() as host:
                # Restore the real extraction function while retaining simulated
                # package manager/process boundaries. No apt/dpkg is run locally.
                download = REAL_DOWNLOAD_PROFILE
                record = sandbox.preflight()
                sandbox.STATE.mkdir(mode=0o700)
                sandbox.write_journal(record)
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:') as archive:
                    member = tarfile.TarInfo('./usr/share/apparmor/extra-profiles/bwrap-userns-restrict')
                    contents = PROFILE_SOURCE if valid else PROFILE_SOURCE + b'tamper'
                    member.size = len(contents)
                    archive.addfile(member, io.BytesIO(contents))
                calls = []
                def command(argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == '/usr/bin/apt-get':
                        (sandbox.STATE / 'apparmor-profiles_test.deb').write_bytes(b'archive')
                        return b''
                    if '-f' in argv:
                        return ('Package: apparmor-profiles\nVersion: ' + sandbox.PACKAGE_VERSION + '\n').encode()
                    return stream.getvalue()
                with mock.patch.object(sandbox, 'run', side_effect=command):
                    if valid:
                        self.assertEqual(download(record)[0], PROFILE_SOURCE)
                    else:
                        with self.assertRaisesRegex(sandbox.Refused, 'profile_source_mismatch'):
                            download(record)
                self.assertEqual(calls[0], ['/usr/bin/apt-get', '-o', 'APT::Get::AllowUnauthenticated=false', '-o',
                    'Acquire::AllowInsecureRepositories=false', 'download', 'apparmor-profiles=' + sandbox.PACKAGE_VERSION])
                self.assertIn('archive', sandbox.read_journal()['files'])
                self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')

    def test_main_only_emits_allowlisted_failure_categories(self):
        for error, category in [(sandbox.Refused('profile_add_failed'), 'profile_add_failed'),
                                (sandbox.Refused('private-token'), 'experiment_gate_failed'),
                                (OSError('private-token'), 'experiment_gate_failed')]:
            with mock.patch('sys.argv', ['helper', 'apply']), mock.patch.object(sandbox, 'apply', side_effect=error), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(sandbox.main(), 1)
            self.assertEqual(json.loads(output.getvalue())['diagnostic'], category)
            self.assertNotIn('private-token', output.getvalue())

    def test_epoch_is_one_bounded_nonblocking_read_and_always_closes(self):
        for data, expected in ((b'0\n', 0), (b'120\n', 120), (b'', None), (b'-1\n', None),
                               (b'1', None), (b'1\n2\n', None), (b' 1\n', None),
                               (b'9' * 31 + b'\n', None), (b'\xff\n', None)):
            with self.subTest(data=data), mock.patch.object(os, 'open', return_value=17) as opened, mock.patch.object(
                    os, 'read', return_value=data) as read, mock.patch.object(os, 'close') as close:
                if expected is None:
                    with self.assertRaisesRegex(sandbox.Refused, 'policy_revision_invalid'):
                        sandbox.policy_epoch()
                else:
                    self.assertEqual(sandbox.policy_epoch(), expected)
                opened.assert_called_once_with(sandbox.REVISION, os.O_RDONLY | os.O_NONBLOCK)
                read.assert_called_once_with(17, 32)
                close.assert_called_once_with(17)
        for error in (BlockingIOError('private'), OSError('private')):
            with mock.patch.object(os, 'open', return_value=17), mock.patch.object(os, 'read', side_effect=error) as read, mock.patch.object(os, 'close') as close:
                with self.assertRaisesRegex(sandbox.Refused, '^policy_revision_unavailable$'):
                    sandbox.policy_epoch()
                read.assert_called_once_with(17, 32)
                close.assert_called_once_with(17)
        with mock.patch.object(os, 'open', side_effect=FileNotFoundError('private')), mock.patch.object(os, 'close') as close:
            with self.assertRaisesRegex(sandbox.Refused, '^policy_revision_unavailable$'):
                sandbox.policy_epoch()
            close.assert_not_called()

    def test_real_hierarchical_inventory_reconciles_modes_names_hashes_and_bounds(self):
        def entry(parent, identifier, name, attach=None, kernel_hash='a' * 64, mode='enforce'):
            path = parent / identifier
            path.mkdir(parents=True)
            for key, value in (('name', name), ('attach', attach or name), ('mode', mode)):
                (path / key).write_text(value + '\n')
            if kernel_hash is not None:
                (path / 'sha256').write_text(kernel_hash + '\n')
            return path
        with tempfile.TemporaryDirectory() as temporary:
            policy = Path(temporary) / 'profiles'
            parent = entry(policy, 'kernel-id1', 'parent', '<unknown>', None)
            child = entry(parent / 'profiles', 'kernel-id2', 'child')
            listed = Path(temporary) / 'list'
            listed.write_text('parent (enforce)\nparent//child (enforce)\n')
            with mock.patch.object(sandbox, 'POLICY', policy), mock.patch.object(sandbox, 'PROFILE_LIST', listed), mock.patch.object(sandbox, 'policy_epoch', return_value=10):
                observed = sandbox.snapshot()
                self.assertEqual(set(observed['inventory']), {'parent', 'parent//child'})
                summary = sandbox.inventory_summary(observed)
                self.assertEqual(summary['attachment_overlap'], 'opaque_only')
                self.assertEqual(summary['sha256_support'], 'some')
                for key, invalid in (('name', 'parent//child'), ('name', 'x' * 4097), ('attach', ''),
                                     ('attach', '<unknown>\nextra'), ('sha256', ''),
                                     ('sha256', 'A' * 64), ('sha256', 'a' * 65), ('mode', 'unexpected')):
                    with self.subTest(key=key, invalid=invalid[:15]):
                        old = (child / key).read_bytes()
                        (child / key).write_text(invalid + '\n')
                        with self.assertRaises(sandbox.Refused):
                            sandbox.snapshot()
                        (child / key).write_bytes(old)
                duplicate = entry(policy, 'different-kernel-id', 'parent')
                with self.assertRaisesRegex(sandbox.Refused, 'attachment_inventory_invalid'):
                    sandbox.snapshot()
                for path in duplicate.iterdir():
                    path.unlink()
                duplicate.rmdir()
                for bound, limit in (('MAX_PROFILES', 1), ('MAX_DEPTH', 1)):
                    with mock.patch.object(sandbox, bound, limit), self.assertRaises(sandbox.Refused):
                        sandbox.snapshot()
                listed.write_text('parent (enforce)\nchild (enforce)\n')
                with self.assertRaisesRegex(sandbox.Refused, 'attachment_inventory_uncertain'):
                    sandbox.snapshot()
                (child / 'attach').unlink()
                with self.assertRaisesRegex(sandbox.Refused, 'attachment_inventory_invalid'):
                    sandbox.attachments()

    def test_opaque_baseline_is_explicit_and_known_mixed_nested_or_invalid_refuse(self):
        for case in ('opaque', 'known', 'mixed', 'nested', 'unreadable', 'epoch'):
            with self.subTest(case=case), SimulatedLinux() as host:
                observed = host.attachments()
                observed['unrelated']['attach'] = '<unknown>'
                if case in ('known', 'mixed'):
                    if case == 'known':
                        observed['unrelated']['attach'] = str(sandbox.BWRAP)
                    else:
                        host.loaded.append('private-name (enforce)')
                        observed['private-name'] = {'mode': 'enforce', 'attach': '/**', 'sha256': None}
                if case == 'nested':
                    host.loaded.append('unrelated//bwrap (enforce)')
                    observed['unrelated//bwrap'] = {'mode': 'enforce', 'attach': '<unknown>', 'sha256': None}
                with mock.patch.object(sandbox, 'attachments', side_effect=sandbox.Refused('attachment_inventory_invalid') if case == 'unreadable' else None,
                                       return_value=observed), mock.patch.object(sandbox, 'policy_epoch', side_effect=[100, 101] if case == 'epoch' else None,
                                       return_value=100), redirect_stdout(io.StringIO()) as output:
                    if case == 'opaque':
                        self.assertEqual(sandbox.preflight()['baseline'], observed)
                    else:
                        with self.assertRaises(sandbox.Refused):
                            sandbox.preflight()
                report = json.loads(output.getvalue())['preflight_metadata']
                if case in ('known', 'mixed', 'opaque'):
                    self.assertEqual(report['attachment_overlap'], {'known': 'known_or_possible', 'mixed': 'mixed', 'opaque': 'opaque_only'}[case])
                self.assertNotIn('private-name', output.getvalue())
                self.assertNotIn('<unknown>', output.getvalue())
                self.assertNotIn('a' * 64, output.getvalue())
                self.assertEqual(host.commands, [])
                self.assertFalse(sandbox.STATE.exists())
        for pattern in ('/else/@{VAR}', '/else/{broken', '/else/[broken', '/else/\\escape', '/else/{,var}'):
            self.assertTrue(sandbox.attachment_may_match(pattern))

    def test_hash_policy_is_mandatory_Y_and_never_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = {key: Path(temporary) / key for key in sandbox.SCALARS}
            values = {'hash_policy': 'Y', 'apparmor_enabled': 'Y', 'restrict_userns': '1', 'restrict_unconfined': '1', 'userns_clone': '1'}
            for key, value in values.items():
                paths[key].write_text(value + '\n')
            with mock.patch.object(sandbox, 'SCALARS', paths):
                self.assertEqual(sandbox.restrictions(), values)
                for value in ('N', 'invalid', None):
                    if value is None:
                        paths['hash_policy'].unlink()
                    else:
                        paths['hash_policy'].write_text(value + '\n')
                    with self.assertRaises(sandbox.Refused):
                        sandbox.restrictions()
                    self.assertEqual(paths['hash_policy'].read_text() if value else None, value + '\n' if value else None)

    def test_add_confirms_only_success_plus_two_and_binds_hash_and_representation(self):
        for opaque in (True, False):
            with self.subTest(opaque=opaque), SimulatedLinux() as host:
                host.opaque = opaque
                host.hashes = {'unrelated': None, 'bwrap': 'b' * 64, 'unpriv_bwrap': 'c' * 64}
                result = sandbox.apply()
                record = sandbox.read_journal()
                self.assertEqual(record['epoch'], 102)
                self.assertEqual(record['owned_metadata']['bwrap']['sha256'], 'b' * 64)
                self.assertNotEqual(record['owned_metadata']['bwrap']['sha256'], record['files']['profile']['hash'])
                self.assertEqual(result['bwrap_attachment'], 'opaque' if opaque else 'literal')
                for drift in ('hash', 'representation', 'epoch'):
                    before = dict(host.hashes), host.opaque, host.epoch
                    if drift == 'hash':
                        host.hashes['bwrap'] = 'd' * 64
                    elif drift == 'representation':
                        host.opaque = not host.opaque
                    else:
                        host.epoch += 1  # Includes same-hash replacements.
                    with self.assertRaises(sandbox.Refused):
                        sandbox.verify_owned(record)
                    with self.assertRaises(sandbox.Refused):
                        sandbox.cleanup()
                    self.assertFalse(any('-R' in argv for argv, _ in host.commands))
                    host.hashes, host.opaque, host.epoch = before
                self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')
                self.assertEqual(host.epoch, 104)

    def test_successful_parser_with_bad_hash_mode_epoch_or_baseline_never_owns(self):
        for fault in ('missing_hash', 'bad_hash', 'wrong_mode', 'delta_zero', 'delta_one', 'delta_three', 'baseline'):
            with self.subTest(fault=fault), SimulatedLinux() as host:
                real_run = host.run
                def command(argv, **kwargs):
                    result = real_run(argv, **kwargs)
                    if '-a' in argv:
                        if fault in ('missing_hash', 'bad_hash'):
                            host.hashes['bwrap'] = None if fault == 'missing_hash' else 'BAD'
                        elif fault == 'wrong_mode':
                            host.loaded.remove('bwrap (enforce)')
                            host.loaded.append('bwrap (complain)')
                        elif fault == 'baseline':
                            host.hashes['unrelated'] = 'd' * 64
                        else:
                            host.epoch = 100 + {'delta_zero': 0, 'delta_one': 1, 'delta_three': 3}[fault]
                    return result
                with mock.patch.object(sandbox, 'run', side_effect=command):
                    with self.assertRaises(sandbox.CleanupFailed) as failure:
                        sandbox.apply()
                self.assertEqual(failure.exception.cleanup_error, 'cleanup_unowned_profile')
                record = sandbox.read_journal()
                self.assertFalse(record['load_observed'])
                self.assertEqual(record['loaded'], [])
                self.assertFalse(any('-R' in argv for argv, _ in host.commands))

    def test_failed_add_with_zero_one_or_two_appearing_names_never_unloads(self):
        for count in (0, 1, 2):
            with self.subTest(count=count), SimulatedLinux() as host:
                def command(argv, **kwargs):
                    if '-a' not in argv:
                        return host.run(argv, **kwargs)
                    host.commands.append((argv, kwargs))
                    host.loaded.extend(sorted(sandbox.OWNED_PROFILES)[:count])
                    host.epoch += count
                    raise sandbox.Refused('profile_add_failed')
                with mock.patch.object(sandbox, 'run', side_effect=command), mock.patch('sys.argv', ['helper', 'apply']), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(sandbox.main(), 1)
                report = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(report['original_operation_failure'], 'profile_add_failed')
                self.assertEqual(report['cleanup_failure'], 'cleanup_unowned_profile')
                self.assertFalse(sandbox.read_journal()['load_observed'])
                with self.assertRaisesRegex(sandbox.Refused, 'cleanup_unowned_profile'):
                    sandbox.cleanup()
                self.assertFalse(any('-R' in argv for argv, _ in host.commands))
                self.assertTrue(sandbox.BWRAP.exists())

    def test_cleanup_requires_each_remove_plus_one_and_durable_checkpoint(self):
        for fault in ('no_epoch', 'extra_epoch', 'not_removed', 'remove_error', 'checkpoint_error'):
            with self.subTest(fault=fault), SimulatedLinux() as host:
                sandbox.apply()
                real_run = host.run
                real_write = sandbox.write_journal
                def command(argv, **kwargs):
                    result = real_run(argv, **kwargs)
                    if '-R' in argv:
                        if fault == 'no_epoch':
                            host.epoch -= 1
                        elif fault == 'extra_epoch':
                            host.epoch += 1
                        elif fault == 'not_removed':
                            host.loaded.append('unpriv_bwrap (enforce)')
                        elif fault == 'remove_error':
                            raise sandbox.Refused('profile_remove_failed')
                    return result
                def journal(record):
                    if fault == 'checkpoint_error' and record['epoch'] == 103:
                        raise OSError('private checkpoint error')
                    return real_write(record)
                with mock.patch.object(sandbox, 'run', side_effect=command), mock.patch.object(sandbox, 'write_journal', side_effect=journal):
                    with self.assertRaises((sandbox.Refused, OSError)):
                        sandbox.cleanup()
                self.assertEqual(sum('-R' in argv for argv, _ in host.commands), 1)
                self.assertEqual(sandbox.read_journal()['pending_removal'], 'unpriv_bwrap (enforce)')
                with self.assertRaisesRegex(sandbox.Refused, 'cleanup_removal_uncertain'):
                    sandbox.cleanup()
                self.assertEqual(sum('-R' in argv for argv, _ in host.commands), 1)
                self.assertTrue(sandbox.PROFILE.exists())

    def test_cleanup_can_resume_after_confirmed_first_removal_checkpoint(self):
        with SimulatedLinux() as host:
            sandbox.apply()
            real_verify = sandbox.verify_source
            def verify(record):
                if record['epoch'] == 103:
                    raise KeyboardInterrupt()
                real_verify(record)
            with mock.patch.object(sandbox, 'verify_source', side_effect=verify), self.assertRaises(KeyboardInterrupt):
                sandbox.cleanup()
            record = sandbox.read_journal()
            self.assertEqual(record['epoch'], 103)
            self.assertEqual(record['loaded'], ['bwrap (enforce)'])
            self.assertEqual(set(record['owned_metadata']), {'bwrap'})
            self.assertIsNone(record['pending_removal'])
            self.assertEqual(sum('-R' in argv for argv, _ in host.commands), 1)
            self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')
            self.assertEqual(sum('-R' in argv for argv, _ in host.commands), 2)
            self.assertEqual(host.epoch, 104)

    def test_journal_directory_sync_failure_after_confirming_add_cannot_authorize_cleanup(self):
        with SimulatedLinux() as host:
            fsync = os.fsync
            def sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and host.epoch == 102:
                    raise OSError('private fsync failure')
                return fsync(fd)
            with mock.patch.object(os, 'fsync', side_effect=sync), self.assertRaises(sandbox.CleanupFailed) as failure:
                sandbox.apply()
            self.assertEqual(failure.exception.cleanup_error, 'journal_write_uncertain')
            self.assertTrue((sandbox.STATE / 'journal.pending').exists())
            with self.assertRaisesRegex(sandbox.Refused, 'journal_write_uncertain'):
                sandbox.cleanup()
            self.assertFalse(any('-R' in argv for argv, _ in host.commands))
            self.assertTrue(sandbox.BWRAP.exists())

    def test_dual_failure_redaction_never_formats_private_exceptions(self):
        error = sandbox.CleanupFailed(OSError('private path uid argv'), sandbox.Refused('private raw error'))
        with mock.patch('sys.argv', ['helper', 'apply']), mock.patch.object(sandbox, 'apply', side_effect=error), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sandbox.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {'mode': 'apply', 'result': 'FAIL',
                         'diagnostic': 'experiment_gate_failed', 'original_operation_failure': 'experiment_gate_failed',
                         'cleanup_failure': 'experiment_gate_failed'})


if __name__ == '__main__':
    unittest.main()
