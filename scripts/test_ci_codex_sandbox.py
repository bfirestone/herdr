"""Offline fault tests. Linux state is simulated, never host kernel proof."""
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import ci_codex_sandbox as sandbox

PROFILE_SOURCE = b"# This profile allows almost everything and only exists to allow\n# bwrap to work on a system with user namespace restrictions\n# being enforced.\n# bwrap is allowed access to user namespaces and capabilities\n# within the user namespace, but its children do not have\n# capabilities, blocking bwrap from being able to be used to\n# arbitrarily by-pass the user namespace restrictions.\n#\n# Note: the bwrap child is stacked against the bwrap profile due to\n# bwraps use of no-new-privs\n\n# disabled by default as it can break some use cases on a system that\n# doesn't have or has disable user namespace restrictions for unconfined\n# use aa-enforce to enable it\n\nabi <abi/4.0>,\n\ninclude <tunables/global>\n\nprofile bwrap /usr/bin/bwrap flags=(attach_disconnected) {\n  allow capability,\n  # not allow all, to allow for pix stack\n  # sadly we have to allow  m every where to allow children to work under\n  # stacking.\n  allow file rwlkm /{**,},\n  allow network,\n  allow unix,\n  allow ptrace,\n  allow signal,\n  allow mqueue,\n  allow io_uring,\n  allow userns,\n  allow mount,\n  allow umount,\n  allow pivot_root,\n  allow dbus,\n  allow px /** -> bwrap//&unpriv_bwrap,\n\n  # the local include should not be used without understanding the userns\n  # restriction.\n  # Site-specific additions and overrides. See local/README for details.\n  include if exists <local/bwrap-userns-restrict>\n}\n\nprofile unpriv_bwrap flags=(attach_disconnected) {\n  # not allow all, to allow for pix stack\n  allow file rwlkm /{**,},\n  allow network,\n  allow unix,\n  allow ptrace,\n  allow signal,\n  allow mqueue,\n  allow io_uring,\n  allow userns,\n  allow mount,\n  allow umount,\n  allow pivot_root,\n  allow dbus,\n\n  allow pix /** -> &unpriv_bwrap,\n\n  audit deny capability,\n\n  # the local include should not be used without understanding the userns\n  # restriction.\n  # Site-specific additions and overrides. See local/README for details.\n  include if exists <local/unpriv_bwrap>\n}\n"


REAL_DOWNLOAD_PROFILE = sandbox.download_profile


class SimulatedLinux:
    """Real scratch files with mocked root identity and kernel/parser boundaries."""
    def __enter__(self):
        self.stack = ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.loaded = ['unrelated (enforce)']
        self.commands = []
        self.fail = None
        self.source = self.root / 'provider-bwrap'
        self.source.write_bytes(b'simulated pinned resource')
        self.source.chmod(0o755)
        self.patch = lambda name, value: self.stack.enter_context(mock.patch.object(sandbox, name, value))
        for name, relative in [('RUNTIME_PARENT', 'opt/herdr-codex-runtime'), ('RUNTIME', 'opt/herdr-codex-runtime/0.154.0'),
                               ('BWRAP', 'opt/herdr-codex-runtime/0.154.0/bwrap'), ('PROFILE', 'etc/apparmor.d/herdr-codex-bwrap-0154'),
                               ('STATE', 'run/herdr-codex-runtime-0154'), ('JOURNAL', 'run/herdr-codex-runtime-0154/journal.json')]:
            self.patch(name, self.root / relative)
        for directory in (self.root / 'opt', sandbox.PROFILE.parent, sandbox.STATE.parent):
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
        self.scalars = {'apparmor_enabled': 'Y', 'restrict_userns': '1', 'restrict_unconfined': None, 'userns_clone': '1'}
        self.patch('restrictions', lambda: dict(self.scalars))
        self.patch('profiles', lambda: sorted(self.loaded))
        self.patch('attachments', self.attachments)
        self.patch('download_profile', self.download)
        self.patch('run', self.run)
        return self

    def __exit__(self, *args):
        self.stack.close()

    def attachments(self):
        return [(value.split(' (')[0], str(sandbox.BWRAP) if value.startswith('bwrap (') else value.split(' (')[0]) for value in self.loaded]

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
                raise sandbox.Refused('profile_add_failed')
            self.loaded.extend(sandbox.OWNED_PROFILES)
        if '-R' in argv:
            name = 'unpriv_bwrap' if b'profile unpriv_bwrap ' in kwargs['data'] else 'bwrap'
            self.loaded.remove(name + ' (enforce)')
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
        for pattern in (str(sandbox.BWRAP), '/opt/**', '/{usr,opt}/**', '/**', '<unknown>', '@{VAR}/bwrap', '', '/opt/herdr-*/**'):
            self.assertTrue(sandbox.attachment_may_match(pattern), pattern)

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

    def test_profile_collision_and_ambiguous_attachment_stop_preflight(self):
        for loaded, attached in [(['bwrap (complain)'], [('bwrap', str(sandbox.BWRAP))]),
                                 (['other (enforce)'], [('other', '/opt/**')])]:
            with SimulatedLinux(), mock.patch.object(sandbox, 'profiles', return_value=loaded), mock.patch.object(
                    sandbox, 'attachments', return_value=attached) as observation:
                if loaded == ['other (enforce)']:
                    observation.return_value = [('other', str(sandbox.RUNTIME_PARENT) + '/**')]
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

    def test_parse_and_partial_add_failure_roll_back_only_added_profiles(self):
        for failure in ('-Q', 'partial_add'):
            with self.subTest(failure=failure), SimulatedLinux() as host:
                host.fail = failure
                with self.assertRaises(sandbox.Refused):
                    sandbox.apply()
                self.assertFalse(sandbox.STATE.exists())
                self.assertFalse(sandbox.PROFILE.exists())
                self.assertEqual(host.loaded, ['unrelated (enforce)'])
                removed = [kwargs['data'] for argv, kwargs in host.commands if '-R' in argv]
                self.assertEqual(len(removed), 1 if failure == 'partial_add' else 0)
                if removed:
                    self.assertNotIn(b'profile unpriv_bwrap ', removed[0])

    def test_partial_add_recovery_refuses_later_unrecorded_profile_before_any_removal(self):
        with SimulatedLinux() as host:
            host.fail = 'partial_add'
            with mock.patch.object(sandbox, 'cleanup', side_effect=sandbox.Refused('interrupted_rollback')):
                with self.assertRaises(sandbox.Refused):
                    sandbox.apply()
            record = sandbox.read_journal()
            self.assertEqual(record['loaded'], ['bwrap (enforce)'])
            self.assertIs(record['load_observed'], True)
            host.loaded.append('unpriv_bwrap (enforce)')
            with self.assertRaisesRegex(sandbox.Refused, 'cleanup_unowned_profile'):
                sandbox.cleanup()
            self.assertFalse(any('-R' in argv for argv, _ in host.commands))
            self.assertEqual(sandbox.read_journal(), record)
            self.assertTrue(sandbox.BWRAP.exists())
            self.assertTrue(sandbox.PROFILE.exists())
            # Once the independently added profile is gone, recorded ownership
            # still permits recovery of this invocation's partial addition.
            host.loaded.remove('unpriv_bwrap (enforce)')
            self.assertEqual(sandbox.cleanup()['cleanup'], 'PASS')
            removed = [kwargs['data'] for argv, kwargs in host.commands if '-R' in argv]
            self.assertEqual(len(removed), 1)
            self.assertNotIn(b'profile unpriv_bwrap ', removed[0])

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
                        observed.append((name, 'unexpected'))
                    else:
                        observed = [(key, 'unexpected' if key == name else value) for key, value in observed]
                    with mock.patch.object(sandbox, 'attachments', return_value=observed):
                        with self.assertRaisesRegex(sandbox.Refused, 'cleanup_attachment_changed'):
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


if __name__ == '__main__':
    unittest.main()
