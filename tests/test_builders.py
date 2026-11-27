"""Comprueba limites de empaquetado sin simular una compilacion nativa."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tools import build_common as build


class NativePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=build.ROOT / '.tools')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_missing_lock_stops_before_installing(self):
        with patch.object(build, 'ROOT', self.directory), patch.object(build, 'run') as run:
            with self.assertRaisesRegex(FileNotFoundError, 'Missing requirements.lock'):
                build.install_locked()
            run.assert_not_called()

    def test_source_copy_excludes_untracked_files(self):
        source = self.directory / 'repo'
        source.mkdir()
        (source / 'README.md').write_text('public')
        (source / 'assets').mkdir()
        (source / 'assets/icon.svg').write_text('<svg/>')
        (source / 'assets/untracked-personal.md').write_text('synthetic private')
        destination = self.directory / 'bundle'
        tracked = SimpleNamespace(stdout=b'assets/icon.svg\0')
        with patch.object(build, 'ROOT', source), \
             patch.object(build, 'PUBLIC_FILES', ('README.md',)), \
             patch.object(build, 'PUBLIC_DIRS', ('assets',)), \
             patch.object(build, 'DATA', ()), patch.object(build, 'run', return_value=tracked):
            build.copy_source(destination)
        self.assertEqual((destination / 'assets/icon.svg').read_text(), '<svg/>')
        self.assertFalse((destination / 'assets/untracked-personal.md').exists())

    def test_checksums_include_native_and_linux_artifacts_without_old_versions(self):
        names = ('Lockfin-0.6.9-Windows-Setup.exe', 'Lockfin-0.6.9-macOS-Apple-Silicon.dmg',
                 'Lockfin-0.6.9-x86_64.AppImage')
        for name in names + ('Lockfin-0.6.8-Windows-Setup.exe',):
            (self.directory / name).write_bytes(b'synthetic artifact')
        with patch.object(build, 'OUTPUT', self.directory):
            build.write_checksums()
        lines = (self.directory / 'SHA256SUMS').read_text().splitlines()
        digest = hashlib.sha256(b'synthetic artifact').hexdigest()
        self.assertEqual(set(lines), {digest + '  ' + name for name in names})

    def test_exit_zero_without_smoke_report_is_rejected(self):
        with patch.object(build, 'run'):
            with self.assertRaisesRegex(RuntimeError, 'did not produce'):
                build.smoke('synthetic-executable')

    def test_valid_smoke_report_is_required(self):
        def report(*args, **kwargs):
            Path(args[-1]).write_text(json.dumps({'version': build.VERSION, 'smoke_test': 'passed'}))
        with patch.object(build, 'run', side_effect=report):
            build.smoke('synthetic-executable')
