"""Permisos POSIX y descarte de referencias con credenciales ficticias."""
from contextlib import nullcontext
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from PySide6.QtWidgets import QApplication
import desktop
import flipper_sync
import vault


class PrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=desktop.PROJECT / '.tools')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'private'
        env = patch.dict(os.environ, {'LOCKFIN_DATA_DIR': str(self.directory)})
        env.start()
        self.addCleanup(env.stop)

    def app(self):
        app = desktop.VaultApp()
        self.addCleanup(app.root.deleteLater)
        return app

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory permission bits')
    def test_private_directory_is_private_with_permissive_umask(self):
        previous = os.umask(0o022)
        try:
            self.app()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory permission bits')
    def test_existing_private_directory_permissions_are_repaired(self):
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        self.app()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_back_locks_and_releases_records_and_master_references(self):
        app = self.app()
        app.show_candidates([['Synthetic account', 'dummy', 'SyntheticOnly123!']], 'Dummy')
        app.records = list(app.candidates)
        app.master = 'SyntheticMaster123!'
        app.mounted = SimpleNamespace(records=list(app.records))
        app.search.setText('dummy')
        app.dirty = False
        app.back()
        self.assertEqual(app.records, [])
        self.assertEqual(app.candidates, [])
        self.assertIsNone(app.master)
        self.assertIsNone(app.mounted)
        self.assertIsNone(app.original)
        self.assertEqual(app.table.rowCount(), 0)
        self.assertEqual(app.search.text(), '')
        self.assertEqual(app.source.text(), '')
        self.assertEqual(app.stack.currentIndex(), 0)

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory permission bits')
    def test_backup_directory_is_private_when_new_or_existing(self):
        self.directory.mkdir(mode=0o700)
        blob = vault.seal([['Synthetic', 'dummy', 'SyntheticOnly123!']], 'SyntheticMaster123!')
        folder = self.directory / 'device-backups'
        for existing in (False, True):
            if existing:
                folder.chmod(0o755)
            pull = flipper_sync.DevicePull(self.directory, None)
            errors = []
            pull.notice.connect(errors.append)
            with patch.object(flipper_sync.device, 'connected_device', return_value=SimpleNamespace(serial_number='dummy')), \
                 patch.object(flipper_sync.device, 'session', return_value=nullcontext(None)), \
                 patch.object(flipper_sync.device, 'command', return_value=b'dummy'), \
                 patch.object(flipper_sync.device, 'firmware_build', return_value=('Momentum 012', None)), \
                 patch.object(flipper_sync.device, 'status', return_value='file'), \
                 patch.object(flipper_sync, 'receive', return_value=blob):
                pull.run()
            self.assertEqual(errors, [])
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
            self.assertEqual(len(list(folder.glob('*.lmv'))), 1)
