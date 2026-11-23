"""Pruebas sin pantalla. Todas las credenciales de estas pruebas son ficticias."""

from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

import desktop
import vault


class DesktopSaveTests(unittest.TestCase):
    def setUp(self):
        scratch = desktop.PROJECT / ".tools"
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "vault.lmv"
        self.errors = []
        self.app = desktop.VaultApp.__new__(desktop.VaultApp)
        self.app.records = [["Cuenta ficticia", "dummy", "PASSWORD_FICTICIA_123"]]
        self.app.master = "BovedaFicticia123"
        self.app.path = self.path
        self.app.original = None
        self.app.dirty = True
        self.app.status = SimpleNamespace(set=lambda _text: None)
        self.app.refresh = lambda *args, **kwargs: None
        self.app.error = lambda message, detail=None: self.errors.append(message)
        self.notifications = []
        self.app.saved = self.notifications.append

    def test_save_creates_encrypted_vault(self):
        self.assertTrue(self.app.save())
        blob = self.path.read_bytes()
        self.assertNotIn(b"PASSWORD_FICTICIA_123", blob)
        self.assertEqual(vault.unseal(blob, self.app.master), self.app.records)
        self.assertEqual(self.app.original, blob)
        self.assertFalse(self.app.dirty)
        self.assertEqual(self.notifications, [self.path])

    def test_external_change_is_not_overwritten(self):
        self.assertTrue(self.app.save())
        external = vault.seal([["Otra ficticia", "dummy2", "OTRA_FICTICIA"]], self.app.master)
        self.path.write_bytes(external)
        self.app.dirty = True
        self.assertFalse(self.app.save())
        self.assertEqual(self.path.read_bytes(), external)
        self.assertTrue(self.app.dirty)
        self.assertTrue(self.errors)

    def test_password_change_rejects_previous_key(self):
        previous_master = self.app.master
        self.assertTrue(self.app.save())
        self.app.master = "NuevaClaveFicticia123"
        self.app.dirty = True
        self.assertTrue(self.app.save())
        blob = self.path.read_bytes()
        self.assertEqual(vault.unseal(blob, self.app.master), self.app.records)
        with self.assertRaises(vault.VaultError):
            vault.unseal(blob, previous_master)

    def test_empty_vault_does_not_create_file(self):
        self.app.records = []
        self.assertFalse(self.app.save())
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
