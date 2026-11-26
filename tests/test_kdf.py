"""Compatibilidad KDF, avisos autenticados y migracion de bovedas ficticias."""
import hashlib
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import vault

ROOT = Path(__file__).resolve().parents[1]


class KdfCompatibilityTests(unittest.TestCase):
    master = "SyntheticMaster123!"
    records = [["Synthetic account", "dummy", "SyntheticPassword123!"]]

    def blob(self, rounds, favorites=False):
        payload = vault.serialize(self.records)
        if favorites:
            payload = b"\x01\x00" + payload
        salt, nonce = bytes(range(16)), bytes(range(12))
        header = vault.HEADER.pack(vault.FAVORITES_MAGIC if favorites else vault.MAGIC,
                                  rounds, salt, nonce, len(payload))
        key = hashlib.pbkdf2_hmac("sha256", self.master.encode(), salt, rounds, 32)
        return header + AESGCM(key).encrypt(nonce, payload, header)

    def test_new_vault_carries_current_cost(self):
        self.assertEqual(vault.HEADER.unpack_from(vault.seal(self.records, self.master))[1],
                         vault.ITERATIONS)

    def test_legacy_formats_open_with_migration_warning(self):
        for favorites in (False, True):
            with self.subTest(favorites=favorites), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                records = vault.unseal(self.blob(100_000, favorites), self.master)
            self.assertEqual(records, self.records)
            self.assertEqual(len(caught), 1)
            self.assertIs(caught[0].category, vault.OutdatedKDFWarning)
            self.assertIn("passwd", str(caught[0].message))
            if favorites:
                self.assertIsInstance(records[0], vault.FavoriteLogin)

    def test_current_and_maximum_cost_open_without_warning(self):
        for rounds in (600_000, 2_000_000):
            with self.subTest(rounds=rounds), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(vault.unseal(self.blob(rounds), self.master), self.records)
            self.assertEqual(caught, [])

    def test_out_of_range_cost_is_rejected_before_derivation(self):
        original = self.blob(600_000)
        for rounds in (9_999, 2_000_001):
            invalid = original[:4] + rounds.to_bytes(4, "little") + original[8:]
            with self.subTest(rounds=rounds), patch("vault.hashlib.pbkdf2_hmac") as derive:
                with self.assertRaises(vault.VaultError):
                    vault.unseal(invalid, self.master)
                derive.assert_not_called()

    def test_warning_requires_successful_authentication(self):
        original = self.blob(100_000)
        damaged = original[:-1] + bytes([original[-1] ^ 1])
        for blob, master in ((original, "WrongSyntheticMaster"), (damaged, self.master)):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                with self.assertRaises(vault.VaultError):
                    vault.unseal(blob, master)
            self.assertEqual(caught, [])

    def test_check_reports_cost_and_status(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".tools") as directory:
            path = Path(directory) / "synthetic.lmv"
            for rounds, status in ((100_000, "below current"), (600_000, "meets current cost")):
                path.write_bytes(self.blob(rounds))
                output = io.StringIO()
                with patch("sys.argv", ["vault.py", "check", str(path)]), \
                     patch("vault.ask_master", return_value=self.master), \
                     warnings.catch_warnings(record=True), redirect_stdout(output):
                    warnings.simplefilter("always")
                    vault.main()
                self.assertIn(f"KDF iterations: {rounds:,}", output.getvalue())
                self.assertIn(status, output.getvalue())

    def test_passwd_upgrades_legacy_vault_and_preserves_favorites(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".tools") as directory:
            path = Path(directory) / "synthetic.lmv"
            path.write_bytes(self.blob(100_000, favorites=True))
            new_master = "NewSyntheticMaster123!"
            with patch("sys.argv", ["vault.py", "passwd", str(path)]), \
                 patch("vault.ask_master", side_effect=[self.master, new_master]), \
                 warnings.catch_warnings(record=True), redirect_stdout(io.StringIO()):
                warnings.simplefilter("always")
                vault.main()
            updated = path.read_bytes()
            self.assertEqual(vault.HEADER.unpack_from(updated)[1], vault.ITERATIONS)
            restored = vault.unseal(updated, new_master)
            self.assertEqual(restored, self.records)
            self.assertIsInstance(restored[0], vault.FavoriteLogin)
            with self.assertRaises(vault.VaultError):
                vault.unseal(updated, self.master)
