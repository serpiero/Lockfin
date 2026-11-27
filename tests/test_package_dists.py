"""El ZIP distribuye un lock con hashes y sin las herramientas del SDK."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import package_dists


class SourcePackageLockTests(unittest.TestCase):
    def test_filtered_lock_preserves_runtime_hashes_and_removes_sdk_entries(self):
        runtime = "cryptography==50.0.2 \\n    --hash=sha256:" + "1" * 64 + "\n\n"
        # Se construyen lineas continuadas reales, no secuencias literales.
        runtime = runtime.replace("\\n", "\\" + "\n")
        sdk = "ufbt==0.2.6 \\n    --hash=sha256:" + "2" * 64 + "\n\n"
        sdk = sdk.replace("\\n", "\\" + "\n")
        sdk += "oslex==2.0.0 --hash=sha256:" + "3" * 64 + "\n"
        sdk += "mslex==1.3.0 --hash=sha256:" + "4" * 64 + "\n"
        tail = "pyserial==3.5 --hash=sha256:" + "5" * 64 + "\n"
        with tempfile.TemporaryDirectory(dir=package_dists.ROOT / ".tools") as directory:
            path = Path(directory) / "requirements.lock"
            path.write_text("--only-binary :all:\n\n" + runtime + sdk + tail)
            result = package_dists.filtered_runtime_lock(path).decode()
        self.assertIn(runtime, result)
        self.assertIn(tail, result)
        self.assertIn("--only-binary :all:", result)
        for name in ("ufbt", "oslex", "mslex"):
            self.assertNotIn(name + "==", result)
        self.assertNotIn("2" * 64, result)

    def test_missing_lock_fails_before_creating_packages(self):
        with tempfile.TemporaryDirectory(dir=package_dists.ROOT / ".tools") as directory:
            root = Path(directory)
            output = root / "dist"
            with patch.object(package_dists, "ROOT", root), \
                 patch.object(package_dists, "OUTPUT", output):
                with self.assertRaisesRegex(FileNotFoundError, "Missing requirements.lock"):
                    package_dists.build()
            self.assertFalse(output.exists())
