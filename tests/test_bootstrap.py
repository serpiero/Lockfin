"""La preparacion exige el lock y nunca instala dependencias sin hashes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import start


class LockedBootstrapTests(unittest.TestCase):
    def test_missing_lock_stops_before_environment_creation(self):
        with tempfile.TemporaryDirectory(dir=start.PROJECT / ".tools") as directory:
            missing = Path(directory) / "missing.lock"
            with patch.object(start, "LOCKFILE", missing), \
                 patch.object(start.venv, "EnvBuilder") as builder, \
                 patch.object(start.subprocess, "run") as install:
                with self.assertRaisesRegex(FileNotFoundError, "requirements.lock"):
                    start.prepare()
                builder.assert_not_called()
                install.assert_not_called()

    def test_setup_requires_hashes_from_the_lock(self):
        with patch.object(start.venv, "EnvBuilder") as builder, \
             patch.object(start.subprocess, "run") as install:
            start.prepare()
        builder.return_value.create.assert_called_once_with(start.ENVIRONMENT)
        command = install.call_args.args[0]
        self.assertIn("--require-hashes", command)
        self.assertEqual(command[-2:], ["-r", str(start.LOCKFILE)])
        self.assertNotIn(str(start.PROJECT / "requirements.txt"), command)
        self.assertTrue(install.call_args.kwargs["check"])
