"""Exercise installation and vault replacement without touching a real Flipper."""
import hashlib
from pathlib import Path
import unittest
from contextlib import nullcontext
from unittest.mock import patch

import device_storage as device


class DeviceTransfers(unittest.TestCase):
    def setUp(self):
        self.info = (b'hardware_target : 7\r\nfirmware_target : 7\r\nfirmware_origin_fork : Momentum\r\n'
                     b'firmware_version : mntm-012\r\nfirmware_api_major : 87\r\nfirmware_api_minor : 1\r\n')
        self.files = {}
        self.calls = []
        for name, handler in {
            'session': lambda identity: nullcontext(None),
            'command': self.command,
            'upload': self.upload,
        }.items():
            mock = patch.object(device, name, handler)
            mock.start()
            self.addCleanup(mock.stop)

    def command(self, port, line):
        import shlex
        self.calls.append(line)
        if line == 'device_info':
            return self.info
        _, op, *args = shlex.split(line)
        path = args[0]
        if op == 'mkdir':
            self.files[path] = None
            return b''
        if path not in self.files:
            raise FileNotFoundError()
        data = self.files[path]
        if op == 'stat':
            return b'Directory' if data is None else f'File, size: {len(data)}b'.encode()
        if op == 'md5':
            return hashlib.md5(data).hexdigest().encode()
        if op == 'rename':
            if args[1] in self.files:
                raise OSError('occupied')
            self.files[args[1]] = self.files.pop(path)
        elif op == 'remove':
            del self.files[path]
        else:
            self.fail(line)
        return b''

    def upload(self, port, path, data):
        self.files[path+'.tmp'] = data
        return path+'.tmp'

    def test_install_is_idempotent_and_preserves_existing_files(self):
        device.install('test', 'Momentum 012')
        root = Path(device.__file__).parent / 'dist'
        self.assertEqual(self.files[device.APP], (root / 'lockfin.fap').read_bytes())
        self.files[device.APP] = b'existing'
        device.install('test', 'Momentum 012')
        self.assertEqual(self.files[device.APP], b'existing')

    def test_official_package_and_mismatched_firmware(self):
        self.info = (b'hardware_target: 7\nfirmware_target: 7\nfirmware_origin_fork: Official\n'
                     b'firmware_version: 1.5.1\nfirmware_api_major: 88\nfirmware_api_minor: 2')
        with self.assertRaises(ValueError):
            device.install('test', 'Momentum 012')
        self.assertFalse(self.files)
        device.install('test', 'Official 1.5.1')
        self.assertEqual(self.files[device.APP], (Path(device.__file__).parent / 'dist/official/lockfin.fap').read_bytes())
        for old, new in ((b'Official', b'Other'), (b'major: 88', b'major: 87'),
                         (b'target: 7', b'target: 6'), (b'1.5.1', b'1.5.2')):
            with self.subTest(field=old), self.assertRaises(ValueError):
                device.firmware_build(self.info.replace(old, new))

    def test_replace_requires_matching_digest(self):
        device.save_vault('test', b'LMV1dummy1', None)
        with self.assertRaises(ValueError):
            device.save_vault('test', b'LMV1dummy2', None)
        old = device.vault_digest(None)
        device.save_vault('test', b'LMV1dummy2', old)
        self.assertEqual(self.files[device.VAULT], b'LMV1dummy2')
        self.assertNotIn(device.BACKUP, self.files)

    def test_occupied_backup_and_unknown_firmware(self):
        self.files[device.BACKUP] = b'valuable'
        with self.assertRaises(ValueError):
            device.save_vault('test', b'LMV1dummy', None)
        self.assertEqual(self.files[device.BACKUP], b'valuable')
        with self.assertRaises(ValueError):
            device.firmware_build(b'hardware_target : 7\r\nfirmware_version : 1.4.3')
