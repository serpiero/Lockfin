"""Pull encrypted vault snapshots using the Flipper storage CLI."""
import hashlib
import re
import time

import device_storage as device
from PySide6.QtCore import QThread, Signal

import vault

READ_COMMAND = b'storage read_chunks "/ext/apps_data/lockfin/vault.lmv" 4096\r'
MAX_SIZE = vault.HEADER.size + vault.MAX_PAYLOAD + 18


def receive(port):
    # Consume CLI banners/echo up to a known prompt before reading binary data.
    port.write(b'\r')
    if not port.read_until(b'>: ', 4096).endswith(b'>: '):
        raise ValueError('USB is busy. Close qFlipper and the device app, then retry.')
    port.write(READ_COMMAND)
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        line = port.read_until(b'\r\n', 512).strip()
        if b'Storage error:' in line:
            raise ValueError('Cannot read the device vault. Check the SD card and create a vault on the Flipper.')
        match = re.fullmatch(rb'(?:Size|File size|Total size):\s*([0-9]{1,8})', line, re.I)
        if match:
            break
    else:
        raise ValueError('Flipper did not report a vault size. Close qFlipper and retry.')
    size = int(match[1])
    if not vault.HEADER.size + 17 <= size <= MAX_SIZE:
        raise ValueError('Unsupported vault size.')
    blob = bytearray()
    while len(blob) < size:
        if not port.read_until(b'Ready?\r\n', 512).endswith(b'Ready?\r\n'):
            raise ValueError('Interrupted USB transfer. Please retry.')
        port.write(b'y')
        expected = min(4096, size - len(blob))
        chunk = port.read(expected)
        if len(chunk) != expected:
            raise ValueError('Incomplete USB transfer. Please retry.')
        blob.extend(chunk)
    magic, rounds, _, _, length = vault.HEADER.unpack_from(blob)
    if (magic not in (vault.MAGIC, vault.FAVORITES_MAGIC) or not vault.MIN_ITERATIONS <= rounds <= vault.MAX_ITERATIONS
            or not 1 <= length - (2 if magic == vault.FAVORITES_MAGIC else 0) <= vault.MAX_PAYLOAD
            or len(blob) != vault.HEADER.size + length + 16):
        raise ValueError('Invalid device vault.')
    return bytes(blob)


class DevicePull(QThread):
    inspected = Signal(str, str, bool)
    received = Signal(str, str)
    notice = Signal(str)

    def __init__(self, directory, parent):
        super().__init__(parent)
        self.directory = directory

    def run(self):
        try:
            found = device.connected_device()
            if not found:
                self.notice.emit('Connect one Flipper via USB and close the device app to sync.')
                return
            inspection = None
            try:
                with device.session(found.serial_number) as port:
                    firmware, _ = device.firmware_build(device.command(port, 'device_info'))
                    app_kind = device.status(port, device.APP)
                    if app_kind == 'directory':
                        raise ValueError('A folder occupies the Lockfin app path.')
                    inspection = (found.serial_number, firmware, app_kind == 'file')
                    exists = device.status(port, device.VAULT) == 'file'
                    blob = receive(port) if exists else None
            finally:
                # A damaged vault must not suppress a valid installation result.
                # Release the serial port before presenting the installation prompt.
                if inspection:
                    self.inspected.emit(*inspection)
            if blob is None:
                self.notice.emit(f'{firmware} connected. No device vault yet.')
                return
            name = 'flipper-' + hashlib.sha256(blob).hexdigest() + '.lmv'
            folder = self.directory / 'device-backups'
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = folder / name
            try:
                vault.atomic_write(path, blob)
            except FileExistsError:
                if vault.read_blob(path) != blob:
                    raise ValueError('Backup conflict. The existing file was preserved.')
            self.received.emit(found.serial_number, str(path))
        except (OSError, ValueError) as error:
            self.notice.emit(str(error))
