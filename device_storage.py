"""Lockfin installation and encrypted transfers over the Flipper USB storage CLI."""
from contextlib import contextmanager
from hashlib import md5
from pathlib import Path
import os
import re
import uuid

import serial
from serial.tools import list_ports

APP = '/ext/apps/Tools/lockfin.fap'
DATA = '/ext/apps_data/lockfin'
VAULT = DATA + '/vault.lmv'
BACKUP = VAULT + '.bak'
PROMPT = b'>: '


def connected_device():
    devices = [p for p in list_ports.comports()
               if (p.vid, p.pid) == (0x0483, 0x5740) and p.serial_number
               and p.serial_number.lower().startswith('flip_')]
    return devices[0] if len(devices) == 1 else None


def until(port, marker, limit=8192):
    data = port.read_until(marker, limit)
    if not data.endswith(marker):
        raise ValueError('USB transfer interrupted. Close qFlipper and Lockfin on the device, then retry.')
    return data[:-len(marker)]


def command(port, line):
    port.write(line.encode('ascii') + b'\r')
    # Discard command echo, including terminal editing/colour sequences.
    until(port, b'\r\n')
    data = until(port, PROMPT).strip()
    if b'Storage error:' in data:
        if b'file/dir not exist' in data.lower():
            raise FileNotFoundError('File not present on Flipper.')
        raise OSError('Flipper storage rejected the operation. Check the SD card.')
    return data


@contextmanager
def session(identity):
    device = connected_device()
    if not device or device.serial_number != identity:
        raise ValueError('Reconnect the same Flipper or save to your computer.')
    opts = {'exclusive': True} if os.name == 'posix' else {}
    with serial.Serial(device.device, 115200, timeout=3, write_timeout=3, **opts) as port:
        # Opening the Flipper VCP emits a banner and a prompt. An extra Return
        # here queues a second prompt and shifts every subsequent response.
        until(port, PROMPT)
        yield port


def status(port, path):
    try:
        data = command(port, f'storage stat "{path}"')
    except FileNotFoundError:
        return None
    if data == b'Directory':
        return 'directory'
    if re.fullmatch(rb'File, size: \d+b', data):
        return 'file'
    raise ValueError('Unexpected Flipper storage response.')


# Each key describes the SDK used to build the corresponding packaged FAP.
BUILDS = {
    ('momentum', 'mntm-012', '87', '1'): ('Momentum 012', Path('lockfin.fap')),
    ('official', '1.5.1', '88', '2'): ('Official 1.5.1', Path('official/lockfin.fap')),
}


def firmware_build(info):
    fields = {}
    for line in info.decode('utf-8', 'replace').splitlines():
        name, separator, value = line.partition(':')
        if separator:
            fields[name.strip().lower()] = value.strip()
    family = fields.get('firmware_origin_fork', '')
    version = fields.get('firmware_version', '')
    key = (family.lower(), version.lower(), fields.get('firmware_api_major'), fields.get('firmware_api_minor'))
    if fields.get('hardware_target') == '7' and fields.get('firmware_target') == '7' and key in BUILDS:
        return BUILDS[key]
    detected = ' '.join(filter(None, (family, version))) or 'unknown'
    raise ValueError(f'Unsupported firmware: {detected}. Supported: Momentum 012 and Official 1.5.1.')


def digest(port, path):
    value = command(port, f'storage md5 "{path}"')
    if not re.fullmatch(rb'[0-9a-fA-F]{32}', value):
        raise ValueError('Could not verify the file on the Flipper.')
    return value.lower()


def ensure_dir(port, path):
    kind = status(port, path)
    if kind is None:
        command(port, f'storage mkdir "{path}"')
    elif kind != 'directory':
        raise ValueError('A file is blocking the installation directory.')


def move(port, source, target):
    command(port, f'storage rename "{source}" "{target}"')


def upload(port, path, data):
    # write_chunk appends. Always upload to a new name and verify before publishing.
    temp = path + '.' + uuid.uuid4().hex[:12] + '.tmp'
    for offset in range(0, len(data), 4096):
        chunk = data[offset:offset + 4096]
        port.write(f'storage write_chunk "{temp}" {len(chunk)}\r'.encode())
        until(port, b'\r\n')
        if until(port, b'\r\n') != b'Ready':
            raise OSError('Flipper could not accept the upload.')
        if port.write(chunk) != len(chunk) or until(port, PROMPT).strip():
            raise OSError('The upload was interrupted.')
    if digest(port, temp) != md5(data).hexdigest().encode():
        raise ValueError('Upload verification failed.')
    return temp


def install(identity, expected_firmware):
    with session(identity) as port:
        firmware, relative_path = firmware_build(command(port, 'device_info'))
        if firmware != expected_firmware:
            raise ValueError('Firmware changed. Sync again before installing.')
        project = Path(__file__).resolve().parent
        root = project / 'Flipper'
        application = (root if root.is_dir() else project / 'dist') / relative_path
        data = application.read_bytes()
        ensure_dir(port, '/ext/apps_data')
        ensure_dir(port, DATA)
        if status(port, APP) == 'file':
            return
        ensure_dir(port, '/ext/apps')
        ensure_dir(port, '/ext/apps/Tools')
        move(port, upload(port, APP, data), APP)


def vault_digest(port):
    kind = status(port, VAULT)
    if kind == 'directory':
        raise ValueError('The device vault path is a directory.')
    return digest(port, VAULT) if kind else None


def save_vault(identity, blob, expected):
    if not blob.startswith((b'LMV1', b'LMV2')):
        raise ValueError('Only encrypted Lockfin vaults can be transferred.')
    with session(identity) as port:
        firmware_build(command(port, 'device_info'))
        ensure_dir(port, '/ext/apps_data')
        ensure_dir(port, DATA)
        if vault_digest(port) != expected:
            raise ValueError('The device vault changed. Check it before replacing it.')
        if status(port, BACKUP) is not None:
            raise ValueError('Open Lockfin on the Flipper to check its existing vault backup first.')
        temp = upload(port, VAULT, blob)
        if vault_digest(port) != expected:
            raise ValueError('The device vault changed during upload.')
        if expected is not None:
            move(port, VAULT, BACKUP)
            if digest(port, BACKUP) != expected:
                move(port, BACKUP, VAULT)
                raise ValueError('The device vault changed during replacement.')
        try:
            move(port, temp, VAULT)
        except (OSError, ValueError):
            if expected is not None and status(port, VAULT) is None:
                move(port, BACKUP, VAULT)
            raise
        if expected is not None:
            command(port, f'storage remove "{BACKUP}"')
