#!/usr/bin/env python3
"""Paquetes Python por SO, exclusivamente desde una lista publica de archivos."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import zipfile

from tools.build_common import write_checksums

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / 'dist' / 'pc'
VERSION = '0.6.9'
FILES = ['desktop.py','device_storage.py','flipper_sync.py','importers.py','vault.py','start.py','assets/lockfin.svg','assets/lockfin_10px.png','LICENSE','third_party/qflipper/NOTICE.md','third_party/qflipper/LICENSE','third_party/qflipper/GridBackground.qml','application.fam','login_manager.c','requirements-build.txt', 'third_party/pyside6/NOTICE.md', 'third_party/pyside6/licenses/LGPL-3.0-only', 'third_party/pyside6/licenses/GPL-3.0-only', 'third_party/pyside6/licenses/Qt-GPL-exception-1.0']


def filtered_runtime_lock(path):
    if not path.is_file():
        raise FileNotFoundError('Missing requirements.lock; refusing to create unlocked packages.')
    text = path.read_text()
    # Se elimina cada entrada completa, incluidos todos sus hashes y marcadores.
    blocks = re.split(r'(?m)(?=^[A-Za-z0-9][A-Za-z0-9_.-]*==)', text)
    kept = []
    for block in blocks:
        match = re.match(r'([A-Za-z0-9_.-]+)==', block)
        if match and match.group(1).lower().replace('_', '-') in {'ufbt', 'oslex', 'mslex'}:
            continue
        kept.append(block)
    filtered = ''.join(kept)
    if '--hash=sha256:' not in filtered:
        raise ValueError('requirements.lock must contain pinned SHA256 hashes.')
    return filtered.encode('utf-8')


def build():
    locked = filtered_runtime_lock(ROOT / 'requirements.lock')
    payload = {name:(ROOT/name).read_bytes() for name in FILES}
    payload['requirements.lock'] = locked
    requirements = '\n'.join(line for line in (ROOT/'requirements.txt').read_text().splitlines()
                             if line and not line.startswith('ufbt'))+'\n'
    payload['requirements.txt'] = requirements.encode()
    for icon in sorted((ROOT/'third_party/qflipper/controls').glob('*/*.svg')):
        payload[icon.relative_to(ROOT).as_posix()] = icon.read_bytes()
    for file in sorted((ROOT/'assets/fonts').iterdir()):
        if file.is_file():
            payload[file.relative_to(ROOT).as_posix()] = file.read_bytes()
    payload['Flipper/lockfin.fap'] = (ROOT/'dist/lockfin.fap').read_bytes()
    payload['Flipper/official/lockfin.fap'] = (ROOT/'dist/official/lockfin.fap').read_bytes()
    audit = os.environ.get('LOCKFIN_AUDIT_EXPORT')
    if audit:
        export = Path(audit)
        document = json.loads(export.read_text(encoding='utf-8-sig'))
        private = [(item.get('login') or {}).get('password') for item in document.get('items',[])]
        private = [s.encode() for s in private if isinstance(s,str) and len(s)>=8]
        if any(secret in data for data in payload.values() for secret in private):
            raise RuntimeError('Posible credencial en los archivos publicos; paquetes detenidos.')
    readme = (ROOT/'README.md').read_text()
    launchers = {
        'Windows': ('Iniciar.cmd', '@echo off\r\ncd /d "%~dp0"\r\nwhere py >nul 2>&1\r\nif errorlevel 1 (python start.py) else (py -3 start.py)\r\nif errorlevel 1 pause\r\n'),
        'macOS': ('Iniciar.command', '#!/bin/sh\ncd "$(dirname "$0")" || exit 1\nexec python3 start.py\n'),
        'Linux': ('Iniciar.sh', '#!/bin/sh\ncd "$(dirname "$0")" || exit 1\nexec python3 start.py\n'),
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for platform,(launcher,content) in launchers.items():
        name=f'Lockfin-{VERSION}-{platform}-Python.zip'
        target=OUTPUT/name;temp=OUTPUT/(name+'.tmp')
        items=dict(payload)
        items['LEEME.txt']=(readme+'\nSistema de este paquete: '+platform+'\n').encode()
        items[launcher]=content.encode()
        with zipfile.ZipFile(temp,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for relative,data in items.items():
                assert not any(part in {'.venv','.ufbt','.git','private','__pycache__'}
                               for part in Path(relative).parts)
                info=zipfile.ZipInfo('Lockfin/'+relative)
                info.compress_type=zipfile.ZIP_DEFLATED
                info.external_attr=((0o100755 if relative==launcher and platform!='Windows'
                                     else 0o100644)<<16)
                archive.writestr(info,data)
        os.replace(temp,target)
        with zipfile.ZipFile(target) as archive:
            assert archive.testzip() is None
            assert not any(n.lower().endswith(('.json','.lmv','.csv','.xml','.tsv'))
                           for n in archive.namelist())
        print(name, target.stat().st_size, 'bytes: contenido publico verificado')
    write_checksums()
    return OUTPUT


if __name__=='__main__':
    build()
