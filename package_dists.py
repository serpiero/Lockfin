#!/usr/bin/env python3
"""Paquetes Python por SO, exclusivamente desde una lista publica de archivos."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / 'dist' / 'pc'
VERSION = '0.6.9'
FILES = ['desktop.py','device_storage.py','flipper_sync.py','importers.py','vault.py','start.py','assets/lockfin.svg','assets/lockfin_10px.png','LICENSE','third_party/qflipper/NOTICE.md','third_party/qflipper/LICENSE','third_party/qflipper/GridBackground.qml','application.fam','login_manager.c','requirements.lock','requirements-build.txt']


def build():
    payload = {name:(ROOT/name).read_bytes() for name in FILES}
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
    checksums=[]
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
        checksums.append(hashlib.sha256(target.read_bytes()).hexdigest()+'  '+name)
        print(name, target.stat().st_size, 'bytes: contenido publico verificado')
    (OUTPUT/'SHA256SUMS').write_text('\n'.join(checksums)+'\n')
    return OUTPUT


if __name__=='__main__':
    build()
