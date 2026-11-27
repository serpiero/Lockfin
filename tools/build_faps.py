#!/usr/bin/env python3
"""Compila ambos FAP con SDKs fijados, separados del entorno de ejecucion."""
import csv
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SDKS = (
    ('momentum', '87.1', 'https://github.com/Next-Flip/Momentum-Firmware/releases/download/mntm-012/flipper-z-f7-sdk-mntm-012.zip', 'c90530c3e0aa7bc4356b8521df20d23d7b4a5435ab58a2530ffb696200408cc2'),
    ('official', '88.2', 'https://update.flipperzero.one/builds/firmware/1.5.1/flipper-z-f7-sdk-1.5.1.zip', 'dfde39df32ba8a9789b26afc1d702579ad8399a1c285770637cfe3287b2e2ffe'),
)


def build():
    if sys.platform != 'linux':
        raise SystemExit('Use the isolated Linux FAP builder, then transfer both artifacts.')
    for flavor, api, url, digest in SDKS:
        stage = ROOT / '.tools' / f'ci-fap-{flavor}'
        stage.mkdir(parents=True, exist_ok=True)
        archive = stage / 'sdk.zip'
        if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError(f'{flavor} SDK digest mismatch.')
            archive.write_bytes(data)
        env = dict(os.environ, UFBT_HOME=str(stage / 'sdk-home'))
        def ufbt(*args):
            subprocess.run([sys.executable, '-m', 'ufbt', *args], cwd=stage, env=env, check=True)
        ufbt('update', '--hw-target', 'f7', '--local', str(archive))
        symbols = stage / 'sdk-home/current/sdk_headers/f7_sdk/targets/f7/api_symbols.csv'
        rows = csv.reader(symbols.read_text().splitlines())
        if next(row[2] for row in rows if row[0] == 'Version') != api:
            raise RuntimeError(f'{flavor} SDK API mismatch.')
        for name in ('login_manager.c', 'application.fam', 'assets/lockfin_10px.png'):
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        ufbt('faps', 'STRICT_FAP_IMPORT_CHECK=yes')
        output = ROOT / 'dist' / ('official/lockfin.fap' if flavor == 'official' else 'lockfin.fap')
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(stage / 'dist/lockfin.fap', output)
        print(f'FAP_BUILD_OK: {flavor}, API {api}', flush=True)


if __name__ == '__main__':
    build()
