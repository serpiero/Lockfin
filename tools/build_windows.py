#!/usr/bin/env python3
"""Genera y prueba el instalador Windows desde un host Windows x86_64."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

from build_common import ROOT, OUTPUT, TOOLS, VERSION, copy_source, freeze_args, install_locked, record, run, smoke


def build():
    if sys.platform != 'win32' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('Build on Windows x86_64; cross-compilation is not supported.')
    compiler = os.getenv('ISCC') or shutil.which('ISCC.exe')
    if not compiler:
        candidate = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Inno Setup 6/ISCC.exe'
        if candidate.is_file():
            compiler = str(candidate)
    if not compiler or not Path(compiler).is_file():
        raise SystemExit('Install Inno Setup 6 or set ISCC to its compiler executable.')
    install_locked()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    run(*freeze_args('windows'))
    folder = TOOLS / 'native-windows/dist/Lockfin'
    copy_source(folder / 'source')
    smoke(folder / 'Lockfin.exe')
    run(compiler, f'/DAppVersion={VERSION}', f'/DBundleDir={folder}',
        f'/DOutputDir={OUTPUT}', f'/DLicensePath={ROOT / "LICENSE"}',
        ROOT / 'tools/windows/Lockfin.iss')
    artifact = OUTPUT / f'Lockfin-{VERSION}-Windows-Setup.exe'
    if not artifact.is_file():
        raise RuntimeError('Inno Setup did not create the expected installer.')
    # La instalacion silenciosa valida el artefacto final, no solo el directorio previo.
    with tempfile.TemporaryDirectory(prefix='lockfin-install-') as temporary:
        installed = Path(temporary) / 'Lockfin'
        run(artifact, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
            f'/DIR={installed}', timeout=120)
        smoke(installed / 'Lockfin.exe')
        run(installed / 'unins000.exe', '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', timeout=120)
    compiler_info = subprocess.run([str(compiler), '/?'], capture_output=True, text=True)
    tools = [line.strip() for line in (compiler_info.stdout + compiler_info.stderr).splitlines()
             if 'Inno Setup' in line][:2]
    record(artifact, tools, 'Unsigned; no Authenticode certificate')
    return artifact


if __name__ == '__main__':
    build()
