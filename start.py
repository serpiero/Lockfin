#!/usr/bin/env python3
"""Lanzador Python 3.10+ para Windows, macOS y Linux.

python start.py          Prepara dependencias si faltan y abre la app.
python start.py --setup  Prepara el entorno local.
python start.py --check  Comprueba dependencias sin abrir ventanas.
python start.py --test   Ejecuta pruebas sin capturas.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import venv

PROJECT = Path(__file__).resolve().parent
ENVIRONMENT = PROJECT / '.venv'


def environment_python():
    return ENVIRONMENT / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')


def prepare():
    print('Preparing the application; only needed on first launch.', flush=True)
    venv.EnvBuilder(with_pip=True, symlinks=os.name != 'nt').create(ENVIRONMENT)
    subprocess.run([str(environment_python()), '-m', 'pip', '--disable-pip-version-check',
                    'install', '-r', str(PROJECT / 'requirements.txt')], cwd=PROJECT, check=True)


def has_dependencies():
    return subprocess.run([str(environment_python()), '-B', '-c',
                           'import cryptography, serial; from PySide6 import QtCore,QtWidgets'],
                          cwd=PROJECT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def desktop_environment():
    # Qt uses its own platform-specific wheels. No Tk or global library changes.
    return os.environ.copy()


def check_desktop(environment):
    result = subprocess.run([str(environment_python()), '-B', '-c',
        "import sys,desktop,cryptography; from PySide6.QtCore import qVersion; "
        "print('Python '+sys.version.split()[0]+' / Qt '+qVersion()+' / cryptography '+cryptography.__version__)"],
        cwd=PROJECT, text=True, capture_output=True, env=environment)
    if result.returncode == 0:
        print('Application ready. '+result.stdout.strip())
        return True
    print('Could not load the companion. Run: python start.py --setup', file=sys.stderr)
    if result.stderr.strip():
        print(result.stderr.strip().splitlines()[-1], file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        print('Python 3.10 or newer is required.', file=sys.stderr); return 1
    if args.setup:
        prepare()
    elif not environment_python().is_file() or not has_dependencies():
        if args.check or args.test:
            print('Set up the application: python start.py --setup', file=sys.stderr); return 1
        prepare()
    environment = desktop_environment()
    if not check_desktop(environment):
        return 1
    if args.test:
        environment['QT_QPA_PLATFORM'] = 'offscreen'
        for command in (['-B','-m','unittest','discover','-s','tests','-v'],
                        ['-B','vault.py','self-test']):
            subprocess.run([str(environment_python()),*command], cwd=PROJECT,
                           env=environment, check=True)
        return 0
    if args.check or args.setup:
        return 0
    return subprocess.run([str(environment_python()),'-B',str(PROJECT/'desktop.py')],
                          cwd=PROJECT, env=environment).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f'Could not prepare or open the application: {exc}', file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(1)
