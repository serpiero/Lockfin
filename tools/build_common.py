"""Recursos publicos, bloqueo de dependencias y verificaciones de paquetes nativos."""
from importlib import metadata
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.6.9'
OUTPUT = ROOT / 'dist/pc'
TOOLS = ROOT / '.tools'
EXCLUDES = ('tkinter', 'PySide6.QtWebEngineWidgets', 'PySide6.QtWebEngineCore',
            'PySide6.Qt3DCore', 'PySide6.Qt3DRender', 'PySide6.QtCharts',
            'PySide6.QtDataVisualization', 'PySide6.QtPdf', 'PySide6.QtQuick3D',
            'PySide6.QtSql', 'PySide6.QtDesigner', 'PySide6.QtTest')
PUBLIC_FILES = ('desktop.py', 'device_storage.py', 'flipper_sync.py', 'importers.py',
                'vault.py', 'start.py', 'login_manager.c', 'application.fam',
                'build_appimage.py', 'package_dists.py', 'requirements.txt',
                'requirements.lock', 'requirements-build.txt', 'LICENSE', 'README.md',
                'SECURITY.md', 'CHANGELOG.md', '.gitignore')
PUBLIC_DIRS = ('assets', 'third_party', 'tests', 'tools', 'docs', '.github')
DATA = (('assets', 'assets'), ('third_party/qflipper', 'third_party/qflipper'),
        ('third_party/pyside6', 'third_party/pyside6'), ('LICENSE', '.'),
        ('dist/lockfin.fap', 'Flipper'), ('dist/official/lockfin.fap', 'Flipper/official'))


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True, **kwargs)


def install_locked():
    lock = ROOT / 'requirements.lock'
    if not lock.is_file():
        raise FileNotFoundError('Missing requirements.lock; refusing an unlocked native build.')
    run(sys.executable, '-m', 'pip', '--isolated', 'install', '--require-hashes',
        '--index-url', 'https://pypi.org/simple', '-r', lock)
    run(sys.executable, '-m', 'pip', 'check')


def freeze_args(flavor):
    stage = TOOLS / f'native-{flavor}'
    args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
            '--onedir', '--windowed', '--name', 'Lockfin',
            '--hidden-import', 'PySide6.QtQuick', '--hidden-import', 'PySide6.QtQml',
            '--distpath', str(stage / 'dist'), '--workpath', str(stage / 'work'),
            '--specpath', str(stage)]
    for name in EXCLUDES:
        args += ['--exclude-module', name]
    for source, destination in DATA:
        if not (ROOT / source).exists():
            raise FileNotFoundError(f'Missing public build resource: {source}')
        args += ['--add-data', f'{ROOT / source}:{destination}']
    for package in ('cryptography', 'PySide6-Essentials', 'shiboken6'):
        args += ['--copy-metadata', package]
    if flavor == 'macos':
        args += ['--osx-bundle-identifier', 'com.serpiero.lockfin']
    return args + [str(ROOT / 'desktop.py')]


def copy_source(destination):
    # Lista publica explicita; no se recorre el repo ni se incluyen datos locales.
    destination.mkdir(parents=True, exist_ok=True)
    for name in PUBLIC_FILES:
        shutil.copy2(ROOT / name, destination / name)
    result = run('git', 'ls-files', '-z', '--', *PUBLIC_DIRS, capture_output=True)
    for encoded in result.stdout.split(b'\0'):
        if not encoded:
            continue
        name = Path(os.fsdecode(encoded))
        if name.suffix.lower() in ('.lmv', '.key', '.pem', '.pfx') or '.lmv.' in name.name:
            raise RuntimeError('Private file in the tracked source allowlist; packaging stopped.')
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    for source, target in DATA[-2:]:
        path = destination / target
        path.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, path / 'lockfin.fap')
    assert not any(destination.rglob('*.lmv'))


def smoke(executable):
    # Un informe persistente permite verificar tambien ejecutables sin consola.
    with tempfile.TemporaryDirectory(prefix='lockfin-native-smoke-') as temp:
        report = Path(temp) / 'smoke.json'
        env = dict(os.environ, QT_QPA_PLATFORM='offscreen',
                   LOCKFIN_DATA_DIR=str(Path(temp) / 'vaults'))
        run(executable, '--smoke-test', '--smoke-test-report', report, env=env, timeout=90)
        if not report.is_file():
            raise RuntimeError('Native executable did not produce its smoke-test report.')
        result = json.loads(report.read_text())
        if result != {'version': VERSION, 'smoke_test': 'passed'}:
            raise RuntimeError('Native smoke-test report is invalid.')
    print(f'NATIVE_SMOKE_OK: {Path(executable).name}', flush=True)


def write_checksums():
    # Incluye solo artefactos de esta version y conserva todos sus formatos.
    targets = sorted(p for p in OUTPUT.glob(f'Lockfin-{VERSION}-*') if p.is_file()
                     and p.name.endswith(('.AppImage', '.exe', '.dmg', '.zip')))
    content = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                      for p in targets)
    temporary = OUTPUT / 'SHA256SUMS.tmp'
    temporary.write_text(content)
    temporary.replace(OUTPUT / 'SHA256SUMS')


def record(artifact, tools, signing):
    packages = ('cryptography', 'pyserial', 'PySide6-Essentials', 'shiboken6', 'PyInstaller')
    result = run('git', 'rev-parse', 'HEAD', capture_output=True, text=True)
    lines = [f'Build host: {platform.platform()}', f'Architecture: {platform.machine()}',
             f'Python: {platform.python_version()}', f'Source commit: {result.stdout.strip()}',
             'Runtime lock SHA256: ' + hashlib.sha256((ROOT / 'requirements.lock').read_bytes()).hexdigest(),
             f'Signing: {signing}', 'Native smoke test: passed']
    lines += [f'{name}: {metadata.version(name)}' for name in packages]
    lines += tools
    lines += [f'Artifact SHA256: {hashlib.sha256(artifact.read_bytes()).hexdigest()}']
    artifact.with_name(artifact.name + '.runtime.txt').write_text('\n'.join(lines) + '\n')
    write_checksums()
    print(f'NATIVE_BUILD_OK: {artifact.name} ({artifact.stat().st_size} bytes)', flush=True)
