#!/usr/bin/env python3
"""Build a native Linux AppImage from explicitly selected public resources."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent
VERSION = '0.6.9'
TOOLS = ROOT / '.tools'


def run(*args, **kwargs):
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def build():
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise SystemExit('Build on x86_64 Linux with PyInstaller and squashfs-tools installed.')
    if not shutil.which('mksquashfs'):
        raise SystemExit('squashfs-tools is required.')
    TOOLS.mkdir(exist_ok=True)
    lock = ROOT / 'requirements.lock'
    if not lock.is_file():
        raise SystemExit('Missing requirements.lock; refusing an unlocked build.')
    run(sys.executable, '-m', 'pip', '--isolated', '--cache-dir', str(TOOLS / 'pip-cache'),
        'install', '--index-url', 'https://pypi.org/simple', '--require-hashes', '-r', str(lock))
    run(sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
        '--onedir', '--windowed', '--name', 'Lockfin',
        '--distpath', str(TOOLS / 'pyinstaller-dist'),
        '--workpath', str(TOOLS / 'pyinstaller-build'), '--specpath', str(TOOLS),
        '--add-data', f'{ROOT / "assets/fonts"}:assets/fonts',
        '--add-data', f'{ROOT / "assets/lockfin.svg"}:assets',
        '--add-data', f'{ROOT / "third_party/qflipper"}:third_party/qflipper',
        '--add-data', f'{ROOT / "LICENSE"}:.',
        '--add-data', f'{ROOT / "dist/lockfin.fap"}:Flipper',
        '--add-data', f'{ROOT / "dist/official/lockfin.fap"}:Flipper/official',
        '--copy-metadata', 'cryptography', '--copy-metadata', 'PySide6-Essentials',
        '--copy-metadata', 'shiboken6', str(ROOT / 'desktop.py'))

    appdir = TOOLS / 'Lockfin.AppDir'
    if appdir.exists():
        shutil.rmtree(appdir)
    shutil.copytree(TOOLS / 'pyinstaller-dist/Lockfin', appdir / 'usr/bin')
    apprun = appdir / 'AppRun'
    apprun.write_text('#!/bin/sh\n'
                      'APPDIR="${APPDIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"\n'
                      'unset QT_PLUGIN_PATH QT_QPA_PLATFORM_PLUGIN_PATH\n'
                      'exec "$APPDIR/usr/bin/Lockfin" "$@"\n')
    apprun.chmod(0o755)
    (appdir / 'lockfin.desktop').write_text(
        '[Desktop Entry]\nType=Application\nName=Lockfin\nExec=Lockfin\n'
        'Icon=lockfin\nCategories=Utility;Security;\nTerminal=false\n'
        f'X-AppImage-Version={VERSION}\n')
    shutil.copy2(ROOT / 'assets/lockfin.svg', appdir / 'lockfin.svg')
    (appdir / '.DirIcon').symlink_to('lockfin.svg')

    # Ship corresponding application source, including the unmodified upstream effect.
    source = appdir / 'usr/share/lockfin/source'
    source.mkdir(parents=True)
    for name in ('desktop.py', 'device_storage.py', 'flipper_sync.py', 'importers.py', 'vault.py', 'start.py',
                 'build_appimage.py', 'package_dists.py', 'login_manager.c', 'application.fam', 'requirements.txt', 'requirements.lock', 'requirements-build.txt', 'README.md', 'LICENSE'):
        shutil.copy2(ROOT / name, source / name)
    shutil.copytree(ROOT / 'assets', source / 'assets')
    shutil.copytree(ROOT / 'third_party/qflipper', source / 'third_party/qflipper')
    shutil.copytree(ROOT / 'tests', source / 'tests', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))

    # Optional local secret audit; neither the export nor its path enters the bundle.
    export = os.environ.get('LOCKFIN_AUDIT_EXPORT')
    if export:
        document = json.loads(Path(export).read_text(encoding='utf-8-sig'))
        passwords = [(item.get('login') or {}).get('password')
                     for item in document.get('items', [])]
        secrets = [p.encode() for p in passwords if isinstance(p, str) and len(p) >= 8]
        for file in appdir.rglob('*'):
            if file.is_file():
                data = file.read_bytes()
                if any(secret in data for secret in secrets):
                    raise RuntimeError('Private credential detected; distribution stopped.')

    # Official static type-2 runtime; pin its exact asset digest in the build record.
    api = 'https://api.github.com/repos/AppImage/type2-runtime/releases/tags/continuous'
    request = urllib.request.Request(api, headers={'User-Agent': 'Lockfin-build'})
    with urllib.request.urlopen(request, timeout=45) as response:
        release = json.load(response)
    asset = next(a for a in release['assets'] if a['name'] == 'runtime-x86_64')
    with urllib.request.urlopen(asset['browser_download_url'], timeout=45) as response:
        runtime = response.read()
    digest = 'sha256:' + hashlib.sha256(runtime).hexdigest()
    if asset.get('digest') != digest or runtime[8:11] != b'AI\x02':
        raise RuntimeError('Official AppImage runtime digest or type mismatch.')

    squashfs = TOOLS / 'Lockfin.squashfs'
    run('mksquashfs', str(appdir), str(squashfs), '-noappend', '-root-owned',
        '-comp', 'gzip', '-processors', '2', '-no-progress')
    output = ROOT / 'dist/pc'
    output.mkdir(parents=True, exist_ok=True)
    target = output / f'Lockfin-{VERSION}-x86_64.AppImage'
    temporary = target.with_suffix('.AppImage.tmp')
    with temporary.open('wb') as stream:
        stream.write(runtime)
        with squashfs.open('rb') as stream_in:
            shutil.copyfileobj(stream_in, stream)
    temporary.chmod(0o755)
    os.replace(temporary, target)
    env = dict(os.environ, APPIMAGE_EXTRACT_AND_RUN='1', QT_QPA_PLATFORM='offscreen',
               APPIMAGELAUNCHER_DISABLE='1')
    run(str(target), '--smoke-test', env=env, timeout=60)
    (output / f'{target.name}.sha256').write_text(
        hashlib.sha256(target.read_bytes()).hexdigest() + '  ' + target.name + '\n')
    (output / f'{target.name}.runtime.txt').write_text(
        f'Official runtime: {asset["browser_download_url"]}\n{digest}\n'
        f'Build host: {platform.platform()}\n'
        'Built and smoke-tested on Arch Linux; older distributions are untested.\n')
    print(f'APPIMAGE_OK: {target.name} ({target.stat().st_size} bytes)')
    return target


if __name__ == '__main__':
    build()
