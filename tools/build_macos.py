#!/usr/bin/env python3
"""Genera un DMG UDZO y valida la aplicacion desde su imagen montada."""
import platform
import shutil
import sys
import tempfile

from build_common import OUTPUT, TOOLS, VERSION, copy_source, freeze_args, install_locked, record, run, smoke


def build():
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise SystemExit('Build on Apple Silicon macOS; the runtime lock targets macOS arm64.')
    install_locked()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    run(*freeze_args('macos'))
    app = TOOLS / 'native-macos/dist/Lockfin.app'
    copy_source(app / 'Contents/Resources/source')
    run('codesign', '--force', '--deep', '--sign', '-', app)
    run('codesign', '--verify', '--deep', '--strict', app)
    smoke(app / 'Contents/MacOS/Lockfin')
    artifact = OUTPUT / f'Lockfin-{VERSION}-macOS-Apple-Silicon.dmg'
    with tempfile.TemporaryDirectory(prefix='lockfin-dmg-') as temporary:
        from pathlib import Path
        staging = Path(temporary) / 'staging'
        staging.mkdir()
        shutil.copytree(app, staging / 'Lockfin.app', symlinks=True)
        (staging / 'Applications').symlink_to('/Applications', target_is_directory=True)
        run('hdiutil', 'create', '-volname', 'Lockfin', '-srcfolder', staging,
            '-format', 'UDZO', '-ov', artifact)
        mount = Path(temporary) / 'mounted'
        run('hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, artifact)
        try:
            if not (mount / 'Applications').is_symlink():
                raise RuntimeError('DMG is missing the Applications shortcut.')
            smoke(mount / 'Lockfin.app/Contents/MacOS/Lockfin')
        finally:
            run('hdiutil', 'detach', mount)
    tools = [run('sw_vers', capture_output=True, text=True).stdout.strip(),
             run('xcodebuild', '-version', capture_output=True, text=True).stdout.strip()]
    record(artifact, tools, 'Ad-hoc only; no Developer ID certificate or notarization')
    return artifact


if __name__ == '__main__':
    build()
