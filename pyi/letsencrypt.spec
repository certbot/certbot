"""PyInstaller spec file for Let's Encrypt client."""
import os
import sys

sys.path.insert(0, '.')
import entrypoints


TMP_ENTRY_POINTS_PATH = os.path.join(WORKPATH, 'entry_points.json')
ENTRY_POINTS = [('entry_points.json', TMP_ENTRY_POINTS_PATH, 'DATA')]
entrypoints.dump_entry_points(
    TMP_ENTRY_POINTS_PATH,
    'letsencrypt',
    'cryptography',
)

MAIN = entrypoints.Entrypoint(
    workpath=WORKPATH,
    analysis_cls=Analysis,
    dist='letsencrypt',
    group='console_scripts',
    name='letsencrypt',
    hiddenimports=[
        'cffi',
        'letsencrypt',
    ],
    hookspath=['.'],
    runtime_hooks=['rthook-entrypoints.py'],
)
MAIN_PYZ = PYZ(
    MAIN.pure,
)
MAIN_EXE = EXE(
    MAIN_PYZ,
    MAIN.scripts,
    MAIN.binaries,
    MAIN.zipfiles,
    MAIN.datas,
    ENTRY_POINTS,
    name='bin/letsencrypt',
    debug=False,
    strip=None,
    upx=True,
    console=True,
)

# TODO: letsencrypt-renewer

# one-folder output, for those people that have /tmp mounted as noexec
# (one-file has to be extracted to /tmp before running, see
# PyInstaller docs for more info)
MAIN_EXE_FOLDER = EXE(
    MAIN_PYZ,
    MAIN.scripts,
    exclude_binaries=True,
    name='letsencrypt-bin',
    debug=False,
    strip=None,
    upx=True,
    console=True,
)
COLL = COLLECT(
    MAIN_EXE_FOLDER,
    MAIN.binaries,
    MAIN.zipfiles,
    MAIN.datas,
    ENTRY_POINTS,
    strip=None,
    upx=True,
    name='folder',
)
