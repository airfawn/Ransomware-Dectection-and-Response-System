# -*- mode: python -*-
block_cipher = None

import os
from PyInstaller.utils.hooks import collect_submodules

# Ensure main.py is bundled alongside the GUI
datas = [
    ('main.py', '.'),
]
hiddenimports = collect_submodules('PyQt5')

a = Analysis(
    ['basic_gui.py'],
    pathex=[os.path.dirname(__file__)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='rdrs_gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='rdrs_gui',
)
