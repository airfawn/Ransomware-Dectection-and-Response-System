# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['basic_gui.py'],
    pathex=[],
    binaries=[],
    # Bundle config.yaml as a read-only asset so the app can find it at runtime.
    # Databases are stored in get_data_dir() (user app data), never inside the bundle.
    datas=[
        ('config.yaml', '.'),
    ],
    hiddenimports=[
        # Existing modules
        'monitor',
        'monitor.filesystem_monitor',
        'monitor.session',
        'utils',
        'utils.logger',
        'utils.paths',
        # New: config with YAML support
        'config',
        'yaml',
        # New: database layer
        'database',
        'database.base_db',
        'database.metadata_db',
        'database.logs_db',
        'database.alerts_db',
        # New: entropy module
        'entropy',
        'entropy.calculator',
        'entropy.monitor',
        # stdlib extras that PyInstaller may miss
        'sqlite3',
        'math',
        'hashlib',
        'platform',
        'threading',
        'queue',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='basic_gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
app = BUNDLE(
    exe,
    name='basic_gui.app',
    icon=None,
    bundle_identifier=None,
)
