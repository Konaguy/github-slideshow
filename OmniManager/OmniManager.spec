# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for OmniManager desktop app
# Build:  pyinstaller OmniManager.spec
# Output: dist/OmniManager.app  (Mac)
#         dist/OmniManager.exe  (Windows)

block_cipher = None

a = Analysis(
    ["desktop.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("app/templates",   "app/templates"),
        ("app/static",      "app/static"),
        ("config.py",       "."),
    ],
    hiddenimports=[
        "flask",
        "flask_sqlalchemy",
        "flask_login",
        "flask_socketio",
        "flask_wtf",
        "flask_migrate",
        "flask_limiter",
        "flask_limiter.util",
        "engineio.async_drivers.threading",
        "socketio",
        "sqlalchemy.dialects.sqlite",
        "apscheduler",
        "apscheduler.schedulers.background",
        "apscheduler.triggers.cron",
        "apscheduler.executors.pool",
        "cryptography",
        "winrm",
        "requests",
        "webview",
        "webview.platforms.cocoa",
        "webview.platforms.winforms",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="OmniManager",
    debug=False,
    strip=False,
    upx=True,
    console=False,
    icon="app/static/icon.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name="OmniManager",
)

app = BUNDLE(
    coll,
    name="OmniManager.app",
    icon="app/static/icon.icns",
    bundle_identifier="com.omnimanager.app",
    info_plist={
        "NSPrincipalClass": "NSApplication",
        "NSHighResolutionCapable": True,
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "12.0",
        "NSRequiresAquaSystemAppearance": False,
    },
)
