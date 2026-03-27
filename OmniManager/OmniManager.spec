# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for OmniManager
# Build: pyinstaller OmniManager.spec

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['run.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('app/templates', 'app/templates'),
        ('app/static',    'app/static'),
    ],
    hiddenimports=[
        'eventlet',
        'eventlet.hubs',
        'eventlet.hubs.epolls',
        'eventlet.hubs.poll',
        'eventlet.hubs.selects',
        'eventlet.green',
        'eventlet.green.subprocess',
        'flask_socketio',
        'flask_login',
        'flask_wtf',
        'flask_sqlalchemy',
        'sqlalchemy.dialects.sqlite',
        'winrm',
        'winrm.protocol',
        'winrm.exceptions',
        'requests',
        'requests_ntlm',
        'requests_credssp',
        'xmltodict',
        'email',
        'email.mime',
        'email.mime.multipart',
        'email.mime.text',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='OmniManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='OmniManager',
)
