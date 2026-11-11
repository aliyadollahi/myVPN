# -*- mode: python ; coding: utf-8 -*-
# Built by build.ps1 - produces ONE exe with Xray + SoftEther engine + seed list inside.
import os
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = []
for pkg in ('customtkinter', 'qrcode'):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

# everything under bundle/ ends up in sys._MEIPASS/bundle/... ; bootstrap.py installs it on first run
for root, _, files in os.walk('bundle'):
    for f in files:
        datas.append((os.path.join(root, f), root))

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib', 'scipy', 'IPython', 'pytest'],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VPNGateGuardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,   # VPN engine install, routes and kill switch need Administrator
)
