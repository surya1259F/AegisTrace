# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from pathlib import Path

block_cipher = None

BASE_DIR = Path(os.path.abspath('.')).resolve()

datas = [
    (str(BASE_DIR / 'forensic_tools' / 'yara' / 'rules'), 'forensic_tools/yara/rules'),
    (str(BASE_DIR / 'backend' / 'alembic.ini'), 'backend'),
    (str(BASE_DIR / 'backend' / 'alembic'), 'backend/alembic'),
]

hidden_imports = [
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'starlette',
    'pydantic',
    'pydantic_core',
    'pydantic_settings',
    'sqlalchemy',
    'sqlalchemy.dialects.sqlite',
    'sqlite3',
    'httpx',
    'multipart',
    'Evtx',
    'Evtx.Evtx',
    'Evtx.Views',
    'hexdump',
    'hmac',

    'hashlib',
    'secrets',
    'uuid',
    'json',
    'asyncio',
    'agents.disk.disk_agent',
    'agents.log.log_agent',
    'agents.malware.malware_agent',
    'agents.memory.memory_agent',
    'forensic_tools.registry',
    'forensic_tools.sleuthkit.adapter',
    'forensic_tools.exiftool.adapter',
    'forensic_tools.volatility.adapter',
    'forensic_tools.yara.adapter',
    'forensic_tools.yara.rules_manager',
    'backend.app.main',
    'backend.app.core.config',
    'backend.app.core.database',
    'backend.app.core.security',
    'backend.app.api.v1.router',
    'backend.app.api.v1.endpoints.system',
    'backend.app.api.v1.endpoints.cases',
    'backend.app.api.v1.endpoints.evidence',
    'backend.app.api.v1.endpoints.investigation',
    'backend.app.api.v1.endpoints.reports',
    'backend.app.api.v1.endpoints.auth',
    'backend.app.api.v1.endpoints.ai',
    'backend.app.services.ai_provider',
    'backend.app.services.ai_copilot',
    'backend.app.services.authorization',
    'backend.app.services.vault',
    'backend.app.services.custody',
    'backend.app.services.audit',
]

a = Analysis(
    [str(BASE_DIR / 'backend' / 'entrypoint.py')],
    pathex=[str(BASE_DIR)],

    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'pytest_asyncio', 'tkinter', 'unittest'],
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
    name='adfir-backend',
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
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='adfir-backend',
)
