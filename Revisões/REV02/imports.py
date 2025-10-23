#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Instalador de dependências baseado no código-fonte.
- Faz parsing por AST para capturar imports com precisão.
- Tenta importar antes de instalar (idempotente).
- Mapeia nomes de módulo para nomes PyPI quando diferem.
Uso:
    python imports.py [CAMINHO_DO_ALVO]
Se não informado, tenta: main2_final.py, main2_pac_status.py, main2.py, main.py (nessa ordem).
"""
from __future__ import annotations

import ast
import sys
import os
import re
import platform
import subprocess
import importlib
from pathlib import Path
from typing import Set, Iterable

# Ordem padrão de arquivos-alvo
CANDIDATOS = [
    "main2_final.py",
]

# Mapeamento módulo -> pacote PyPI
PACKAGE_MAP = {
    # GUI / imagens
    "PIL": "pillow",
    "cv2": "opencv-python",
    # HTTP / datas / tz
    "dateutil": "python-dateutil",
    # (requests, numpy, pandas, matplotlib têm o mesmo nome no PyPI)
    # Outros alias comuns
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "jose": "python-jose",
    "orjson": "orjson",
    "ujson": "ujson",
    "simplejson": "simplejson",
    "fastapi": "fastapi",
    "starlette": "starlette",
    "uvicorn": "uvicorn",
    "pydantic": "pydantic",
    "loguru": "loguru",
    "rich": "rich",
    "tenacity": "tenacity",
    "tqdm": "tqdm",
    "psutil": "psutil",
    "win10toast": "win10toast",
}

# Módulos da stdlib que não devem ser instalados
# (lista enxuta; usamos tentativa de import para decidir)
PROVAVEL_STDLIB = {
    "sys","os","re","json","csv","math","time","datetime","pathlib","typing",
    "itertools","functools","collections","subprocess","threading","queue",
    "logging","argparse","shutil","tempfile","uuid","hashlib","hmac","base64",
    "ssl","socket","http","urllib","configparser","dataclasses","statistics",
    "traceback","enum","types","platform","ctypes","getpass","glob","inspect",
    "random","string","zipfile","tarfile","importlib","site","runpy","ast",
    "tkinter","winsound"  # tkinter e winsound fazem parte da stdlib (Windows)
}

def escolher_alvo(argv: Iterable[str]) -> Path:
    if len(argv) > 1:
        p = Path(argv[1]).expanduser()
        if p.exists():
            return p
        print(f"[aviso] Caminho passado não existe: {p}")
    for nome in CANDIDATOS:
        p = Path(nome)
        if p.exists():
            return p
    raise FileNotFoundError(
        "Nenhum arquivo-alvo encontrado. Informe o caminho do arquivo fonte.\n"
        "Tentados: " + ", ".join(CANDIDATOS)
    )

def coletar_imports(codigo: str) -> Set[str]:
    tree = ast.parse(codigo)
    mods: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                raiz = (alias.name.split(".")[0]).strip()
                if raiz:
                    mods.add(raiz)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                raiz = (node.module.split(".")[0]).strip()
                if raiz:
                    mods.add(raiz)
    return mods

def pip_install(pkg: str) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", pkg]
    print(f"[pip] instalando: {pkg}")
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[erro] pip falhou para '{pkg}': {e}")
        return False

def precisa_instalar(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return False
    except Exception:
        return True

def tratar_tkinter(mod: str) -> None:
    # Tkinter é stdlib; em Windows geralmente já vem. Em Linux/macOS depende de libs do SO.
    so = platform.system().lower()
    msg = (
        "[tkinter] Tkinter faz parte da biblioteca padrão.\n"
        "- Windows: já vem com o Python oficial.\n"
        "- Ubuntu/Debian: sudo apt-get install python3-tk\n"
        "- macOS (brew): brew install python-tk@3 (ou use o instalador oficial do Python)\n"
        "Obs.: não é instalado via 'pip'."
    )
    print(msg)

def main() -> None:
    alvo = escolher_alvo(sys.argv)
    print(f"[info] Arquivo-alvo: {alvo}")

    codigo = Path(alvo).read_text(encoding="utf-8", errors="ignore")
    mods = coletar_imports(codigo)

    if not mods:
        print("[info] Nenhum import detectado.")
        return

    print(f"[info] Módulos detectados ({len(mods)}): {', '.join(sorted(mods))}")

    for mod in sorted(mods):
        # Pula prováveis stdlib (ainda assim tentaremos importar para garantir)
        if mod in PROVAVEL_STDLIB:
            # tkinter precisa de nota especial às vezes
            if mod == "tkinter":
                try:
                    importlib.import_module("tkinter")
                except Exception:
                    tratar_tkinter(mod)
            continue

        if precisa_instalar(mod):
            # resolve nome PyPI
            pkg = PACKAGE_MAP.get(mod, mod)
            ok = pip_install(pkg)
            if not ok and mod == "tkinter":
                tratar_tkinter(mod)
        else:
            print(f"[ok] '{mod}' já disponível.")

    print("[done] Verificação de dependências concluída.")

if __name__ == "__main__":
    main()
