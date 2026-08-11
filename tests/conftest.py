# -*- coding: utf-8 -*-
"""Isolamento global da suite contra side-effects reais.

O relatorio semanal envia e-mail via Microsoft Graph (_get_outlook_service).
Como o .env de producao (credenciais MSAL) fica no diretorio do projeto,
qualquer teste que gere o relatorio autenticaria na Azure AD e enviaria
e-mail real com anexo. O stub autouse abaixo bloqueia isso para TODA a
suite; testes que precisem inspecionar o envio podem usar o fixture
`isolar_outlook` e ler `stub.enviados`.
"""
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import main


class _OutlookServiceStub:
    def __init__(self):
        self.enviados = []

    def send_weekly_report(self, report_path, period_label):
        self.enviados.append((str(report_path), str(period_label)))
        return 202


@pytest.fixture(autouse=True)
def isolar_outlook(monkeypatch):
    stub = _OutlookServiceStub()
    monkeypatch.setattr(main, "_get_outlook_service", lambda: stub)
    yield stub
