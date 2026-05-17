# -*- coding: utf-8 -*-
# ===========================================
# Monitor de Relés/Inversores (headless, Teams)
# - Sem UI/monitor; roda em servidor e envia alertas para Teams.
# - SSL: use verificação adequada. No servidor, aponte a variável
#   de ambiente SSL_CERT_FILE ou REQUESTS_CA_BUNDLE para o bundle
#   de CA válido (ex.: .pem fornecido pela infra) ou ajuste VERIFY_CA.
# ===========================================

import atexit
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from datetime import time as dtime
from datetime import timedelta
from email.utils import parsedate_to_datetime
from functools import lru_cache
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from statistics import median
from typing import Generator, Literal, TypedDict
from zipfile import ZIP_DEFLATED, ZipFile

import requests
from dotenv import load_dotenv
from requests import Session
from requests.exceptions import Timeout


load_dotenv()
# =========================
# CONFIGURACAO VIA AMBIENTE
# =========================
PVOP_BASE_URL = os.environ.get("PVOP_BASE_URL", "https://apipv.pvoperation.com.br/api/v1").strip()
PVOP_EMAIL = os.environ.get("MONITOR_EMAIL", "").strip()
PVOP_PASSWORD = os.environ.get("MONITOR_PASSWORD", "").strip()
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)
# Diagnostico extra do circuito de rele. Ative com RELE_DEBUG=1 no .env
# para gerar logs detalhados (payload Teams, contagens de estado, motivo
# exato de cada decisao de envio). Desligue (RELE_DEBUG=0) apos diagnostico
# para evitar poluir os logs em producao.
RELE_DEBUG = os.environ.get("RELE_DEBUG", "0").strip().lower() in ("1", "true", "yes", "on")
# =========================

# Lock de instancia: fcntl (Unix) ou msvcrt (Windows)
try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

# --- Configuração geral ---
RELAY_INTERVAL = 600          # 10 min
INVERTER_INTERVAL = 900       # 15 min
PLANTS_CACHE_TTL = timedelta(seconds=RELAY_INTERVAL)  # relay e inversor partilham a mesma lista
# Cooldown menor que RELAY_INTERVAL para garantir que a varredura seguinte
# consiga reprocessar o alerta (caso contrario, varia entre 0 e 2x o intervalo).
RELAY_NOTIFICATION_RETRY_COOLDOWN = timedelta(seconds=RELAY_INTERVAL // 2)
SAVE_STATE_FAIL_THRESHOLD = 3
STOP_JOIN_TIMEOUT = 35        # aguarda encerramento das threads antes de forcar saida
HEARTBEAT_TIMES = [
    dtime(7, 0),
    dtime(12, 0),
    dtime(17, 0),
    dtime(20, 0),
    dtime(23, 0)
]
SOLAR_WINDOW_START = dtime(6, 0)
SOLAR_WINDOW_END = dtime(17, 30)
SOLAR_WINDOW_LABEL = f"{SOLAR_WINDOW_START.strftime('%H:%M')}-{SOLAR_WINDOW_END.strftime('%H:%M')}"
INVERTER_SOLAR_WINDOW_START = dtime(6, 30)
INVERTER_SOLAR_WINDOW_END = dtime(17, 0)
INVERTER_SOLAR_WINDOW_LABEL = (
    f"{INVERTER_SOLAR_WINDOW_START.strftime('%H:%M')}"
    f"-{INVERTER_SOLAR_WINDOW_END.strftime('%H:%M')}"
)
IBIMIRIM_INVERTER_SOLAR_WINDOW_START = dtime(7, 30)
IBIMIRIM_INVERTER_SOLAR_WINDOW_END = dtime(17, 0)
IBIMIRIM_INVERTER_SOLAR_WINDOW_LABEL = (
    f"{IBIMIRIM_INVERTER_SOLAR_WINDOW_START.strftime('%H:%M')}"
    f"-{IBIMIRIM_INVERTER_SOLAR_WINDOW_END.strftime('%H:%M')}"
)
IBIMIRIM_INVERTER_PLANT_NAMES = {
    "COMP.IBI.2500.LT01",
    "COMP.IBI.2500.LT02",
    "COMP.IBI.2500.LT03",
    "COMP.IBI.2500.LT04",
    "COMP.IBI.2500.LT05",
}
# Apenas estas usinas possuem relé de proteção e devem ser varridas no fluxo de relé.
RELE_PLANT_IDS = {
    "19478", "19815", "19816", "21544", "22275", "22283", "22290", "22291",
    "22873", "22874", "24129", "24130", "53209", "53222", "53297", "59991",
    "60003", "60559", "297443", "297444", "297445", "297446", "297449",
    "18744051", "18744052",
}
WEEKLY_REPORT_CHECK_INTERVAL = 300
WEEKLY_REPORT_GENERATION_TIME = dtime(0, 5)
# Usa uma semana extra para reconstruir estado na borda da semana sem aumentar
# demais a carga da API; o state local continua como segunda fonte.
WEEKLY_REPORT_WARMUP_DAYS = 7

RELAY_PARAMS_CLASSIF = {
    "SOBRETENSÃO": {"r59A", "r59B", "r59C", "r59N"},
    "SUBTENSÃO": {"r27A", "r27B", "r27C", "r27_0"},
    "FREQUÊNCIA": {"r81O", "r81U"},
    "TÉRMICO": {"r49", "r49_2"},
    "BLOQUEIO": {"rAR", "rBA", "rDO"},
}
RELAY_PARAMETROS = {
    "r27A","r27B","r27C","r27_0","r32A","r32A_2","r32B","r32B_2","r32C","r32C_2",
    "r46Q","r47","r59A","r59B","r59C","r59N","r67A","r67A_2","r67B","r67B_2",
    "r67C","r67C_2","r67N_1","r67N_2","r78","r81O","r81U","r86","rAR","rBA",
    "rDO","rEPwd","rERLS","rEl2t","rFR","rGS","rHLT","rRL1","rRL2","rRL3",
    "rRL4","rRL5","rRR","r49","r49_2"
}
# Lookup case-insensitive: protege contra variacao de capitalizacao das chaves
# vindas da API (mesma classe de bug que o inversor ja blindou com varios aliases de "Pac").
RELAY_PARAMETROS_LOOKUP = {p.lower(): p for p in RELAY_PARAMETROS}

# Limites para evitar crescimento indefinido do state.
MAX_PENDING_RELE_POR_USINA = 200
MAX_PENDING_INV = 400
MAX_INCIDENT_HISTORY = 10000
INCIDENT_RETENTION_DAYS = 180
INVERTER_CONSECUTIVE_READINGS = 3
INVERTER_RECOVERY_CONSECUTIVE_READINGS = 2
INVERTER_FAILURE_LABEL = f"PAC=0 ({INVERTER_CONSECUTIVE_READINGS} leituras consecutivas)"
INVERTER_MISSING_SCAN_TOLERANCE = 3
INVERTER_HEARTBEAT_CONFIRMATION_TTL = timedelta(seconds=(INVERTER_INTERVAL * 3) + 60)

# SSL: ajuste para o bundle correto no servidor (ex.: /etc/ssl/certs/ca.pem)
VERIFY_CA = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or True

_teams_session = requests.Session()

# Diretórios/arquivos de controle
BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "monitor_state.json"
LOCK_FILE = STATE_DIR / ".monitor_lock"
LOG_DIR = BASE_DIR / "logs"
LOG_RELE_DIR = LOG_DIR / "rele"
LOG_INV_DIR = LOG_DIR / "inversor"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# evite reprocessar a borda final da janela (pula 1 segundo além do último fim)
WINDOW_DELTA_SECONDS = 1
STATE_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Tipos de dados — puramente documentais, sem efeito em runtime
# ---------------------------------------------------------------------------
SeverityLevel = Literal["info", "warning", "danger"]


class CardTeams(TypedDict):
    title: str
    text: str
    severity: SeverityLevel
    facts: list[tuple[str, str]] | None


class EstadoInversor(TypedDict):
    ativa: bool
    rec_seq: int
    seq_zero: int
    alerta: dict | None
    notificado: bool
    ausente_scans: int
    ultima_confirmacao_ts: str | None


class Incidente(TypedDict):
    chave: str
    natureza: str
    tipo_falha: str
    usina_id: str
    usina: str | None
    equipamento: str
    inicio_ts: str
    fim_ts: str | None


def _configurar_logger_arquivo(name: str, log_dir: Path, log_filename: str, fmt, base_logger) -> logging.Logger:
    lgr = logging.getLogger(name)
    lgr.setLevel(logging.INFO)
    lgr.handlers.clear()
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        h = TimedRotatingFileHandler(log_dir / log_filename, when="midnight", backupCount=7, encoding="utf-8")
        h.setLevel(logging.INFO)
        h.setFormatter(fmt)
        lgr.addHandler(h)
    except Exception as e:
        base_logger.warning(f"Falha ao inicializar log em arquivo ({name}): {e}")
    lgr.propagate = True
    return lgr


# Responsavel por criar os loggers base e setar a rotacao diaria dos arquivos de log.
def setup_logging():
    fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    base_logger = logging.getLogger("RelayMonitorHeadless")
    base_logger.setLevel(logging.INFO)
    base_logger.handlers.clear()
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    base_logger.addHandler(console)

    _configurar_logger_arquivo("RelayMonitorHeadless.rele",     LOG_RELE_DIR, "rele.log",     fmt, base_logger)
    _configurar_logger_arquivo("RelayMonitorHeadless.inversor", LOG_INV_DIR,  "inversor.log", fmt, base_logger)


# Inicializa configuracao de loggers antes de criar instancias globais.
setup_logging()
logger = logging.getLogger("RelayMonitorHeadless")
logger_rele = logging.getLogger("RelayMonitorHeadless.rele")
logger_inv = logging.getLogger("RelayMonitorHeadless.inversor")

def _is_placeholder(value: str) -> bool:
    if value is None:
        return True
    raw = str(value).strip()
    return (not raw) or (raw.upper() == "COLE_AQUI")

def validate_config():
    missing = []
    if _is_placeholder(PVOP_BASE_URL):
        missing.append("PVOP_BASE_URL")
    if _is_placeholder(PVOP_EMAIL):
        missing.append("MONITOR_EMAIL")
    if _is_placeholder(PVOP_PASSWORD):
        missing.append("MONITOR_PASSWORD")
    if _is_placeholder(TEAMS_WEBHOOK_URL):
        missing.append("TEAMS_WEBHOOK_URL")
    if missing:
        raise SystemExit(
            "Configuracao obrigatoria ausente ou placeholder em variaveis de ambiente: "
            + ", ".join(missing)
            + ". Configure o ambiente do servico ou crie um .env local nao versionado."
        )


def _parse_retry_after_seconds(headers: dict) -> int | None:
    """Parsa o header Retry-After e retorna o numero de segundos a esperar."""
    retry_after = (headers or {}).get("Retry-After")
    if not retry_after:
        return None
    try:
        return max(0, int(retry_after))
    except (TypeError, ValueError):
        pass
    try:
        parsed = parsedate_to_datetime(retry_after)
    except Exception:
        return None
    if not parsed:
        return None
    now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
    delta = (parsed - now).total_seconds()
    return max(0, int(delta))


# Envia cartao padrao (MessageCard) para Teams quando alertas ocorrem.
def _teams_post_card(
    title: str,
    text: str,
    severity: SeverityLevel = "info",
    facts: list[tuple[str, str]] | None = None,
    max_tentativas: int = 3,
) -> bool:
    """Envia um 'MessageCard' para um Incoming Webhook do Microsoft Teams."""
    if not TEAMS_ENABLED:
        return False

    colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": colors.get(severity, "0078D4"),
        "title": title,
        "text": text,
    }
    if facts:
        payload["sections"] = [{"facts": [{"name": k, "value": v} for k, v in facts]}]
    max_tentativas = max(1, int(max_tentativas or 1))
    backoff_base = 2
    payload_bytes = json.dumps(payload)
    if RELE_DEBUG:
        logger.info(
            f"[TEAMS][DEBUG] POST | title={title!r} | severity={severity} | "
            f"payload_size={len(payload_bytes)}B | payload={payload_bytes[:500]}"
        )
    for tentativa in range(1, max_tentativas + 1):
        try:
            r = _teams_session.post(
                TEAMS_WEBHOOK_URL,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code == 429:
                espera = _parse_retry_after_seconds(r.headers)
                if espera is not None:
                    espera = min(max(0, espera), 60)
                    if tentativa == max_tentativas:
                        logger.warning(
                            f"[TEAMS] Rate limit (429) excedeu tentativas | title={title!r}"
                        )
                        return False
                    time.sleep(espera)
                    continue
            r.raise_for_status()
            resposta_txt = (getattr(r, "text", "") or "").strip()
            if "Webhook message delivery failed" in resposta_txt:
                logger.warning(
                    f"[TEAMS] Webhook aceito com falha de entrega | title={title!r} | "
                    f"status={r.status_code} | body={resposta_txt[:500]!r}"
                )
                return False
            if RELE_DEBUG:
                logger.info(
                    f"[TEAMS][DEBUG] OK | title={title!r} | status={r.status_code} | "
                    f"body[:200]={resposta_txt[:200]!r}"
                )
            return True
        except Exception as e:
            status_code = getattr(getattr(e, "response", None), "status_code", None)
            body_txt = getattr(getattr(e, "response", None), "text", "") or ""
            # Toda tentativa que falha vira WARNING (nao so a ultima); essencial
            # para diagnosticar webhooks que falham sistematicamente.
            logger.warning(
                f"[TEAMS] tentativa {tentativa}/{max_tentativas} falhou | "
                f"title={title!r} | erro={type(e).__name__}: {e} | "
                f"status={status_code} | body[:300]={body_txt[:300]!r}"
            )
            if tentativa == max_tentativas:
                return False
            time.sleep(backoff_base * tentativa)
    return False


# Cliente responsavel por autenticar na API PVOperation e expor chamadas encapsuladas.
class PVOperationAPI:
    """Cliente da API PVOperation com retry e verificação SSL configurável."""

    # Inicializa credenciais, sessao HTTP e dispara autenticacao inicial.
    def __init__(self, email, password, base_url=PVOP_BASE_URL, verify=VERIFY_CA):
        self.email = email
        self.password = password
        self.base_url = base_url
        self._verify = verify  # guarda configuracao de verificacao SSL
        self.session = Session()
        self.session.verify = self._verify
        self.token = None
        self.headers = {}
        self.last_get_plants_timeout = False
        self.last_get_plants_error = False
        self.last_post_day_timeout = False
        self.last_post_day_error = False
        self.last_post_day_error_reason = None
        self._login()

    def _reset_session(self):
        try:
            self.session.close()
        except Exception:
            pass
        self.session = Session()
        self.session.verify = self._verify

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers=None,
        json_payload=None,
        timeout: int = 20,
        max_tentativas: int = 3,
        backoff_base: int = 2,
        contexto: str = "",
        reauth_on_401: bool = False,
        retry_on_status=None,
        log_status: bool = True,
        conn_error_suffix: str = "Tentando recriar sessão.",
    ):
        def _should_retry(status_code: int) -> bool:
            if retry_on_status is None:
                return status_code == 429 or 500 <= status_code <= 599
            if callable(retry_on_status):
                return retry_on_status(status_code)
            return status_code in retry_on_status

        for tentativa in range(1, max_tentativas + 1):
            try:
                req_headers = headers if headers is not None else self.headers
                resp = self.session.request(
                    method,
                    url,
                    headers=req_headers,
                    json=json_payload,
                    timeout=timeout,
                )
            except Timeout:
                logger.warning(
                    f"Timeout em {contexto} - tentativa {tentativa}/{max_tentativas}."
                )
                if tentativa == max_tentativas:
                    return None, True
                time.sleep(backoff_base * tentativa)
                continue
            except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                logger.warning(
                    f"Erro de conexão em {contexto}: {e}. {conn_error_suffix}"
                )
                self._reset_session()
                if not self._login():
                    if tentativa == max_tentativas:
                        return None, False
                    time.sleep(backoff_base * tentativa)
                    continue
                if tentativa == max_tentativas:
                    return None, False
                time.sleep(backoff_base * tentativa)
                continue
            except Exception as e:
                logger.error(f"Erro em {contexto}: {e}")
                return None, False

            if resp.status_code == 401 and reauth_on_401:
                if not self.verificar_token():
                    return None, False
                time.sleep(1)
                continue

            if _should_retry(resp.status_code):
                if log_status:
                    logger.warning(
                        f"Status {resp.status_code} em {contexto} - tentativa {tentativa}/{max_tentativas}."
                    )
                if tentativa == max_tentativas:
                    return resp, False
                if resp.status_code == 429:
                    espera = _parse_retry_after_seconds(resp.headers)
                    if espera is None:
                        espera = min(backoff_base ** tentativa, 10)
                else:
                    espera = backoff_base * tentativa
                time.sleep(espera)
                continue

            return resp, False

        return None, False

    # Executa login na API para obter token JWT e cabecalhos de autorizacao.
    def _login(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.base_url}/authenticate",
                json={"username": self.email, "password": self.password},
                timeout=20,
            )
            if resp.status_code == 200:
                try:
                    token = resp.json().get("token")
                except Exception as e:
                    logger.error(f"Falha ao ler token da resposta: {e}")
                    return False
                if not token:
                    logger.error("Falha na autenticação: token ausente na resposta.")
                    return False
                self.token = token
                self.headers = {"x-access-token": self.token}
                logger.info("Autenticação realizada com sucesso.")
                return True
            logger.error(f"Falha na autenticação. Status: {resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"Erro durante login: {e}")
            return False

    # Tenta renovar token quando as chamadas retornam nao autorizado.
    def verificar_token(self) -> bool:
        logger.warning("Tentando renovar token...")
        ok = self._login()
        if not ok:
            logger.error("Não foi possível renovar o token.")
        return ok

    # Recupera lista de plantas tratando expiracao de sessao e reconexao.
    def get_plants(self) -> list | None:
        url = f"{self.base_url}/plants"
        self.last_get_plants_timeout = False
        self.last_get_plants_error = False
        r, timeout_flag = self._request_with_retry(
            "get",
            url,
            timeout=20,
            max_tentativas=3,
            backoff_base=2,
            contexto="get_plants",
            reauth_on_401=True,
            retry_on_status=None,
            log_status=False,
            conn_error_suffix="Tentando recriar sessão e reautenticar.",
        )
        if r is None:
            self.last_get_plants_timeout = bool(timeout_flag)
            self.last_get_plants_error = True
            return None
        if r.status_code == 200:
            try:
                return r.json() or []
            except Exception:
                logger.error("Resposta não-JSON em get_plants (status 200).")
                self.last_get_plants_error = True
                return None
        logger.error(f"Erro ao buscar plantas. Status: {r.status_code}")
        self.last_get_plants_error = True
        return None

    # Faz chamada para endpoint diario (day_*) com retry e backoff exponencial leve.
    def post_day(self, endpoint: str, plant_id: int, date: datetime) -> tuple[list | None, bool]:
        """Chama endpoints day_* com retry/backoff. Retorna (dados ou None, timeout_flag)."""
        self.last_post_day_timeout = False
        self.last_post_day_error = False
        self.last_post_day_error_reason = None
        payload = {"id": int(plant_id), "date": date.strftime("%Y-%m-%d")}
        url = f"{self.base_url}/{endpoint}"
        contexto = f"{endpoint} (usina {plant_id}, {date.date()})"
        r, timeout_flag = self._request_with_retry(
            "post",
            url,
            json_payload=payload,
            timeout=30,
            max_tentativas=3,
            backoff_base=2,
            contexto=contexto,
            reauth_on_401=True,
            retry_on_status=lambda status: status == 408 or status == 429 or 500 <= status <= 599,
            log_status=True,
            conn_error_suffix="Tentando recriar sessão.",
        )
        if r is None:
            self.last_post_day_timeout = bool(timeout_flag)
            self.last_post_day_error = True
            self.last_post_day_error_reason = "TIMEOUT" if timeout_flag else "REQUEST_ERROR"
            return None, timeout_flag
        if r.status_code == 200:
            try:
                return r.json(), False
            except Exception as e:
                logger.error(f"Resposta não-JSON em {contexto} (status 200): {e}")
                self.last_post_day_error = True
                self.last_post_day_error_reason = "JSON_INVALID"
                return None, False
        self.last_post_day_error = True
        self.last_post_day_error_reason = f"HTTP_{r.status_code}"
        logger.error(f"Erro em {contexto}. Status: {r.status_code}")
        return None, False


# Normaliza valores numericos vindos como string ou numero bruto para float.
def extrair_valor_numerico(valor: str | int | float | bool | None) -> float | None:
    if isinstance(valor, bool):
        return float(valor)
    if isinstance(valor, (int, float)):
        return float(valor)
    if isinstance(valor, str):
        txt = valor.strip()
        if "," in txt and "." in txt and txt.rfind(",") > txt.rfind("."):
            txt = txt.replace(".", "").replace(",", ".")
        elif "," in txt and "." not in txt:
            txt = txt.replace(",", ".")
        m = re.search(r"([-+]?\d*\.\d+|\d+)", txt)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return None
    return None


def _xml_escape(txt: str) -> str:
    return (
        txt.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@lru_cache(maxsize=128)
def _xlsx_col_name(index_zero_based: int) -> str:
    idx = int(index_zero_based)
    if idx < 0:
        raise ValueError("index de coluna invalido")
    letters = []
    while True:
        idx, rem = divmod(idx, 26)
        letters.append(chr(ord("A") + rem))
        if idx == 0:
            break
        idx -= 1
    return "".join(reversed(letters))


def _build_sheet_xml(rows):
    row_parts = []
    for row_idx, row in enumerate(rows, start=1):
        cell_parts = []
        for col_idx, value in enumerate(row):
            cell_ref = f"{_xlsx_col_name(col_idx)}{row_idx}"
            if isinstance(value, bool):
                val = "1" if value else "0"
                cell_parts.append(f'<c r="{cell_ref}" t="b"><v>{val}</v></c>')
                continue
            if isinstance(value, (int, float)):
                cell_parts.append(f'<c r="{cell_ref}"><v>{value}</v></c>')
                continue
            txt = "" if value is None else str(value)
            escaped = _xml_escape(txt)
            preserve = ' xml:space="preserve"' if (txt[:1] == " " or txt[-1:] == " ") else ""
            cell_parts.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t{preserve}>{escaped}</t></is></c>'
            )
        row_parts.append(f'<row r="{row_idx}">{"".join(cell_parts)}</row>')
    sheet_data = "".join(row_parts)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{sheet_data}</sheetData>"
        "</worksheet>"
    )


def _write_xlsx_file(path: Path, sheets):
    safe_sheets = []
    for idx, (name, rows) in enumerate(sheets, start=1):
        sheet_name = str(name or f"Sheet{idx}")[:31]
        sheet_rows = rows if isinstance(rows, list) else list(rows)
        safe_sheets.append((sheet_name, sheet_rows))

    sheet_entries = []
    rel_entries = []
    override_entries = []
    for idx, (sheet_name, rows) in enumerate(safe_sheets, start=1):
        rid = f"rId{idx}"
        sheet_entries.append(
            f'<sheet name="{_xml_escape(sheet_name)}" sheetId="{idx}" r:id="{rid}"/>'
        )
        rel_entries.append(
            f'<Relationship Id="{rid}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
        override_entries.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{''.join(sheet_entries)}</sheets>"
        "</workbook>"
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{''.join(rel_entries)}"
        "</Relationships>"
    )
    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f"{''.join(override_entries)}"
        "</Types>"
    )

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with ZipFile(tmp_path, "w", compression=ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        for idx, (_, rows) in enumerate(safe_sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", _build_sheet_xml(rows))
    os.replace(tmp_path, path)


def _parse_iso_datetime(valor):
    if not valor:
        return None
    try:
        return datetime.fromisoformat(str(valor))
    except Exception:
        return None


def _formatar_duracao(segundos: float) -> str:
    secs = max(0, int(round(float(segundos))))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _formatar_janela_solar_label(janela_inicio: dtime, janela_fim: dtime) -> str:
    return f"{janela_inicio.strftime('%H:%M')}-{janela_fim.strftime('%H:%M')}"


def _formatar_blocos_rele(itens: list, *, markdown: bool = False) -> str:
    # markdown=True usa o mesmo estilo do card do inversor (**Campo:** valor)
    # que ja funciona em producao. markdown=False (default) mantem formato
    # plano para logs internos.
    blocos = []
    for it in itens:
        if markdown:
            linhas = [
                f"**Relé:** {it.get('rele', 'N/A')}",
                f"**Tipo:** {it.get('tipo', 'N/A')}",
                f"**Horário:** {it.get('horario', '?')}",
                f"**Parâmetros:** {it.get('parametros', '')}",
            ]
        else:
            linhas = [
                f"Relé: {it.get('rele', 'N/A')}",
                f"Tipo: {it.get('tipo', 'N/A')}",
                f"Horário: {it.get('horario', '?')}",
                f"Parâmetros: {it.get('parametros', '')}",
            ]
        blocos.append("  \n".join(linhas))
    return "  \n  \n".join(blocos)


def _montar_card_rele_falha(pacote: dict) -> CardTeams | None:
    novos = pacote.get("novos") or []
    if not novos:
        return None
    # Mesmo estilo de formatacao do card de inversor — que funciona em producao.
    texto = _formatar_blocos_rele(novos, markdown=True)
    usina = pacote.get("usina", "N/A")
    severos = {"SOBRETENSÃO", "TÉRMICO", "BLOQUEIO"}
    severity = "danger" if any(i.get("tipo") in severos for i in novos) else "warning"
    return {
        "title": f"⚠️ Falha de relé - {usina}",
        # Sem prefixo "  \n" — alguns renderers/regras DLP rejeitam texto
        # iniciado por whitespace. Card de inversor (que funciona) tambem
        # comeca direto no conteudo.
        "text": texto,
        "severity": severity,
        "facts": [("Capacidade", f"{pacote.get('capacidade', 'N/A')} kWp")],
    }


def _montar_card_rele_normalizacao(pacote: dict) -> CardTeams | None:
    normalizados = pacote.get("normalizados") or []
    if not normalizados:
        return None
    texto = _formatar_blocos_rele(normalizados, markdown=True)
    usina = pacote.get("usina", "N/A")
    return {
        "title": f"✔️ Normalização de relé - {usina}",
        "text": texto,
        "severity": "info",
        "facts": [("Capacidade", f"{pacote.get('capacidade', 'N/A')} kWp")],
    }


def _formatar_corpo_card_inversor(alerta: dict, detalhes_txt: str) -> str:
    return (
        f"**Usina:** {alerta['usina']}  \n"
        f"**Inversor:** {alerta['inversor']}  \n"
        f"**Horário:** {alerta['horario']}  \n"
        f"**Detalhes:** {detalhes_txt}"
    )


def _formatar_texto_heartbeat(
    *,
    rele_atrasado: bool,
    inv_atrasado: bool,
    ultima_rele: datetime | None,
    ultima_inv: datetime | None,
    ativos_rele: int,
    ativos_inv: int,
    rele_usinas: list,
    inv_usina_counts: dict,
    previsto: datetime,
) -> str:
    bullet_prefix = "    • "
    info = [
        "Heartbeat: monitor rodando",
        "Status: OK" if not (rele_atrasado or inv_atrasado) else "Status: SCAN ATRASADO",
        *(["⚠️ Scan de relé atrasado"] if rele_atrasado else []),
        *(["⚠️ Scan de inversor atrasado"] if inv_atrasado else []),
        f"Última varredura relé: {ultima_rele.strftime('%d/%m %H:%M:%S') if ultima_rele else 'N/D'}",
        f"Última varredura inversor: {ultima_inv.strftime('%d/%m %H:%M:%S') if ultima_inv else 'N/D'}",
        f"Host/PID: {socket.gethostname()} / {os.getpid()}",
        f"Heartbeat previsto: {previsto.strftime('%d/%m %H:%M')}",
        "",
        f"**Alertas de relé ativos: {ativos_rele}**",
    ]
    for nome in rele_usinas:
        info.append(f"{bullet_prefix}{nome}")
    info.append("")
    info.append(f"**Alertas de inversor ativos: {ativos_inv}**")
    for nome in sorted(inv_usina_counts):
        info.append(f"{bullet_prefix}{nome} ({inv_usina_counts[nome]})")
    return "  \n".join(info)


# Ibimirim tem janela solar diferente das demais usinas — nome matching por substring.
def _is_ibimirim_usina(usina_nome: str) -> bool:
    if not usina_nome:
        return False
    nome_normalizado = str(usina_nome).strip().upper()
    return nome_normalizado in IBIMIRIM_INVERTER_PLANT_NAMES or "IBIMIRIM" in nome_normalizado


def _obter_janela_solar_inversor(usina_nome: str | None = None) -> tuple[dtime, dtime]:
    if _is_ibimirim_usina(usina_nome):
        return IBIMIRIM_INVERTER_SOLAR_WINDOW_START, IBIMIRIM_INVERTER_SOLAR_WINDOW_END
    return INVERTER_SOLAR_WINDOW_START, INVERTER_SOLAR_WINDOW_END


def _calcular_sobreposicao_segundos(inicio: datetime, fim: datetime, faixa_ini: datetime, faixa_fim: datetime) -> float:
    ini = max(inicio, faixa_ini)
    end = min(fim, faixa_fim)
    if end <= ini:
        return 0.0
    return float((end - ini).total_seconds())


def _calcular_sobreposicao_janela_solar(
    inicio: datetime,
    fim: datetime,
    janela_inicio: dtime = SOLAR_WINDOW_START,
    janela_fim: dtime = SOLAR_WINDOW_END,
) -> float:
    if fim <= inicio:
        return 0.0
    total = 0.0
    dia = inicio.date()
    while dia <= fim.date():
        faixa_ini = datetime.combine(dia, janela_inicio)
        faixa_fim = datetime.combine(dia, janela_fim)
        total += _calcular_sobreposicao_segundos(inicio, fim, faixa_ini, faixa_fim)
        dia += timedelta(days=1)
    return total


_RELE_STRINGS_ATIVAS_EXTRA = {
    "true", "1", "on", "yes", "sim", "ativo", "active",
    "alarm", "alarme", "trip", "tripped", "y", "t",
}


def _rele_param_ativo(valor) -> bool:
    # Mantem semantica binaria estrita do contrato historico (valor == 1
    # significa "alarme ativo"); apenas amplia o repertorio de strings
    # aceitas para resistir a variacoes de payload (ex.: "on", "trip").
    if valor is None:
        return False
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, (int, float)):
        return valor == 1
    if isinstance(valor, str):
        txt = valor.strip().lower()
        if not txt:
            return False
        if txt in _RELE_STRINGS_ATIVAS_EXTRA:
            return True
        try:
            return float(txt.replace(",", ".")) == 1.0
        except Exception:
            return False
    return False


def _extrair_parametros_ativos_rele(conteudo_raw) -> list:
    """Extrai parametros de rele ativos do payload da API com match case-insensitive.

    Retorna nomes canonicos (definidos em RELAY_PARAMETROS), independentemente
    da capitalizacao usada pela API. Preserva a ordem de aparicao no dict.
    """
    if not isinstance(conteudo_raw, dict):
        return []
    ativos = []
    vistos = set()
    for raw_key, raw_val in conteudo_raw.items():
        if not isinstance(raw_key, str):
            continue
        canon = RELAY_PARAMETROS_LOOKUP.get(raw_key.strip().lower())
        if canon is None or canon in vistos:
            continue
        if _rele_param_ativo(raw_val):
            ativos.append(canon)
            vistos.add(canon)
    return ativos


def _iterar_registros_api_dia(data_resp, endpoint: str, plant_id: str, logger_ctx) -> Generator[tuple[dict, dict, datetime], None, None]:
    if not isinstance(data_resp, list):
        logger_ctx.warning(f"Resposta inesperada em {endpoint} (usina {plant_id}): {type(data_resp).__name__}")
        return

    for registro in (data_resp or []):
        if not isinstance(registro, dict):
            logger_ctx.warning(f"Item inesperado em {endpoint} (usina {plant_id}): {type(registro).__name__}")
            continue
        conteudo_raw = registro.get("conteudojson", {})
        if not isinstance(conteudo_raw, dict):
            logger_ctx.warning(
                f"conteudojson invalido em {endpoint} (usina {plant_id}): {type(conteudo_raw).__name__}"
            )
            continue
        try:
            ts = datetime.strptime(conteudo_raw.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        yield registro, conteudo_raw, ts


# Varre leituras de rele no intervalo informado para encontrar eventos e classifica-los.
def detectar_alertas_rele(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime):
    agrupados = {}
    tem_dados = False
    teve_timeout = False
    max_ts_processado = None

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag or getattr(api, "last_post_day_error", False):
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue

        # Alinhado com a versao funcional (commit 7ac5717): qualquer resposta
        # nao-vazia da API confirma comunicacao com a usina. So marcar como
        # "sem dados" se o intervalo nao tem leituras seria muito restritivo
        # (ex.: usinas com leituras esparsas viravam silenciosas).
        if isinstance(data_resp, list) and data_resp:
            tem_dados = True

        for registro, conteudo_raw, ts in _iterar_registros_api_dia(data_resp, "day_relay", plant_id, logger_rele):
            # Resiliencia a variacoes de capitalizacao/nome (mesmo padrao usado
            # para o inversor com "idinversor"/"Inversor"/"esn").
            idrele = (
                registro.get("idrele")
                or registro.get("idRele")
                or registro.get("IdRele")
                or registro.get("id_rele")
                or conteudo_raw.get("idrele")
                or conteudo_raw.get("Rele")
                or conteudo_raw.get("rele")
            )
            if not idrele:
                continue
            if not (inicio <= ts <= fim):
                continue
            tem_dados = True
            if max_ts_processado is None or ts > max_ts_processado:
                max_ts_processado = ts

            ativos = _extrair_parametros_ativos_rele(conteudo_raw)
            if not ativos:
                # Diagnostico: payload chegou mas nenhum parametro foi reconhecido
                # como ativo. Util para detectar mudanca de contrato da API.
                if conteudo_raw:
                    chaves_inesperadas = [
                        k for k in conteudo_raw
                        if isinstance(k, str)
                        and k.strip().lower() not in RELAY_PARAMETROS_LOOKUP
                        and k.lower().startswith("r")
                    ]
                    if chaves_inesperadas:
                        logger_rele.debug(
                            f"[RELE] Registro sem parametros ativos | usina={plant_id} | "
                            f"rele={idrele} | ts={ts.isoformat()} | "
                            f"chaves_r_desconhecidas={chaves_inesperadas[:10]}"
                        )
                continue

            tipo = "OUTROS"
            for classe, lista in RELAY_PARAMS_CLASSIF.items():
                if any(p in lista for p in ativos):
                    tipo = classe
                    break

            parametros_chave = _normalizar_parametros_rele(ativos)
            base = _chave_evento_rele(plant_id, idrele, tipo, parametros_chave)
            entry = agrupados.get(base)
            if not entry:
                agrupados[base] = {
                    "ts_leitura": ts,
                    "ts_primeiro": ts,
                    "ts_ultimo": ts,
                    "rele_id": idrele,
                    "parametros_set": set(ativos),
                    "parametros_chave": parametros_chave,
                    "tipo_alerta": tipo,
                }
            else:
                if ts < entry["ts_primeiro"]:
                    entry["ts_primeiro"] = ts
                if ts > entry["ts_ultimo"]:
                    entry["ts_ultimo"] = ts
                entry["parametros_set"].update(ativos)
        d += timedelta(days=1)

    if not agrupados:
        return [], tem_dados, teve_timeout, max_ts_processado

    candidatos = []
    for entry in agrupados.values():
        entry["ts_leitura"] = entry["ts_ultimo"]
        entry["parametros"] = ", ".join(sorted(entry.pop("parametros_set")))
        candidatos.append(entry)
    candidatos.sort(key=lambda a: a["ts_leitura"])
    return candidatos, tem_dados, teve_timeout, max_ts_processado


def _horario_esta_na_janela(referencia: datetime, janela_ini_t: dtime, janela_fim_t: dtime) -> bool:
    return janela_ini_t <= referencia.time() <= janela_fim_t


# Avalia leituras de inversores para identificar falha (Pac 0) e recuperacao (Pac != 0).
def detectar_falhas_inversores(
    api: PVOperationAPI,
    plant_id: str,
    inicio: datetime,
    fim: datetime,
    falhas_ativas_previas: dict,
    janela_inicio: dtime = INVERTER_SOLAR_WINDOW_START,
    janela_fim: dtime = INVERTER_SOLAR_WINDOW_END,
):
    leituras_por_inv = {}
    tem_dados = False
    tem_resposta = False
    tem_registro_api = False
    teve_timeout = False
    max_ts_processado = None

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag or getattr(api, "last_post_day_error", False):
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue
        if not isinstance(data_resp, list):
            logger_inv.warning(f"Resposta inesperada em day_inverter (usina {plant_id}): {type(data_resp).__name__}")
            d += timedelta(days=1)
            continue
        tem_resposta = True
        if data_resp:
            tem_registro_api = True

        for reg, conteudo_raw, ts in _iterar_registros_api_dia(data_resp, "day_inverter", plant_id, logger_inv):
            inv_id = reg.get("idinversor") or conteudo_raw.get("Inversor") or conteudo_raw.get("esn")
            if not inv_id:
                continue
            inv_id = str(inv_id)
            if not (inicio <= ts <= fim):
                continue
            if not (janela_inicio <= ts.time() <= janela_fim):
                continue

            pac_raw = None
            for k in ("Pac", "PAC", "Potencia_Saida", "Pout", "Potencia"):
                if k in conteudo_raw:
                    pac_raw = conteudo_raw.get(k)
                    break

            if pac_raw is None:
                leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "pac_zero": False, "sem_dados": True, "pac": None})
                continue

            pac = extrair_valor_numerico(pac_raw)
            if pac is None:
                leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "pac_zero": False, "sem_dados": True, "pac": None})
                continue

            cond = pac <= 0
            leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "pac_zero": cond, "sem_dados": False, "pac": pac})
            tem_dados = True
            if max_ts_processado is None or ts > max_ts_processado:
                max_ts_processado = ts
        d += timedelta(days=1)

    falhas = []
    recuperados = []
    falhas_ativas = {}

    for inv_id, lst in leituras_por_inv.items():
        if not lst:
            continue
        lst.sort(key=lambda x: x["ts"])

        valid_ts = [item["ts"] for item in lst if not item.get("sem_dados")]
        expected_interval = None
        if len(valid_ts) >= 2:
            deltas = [
                valid_ts[i] - valid_ts[i - 1]
                for i in range(1, len(valid_ts))
                if valid_ts[i] > valid_ts[i - 1]
            ]
            if deltas:
                expected_interval = timedelta(seconds=median([d.total_seconds() for d in deltas]))

        state_key = f"{plant_id}:{inv_id}"
        prev_state = falhas_ativas_previas.get(state_key, {"ativa": False, "rec_seq": 0, "seq_zero": 0})
        if isinstance(prev_state, bool):
            prev_state = {"ativa": prev_state, "rec_seq": 0, "seq_zero": 0}
        ativa = bool(prev_state.get("ativa", False))
        rec_seq = int(prev_state.get("rec_seq", 0))
        seq_zero = int(prev_state.get("seq_zero", 0))
        ultima_confirmacao_dt = _parse_iso_datetime(prev_state.get("ultima_confirmacao_ts"))
        last_valid_ts = None

        for item in lst:
            ts = item["ts"]
            if item["sem_dados"]:
                continue
            if last_valid_ts and expected_interval and (ts - last_valid_ts) > (expected_interval * 2):
                seq_zero = 0
                rec_seq = 0

            pac_zero = item["pac_zero"]  # True se potência == 0.0
            if pac_zero:
                seq_zero = seq_zero + 1
                rec_seq = 0
            else:
                seq_zero = 0
                rec_seq = rec_seq + 1
            last_valid_ts = ts

            if seq_zero >= INVERTER_CONSECUTIVE_READINGS and not ativa:
                falhas.append(
                    {
                        "inversor_id": str(inv_id),
                        "ts_leitura": ts,
                        "status": "FALHA",
                        "indicadores": {"pac": item.get("pac", 0.0)},
                    }
                )
                ativa = True
                rec_seq = 0
                ultima_confirmacao_dt = ts

            if ativa and pac_zero:
                ultima_confirmacao_dt = ts

            if ativa and rec_seq >= INVERTER_RECOVERY_CONSECUTIVE_READINGS:
                recuperados.append(
                    {
                        "inversor_id": str(inv_id),
                        "ts_leitura": ts,
                        "status": "NORMALIZADO",
                        "indicadores": {"pac": item.get("pac", None)},
                    }
                )
                ativa = False
                rec_seq = 0
                ultima_confirmacao_dt = None

        falhas_ativas[state_key] = {
            "ativa": ativa,
            "rec_seq": rec_seq,
            "seq_zero": seq_zero,
            "ultima_confirmacao_ts": ultima_confirmacao_dt.isoformat() if ultima_confirmacao_dt else None,
            "tem_dado_valido": any(not item.get("sem_dados") for item in lst),
        }

    # Fora do horario ativo do inversor, lista vazia nao deve virar SEM_DADOS
    # so porque o checkpoint por max_ts ainda encosta na cauda da janela solar.
    fim_dentro_janela = _horario_esta_na_janela(fim, janela_inicio, janela_fim)
    resposta_vazia_fora_janela = tem_resposta and not tem_registro_api and not fim_dentro_janela
    tem_dados_efetivo = tem_dados or resposta_vazia_fora_janela
    return falhas, recuperados, tem_dados_efetivo, falhas_ativas, teve_timeout, max_ts_processado


def _plant_ids_retornados(plantas):
    ids = set()
    for p in plantas or []:
        try:
            ids.add(str(int(p.get("id"))))
        except (TypeError, ValueError):
            continue
    return ids


def _serial_inversor_de_chave(chave_inv, usina_id: str) -> str | None:
    prefixo = f"{usina_id}:"
    if not isinstance(chave_inv, str) or not chave_inv.startswith(prefixo):
        return None
    serial = chave_inv[len(prefixo):].strip()
    return serial or None


def _inversores_sem_dados_para_log(usina_id: str, falhas_ativas_atual: dict, estado_inversores: dict) -> list[str | None]:
    seriais = []
    for fonte in (falhas_ativas_atual, estado_inversores):
        if not isinstance(fonte, dict):
            continue
        for chave_inv in fonte:
            serial = _serial_inversor_de_chave(chave_inv, usina_id)
            if serial and serial not in seriais:
                seriais.append(serial)
        if seriais:
            break
    return seriais or [None]


def _mensagem_sem_dados_inversor(usina_nome, inversor_serial: str | None, motivo: str) -> str:
    usina_txt = str(usina_nome) if usina_nome else "N/A"
    if inversor_serial:
        inversor_txt = f'"{inversor_serial}"'
    else:
        inversor_txt = "não identificado"
    return f'Sem dados de inversor em "{usina_txt}" - Inversor: {inversor_txt} (motivo: {motivo}).'


def _normalizar_campo_chave_rele(valor) -> str:
    return re.sub(r"\s+", " ", str(valor or "").strip()).lower()


def _normalizar_parametros_rele(parametros) -> str:
    if parametros is None:
        partes = []
    elif isinstance(parametros, str):
        partes = parametros.split("|", 1)[0].split(",")
    else:
        partes = list(parametros)
    normalizados = {
        _normalizar_campo_chave_rele(p)
        for p in partes
        if _normalizar_campo_chave_rele(p)
    }
    return ",".join(sorted(normalizados))


def _chave_evento_rele(usina_id, rele_id, tipo_alerta, parametros) -> str:
    return ":".join([
        _normalizar_campo_chave_rele(usina_id),
        _normalizar_campo_chave_rele(rele_id),
        _normalizar_campo_chave_rele(tipo_alerta),
        _normalizar_parametros_rele(parametros),
    ])


def _chave_legada_rele(usina_id, rele_id, tipo_alerta) -> str:
    return ":".join([
        _normalizar_campo_chave_rele(usina_id),
        _normalizar_campo_chave_rele(rele_id),
        _normalizar_campo_chave_rele(tipo_alerta),
    ])


def _partes_chave_rele(base: str) -> tuple[str, str, str, str]:
    partes = str(base or "").split(":", 3)
    if len(partes) == 4:
        return partes[0], partes[1], partes[2], partes[3]
    if len(partes) == 3:
        return partes[0], partes[1], partes[2], ""
    return "N/A", str(base), "OUTROS", ""


def _dedupe_por_base(itens: list) -> list:
    vistos = set()
    saida = []
    for item in itens:
        base = item.get("base")
        if base and base in vistos:
            continue
        if base:
            vistos.add(base)
        saida.append(item)
    return saida


def _alerta_ts_key(item: dict) -> datetime:
    ts = item.get("ts_iso")
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min


def _compor_entrada_estado_inversor(prev_entry: dict, estado_novo: dict, tem_dado_valido: bool) -> EstadoInversor:
    entry = {
        "ativa": bool(estado_novo.get("ativa", False)),
        "rec_seq": int(estado_novo.get("rec_seq", 0)),
        "seq_zero": int(estado_novo.get("seq_zero", 0)),
        "alerta": prev_entry.get("alerta"),
        "notificado": bool(prev_entry.get("notificado", False)),
        "ausente_scans": (
            0 if tem_dado_valido
            else int(prev_entry.get("ausente_scans", 0))
        ),
        "ultima_confirmacao_ts": (
            estado_novo.get("ultima_confirmacao_ts")
            if tem_dado_valido
            else prev_entry.get("ultima_confirmacao_ts")
        ),
    }
    if not entry["ativa"]:
        entry["alerta"] = None
        entry["notificado"] = False
        entry["ultima_confirmacao_ts"] = None
    return entry


def _montar_alerta_inversor(item: dict, nome: str, cap, janela_label_inv: str) -> dict:
    return {
        "usina": nome,
        "capacidade": cap,
        "inversor": item["inversor_id"],
        "horario": item["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
        "ts_iso": item["ts_leitura"].isoformat(),
        "status": item["status"],
        "indicadores": item.get("indicadores", {}),
        "janela_solar_label": janela_label_inv,
    }


# Servico central que orquestra varreduras de reles/inversores e envia notificacoes.
class MonitorService:
    """Serviço headless: varre relés e inversores e notifica Teams."""

    def _init_state_defaults(self):
        self.ultima_varredura_rele = None
        self.ultima_varredura_inversor = None
        self.ultima_varredura_rele_por_usina = {}
        self.ultima_varredura_inversor_por_usina = {}
        self.rele_alertas_ativos = set()      # usina:rele:tipo:parametros
        self.rele_alerta_chave = {}
        self.rele_notificados = set()
        self.rele_notificacao_retry_after = {}
        self.estado_inversores = {}           # usina:inv -> estado (seq + alerta)
        self.pending_notifications = {"rele_normalizados": {}, "inv_normalizados": {}}
        self.usinas_alerta_rele_recente = set()
        self.incidentes_rele_ativos = {}      # base rele -> incidente aberto
        self.incidentes_inv_ativos = {}       # usina:inv -> incidente aberto
        self.historico_incidentes = []        # incidentes concluídos (relé e inversor)
        self.last_weekly_report_id = None
        self._last_historico_cleanup = None   # throttle: evita varredura completa a cada save
        self._plants_cache = None             # cache da lista de usinas entre relay e inversor scan
        self._plants_cache_ts = None

    # Prepara estado inicial do servico e caches de alertas.
    def __init__(self, api_rele: PVOperationAPI, api_inversor: PVOperationAPI = None):
        self.api_rele = api_rele
        self.api_inversor = api_inversor or api_rele
        self._init_state_defaults()
        self.stop_event = threading.Event()
        self._lock_fd = None
        self._state_lock = threading.Lock()
        self._threads = []
        self._scan_lock = threading.Lock()
        self._save_state_fail_count = 0

    # Inicia o monitor em modo daemon criando threads de varredura.
    def start(self):
        self._acquire_lock()
        self._load_state()
        atexit.register(self._shutdown_cleanup)
        self._threads = [
            threading.Thread(target=self._loop_scans, daemon=True),
            threading.Thread(target=self._loop_heartbeat, daemon=True),
            threading.Thread(target=self._loop_weekly_report, daemon=True),
        ]
        for t in self._threads:
            t.start()

    # Executa cleanup ao sair do processo (atexit) com as mesmas garantias do stop().
    def _shutdown_cleanup(self):
        if self.stop_event.is_set():
            return
        try:
            self.stop()
        except Exception:
            logger.exception("Falha no shutdown atexit")

    # Encerra o monitor sinalizando parada e salvando estado.
    def stop(self):
        self.stop_event.set()
        threads_vivas = []
        for t in self._threads:
            t.join(timeout=STOP_JOIN_TIMEOUT)
            if t.is_alive():
                logger.warning(f"Thread ainda ativa apos timeout de stop: {t.name}")
                threads_vivas.append(t)
        if threads_vivas:
            logger.warning("Threads ainda ativas; forçando persistência e liberação do lock.")
        acquired_scan = False
        try:
            acquired_scan = self._scan_lock.acquire(timeout=1)
            if not acquired_scan:
                logger.warning("Nao foi possivel obter scan lock para snapshot; salvando estado mesmo assim.")
            self._save_state()
        finally:
            if acquired_scan:
                self._scan_lock.release()
            self._release_lock()

    # Cria lock de arquivo para evitar multiplas instancias simultaneas.
    def _acquire_lock(self):
        try:
            self._lock_fd = open(LOCK_FILE, "a+")
            self._lock_fd.seek(0)
            if os.name == "nt":
                if not msvcrt:
                    raise RuntimeError("Lock de Windows não disponível (msvcrt ausente).")
                try:
                    msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise BlockingIOError("Lock já ativa em Windows.")
            else:
                if not fcntl:
                    raise RuntimeError("Lock de Unix não disponível (fcntl ausente).")
                fcntl.lockf(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd.seek(0)
            self._lock_fd.truncate(0)
            self._lock_fd.write(str(os.getpid()))
            self._lock_fd.flush()
        except BlockingIOError:
            logger.error("Já existe uma instância em execução (lock ativo). Encerrando.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Não foi possível criar lock de instância única: {e}")
            sys.exit(1)

    # Libera o lock de arquivo ao finalizar execucao.
    def _release_lock(self):
        try:
            if self._lock_fd:
                if os.name == "nt" and msvcrt:
                    try:
                        msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                elif fcntl:
                    try:
                        fcntl.lockf(self._lock_fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                self._lock_fd.close()
                self._lock_fd = None
        except Exception:
            pass

    def _backup_corrupt_state(self, reason: str) -> Path | None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = STATE_FILE.with_name(f"{STATE_FILE.name}.corrupt.{ts}")
        try:
            os.replace(STATE_FILE, backup_path)
            logger.warning(f"State corrompido detectado ({reason}); backup criado em: {backup_path}")
            return backup_path
        except Exception as e:
            logger.warning(f"Falha ao criar backup do state corrompido: {e}")
            return None

    def _detectar_lista_parcial(self, plantas: list, checkpoint_dict: dict, chaves_estado, logger_ctx, contexto: str) -> set:
        ids_retornados = _plant_ids_retornados(plantas)
        usinas_esperadas = set(checkpoint_dict) | {chave.split(":", 1)[0] for chave in chaves_estado}
        ausentes = usinas_esperadas - ids_retornados
        if ausentes:
            logger_ctx.warning(f"Lista parcial de usinas ({contexto}); ausentes: {sorted(ausentes)}")
        return ausentes

    def _obter_plantas(self, api, logger_ctx, contexto: str) -> tuple:
        agora = datetime.now()
        if (
            self._plants_cache is not None
            and self._plants_cache_ts is not None
            and (agora - self._plants_cache_ts) < PLANTS_CACHE_TTL
        ):
            plantas = self._plants_cache
        else:
            plantas = api.get_plants()
            if plantas is not None:  # None = erro → não cachear
                self._plants_cache = list(plantas)
                self._plants_cache_ts = agora
        if plantas is None:
            motivo = "TIMEOUT" if api.last_get_plants_timeout else "ERRO_API"
            logger_ctx.warning(f"Erro ao buscar plantas ({contexto}). Motivo: {motivo}.")
            return [], True
        if not plantas:
            logger_ctx.warning(f"Nenhuma usina encontrada ({contexto}).")
            return [], True
        return list(plantas), False

    def _fechar_incidente(self, incidente: dict, fim_ts: datetime):
        inicio_dt = _parse_iso_datetime(incidente.get("inicio_ts")) or fim_ts
        fim_dt    = fim_ts if isinstance(fim_ts, datetime) else datetime.now()
        if fim_dt < inicio_dt:
            fim_dt = inicio_dt
        finalizado = dict(incidente)
        finalizado["fim_ts"] = fim_dt.isoformat()
        self.historico_incidentes.append(finalizado)

    @staticmethod
    def _carregar_incidentes_ativos(raw, natureza_default: str, tipo_falha_default: str) -> dict:
        if not isinstance(raw, dict):
            return {}
        resultado = {}
        for chave, item in raw.items():
            if not isinstance(item, dict) or not item.get("inicio_ts"):
                continue
            resultado[str(chave)] = {
                "chave":       str(item.get("chave",       chave)),
                "natureza":    str(item.get("natureza",    natureza_default)),
                "tipo_falha":  str(item.get("tipo_falha",  tipo_falha_default)),
                "usina_id":    str(item.get("usina_id",    "")),
                "usina":       item.get("usina"),
                "equipamento": str(item.get("equipamento", "")),
                "inicio_ts":   str(item.get("inicio_ts")),
            }
        return resultado

    @staticmethod
    def _carregar_varredura_por_usina(raw) -> dict:
        if not isinstance(raw, dict):
            return {}
        resultado = {}
        for usina_id, ts in raw.items():
            if not ts:
                continue
            try:
                resultado[str(usina_id)] = datetime.fromisoformat(ts)
            except Exception:
                continue
        return resultado

    def _limitar_pendencias(self):
        pend_rele = self.pending_notifications.get("rele_normalizados", {})
        if isinstance(pend_rele, dict):
            for usina_id, itens in list(pend_rele.items()):
                if not isinstance(itens, list):
                    continue
                if len(itens) > MAX_PENDING_RELE_POR_USINA:
                    pend_rele[usina_id] = itens[-MAX_PENDING_RELE_POR_USINA:]
        pend_inv = self.pending_notifications.get("inv_normalizados", {})
        if isinstance(pend_inv, dict) and len(pend_inv) > MAX_PENDING_INV:
            for chave in list(pend_inv.keys())[:-MAX_PENDING_INV]:
                pend_inv.pop(chave, None)

    def _limitar_historico_incidentes(self):
        if not isinstance(self.historico_incidentes, list):
            self.historico_incidentes = []
            return
        # Truncamento de tamanho: sempre aplicado
        if len(self.historico_incidentes) > MAX_INCIDENT_HISTORY:
            self.historico_incidentes = self.historico_incidentes[-MAX_INCIDENT_HISTORY:]
        # Limpeza por data: throttled para 1×/hora (custo linear com 10k itens)
        agora = datetime.now()
        if (
            self._last_historico_cleanup is not None
            and (agora - self._last_historico_cleanup) < timedelta(hours=1)
        ):
            return
        self._last_historico_cleanup = agora
        limite = agora - timedelta(days=INCIDENT_RETENTION_DAYS)
        saida = []
        for item in self.historico_incidentes:
            if not isinstance(item, dict):
                continue
            fim_dt = _parse_iso_datetime(item.get("fim_ts"))
            if fim_dt and fim_dt < limite:
                continue
            saida.append(item)
        self.historico_incidentes = saida[-MAX_INCIDENT_HISTORY:]

    @staticmethod
    def _novo_incidente(base_key: str, natureza: str, tipo_falha: str, usina_id: str, usina: str | None, equipamento: str, inicio_ts: datetime, fim_ts: str | None = None) -> Incidente:
        inicio = inicio_ts if isinstance(inicio_ts, datetime) else datetime.now()
        return {
            "chave": str(base_key),
            "natureza": str(natureza),
            "tipo_falha": str(tipo_falha),
            "usina_id": str(usina_id),
            "usina": usina or f"Usina {usina_id}",
            "equipamento": str(equipamento),
            "inicio_ts": inicio.isoformat(),
            "fim_ts": fim_ts,
        }

    def _registrar_inicio_incidente_rele(self, base: str, usina_id: str, usina: str, rele_id: str, tipo_falha: str, inicio_ts: datetime):
        if base not in self.incidentes_rele_ativos:
            self.incidentes_rele_ativos[base] = self._novo_incidente(
                base_key=base,
                natureza="RELE",
                tipo_falha=tipo_falha,
                usina_id=usina_id,
                usina=usina,
                equipamento=rele_id,
                inicio_ts=inicio_ts,
            )

    def _registrar_fim_incidente_rele(self, base: str, fim_ts: datetime, fallback_alerta=None):
        incidente = self.incidentes_rele_ativos.pop(base, None)
        if incidente is None:
            alerta = fallback_alerta if isinstance(fallback_alerta, dict) else {}
            usina_id, rele_id, tipo, _ = _partes_chave_rele(base)
            inicio_dt = _parse_iso_datetime(alerta.get("ts_iso")) or fim_ts
            incidente = self._novo_incidente(
                base_key=base,
                natureza="RELE",
                tipo_falha=alerta.get("tipo", tipo),
                usina_id=usina_id,
                usina=alerta.get("usina"),
                equipamento=alerta.get("rele", rele_id),
                inicio_ts=inicio_dt,
            )
        self._fechar_incidente(incidente, fim_ts)

    def _migrar_chave_rele_ativa(self, chave_antiga: str, chave_nova: str) -> None:
        if not chave_antiga or chave_antiga == chave_nova:
            return
        migrado = False
        if chave_antiga in self.rele_alertas_ativos:
            self.rele_alertas_ativos.discard(chave_antiga)
            self.rele_alertas_ativos.add(chave_nova)
            migrado = True
        if chave_antiga in self.rele_notificados:
            self.rele_notificados.discard(chave_antiga)
            self.rele_notificados.add(chave_nova)
            migrado = True
        retry_after = self.rele_notificacao_retry_after.pop(chave_antiga, None)
        if retry_after is not None:
            self.rele_notificacao_retry_after.setdefault(chave_nova, retry_after)
            migrado = True
        alerta_antigo = self.rele_alerta_chave.pop(chave_antiga, None)
        if alerta_antigo is not None:
            if chave_nova not in self.rele_alerta_chave:
                self.rele_alerta_chave[chave_nova] = alerta_antigo
            migrado = True
        incidente = self.incidentes_rele_ativos.pop(chave_antiga, None)
        if incidente is not None:
            if chave_nova not in self.incidentes_rele_ativos:
                incidente["chave"] = chave_nova
                self.incidentes_rele_ativos[chave_nova] = incidente
            migrado = True
        if migrado:
            logger_rele.info(f"[RELE] Chave legada migrada | antiga={chave_antiga} | nova={chave_nova}")

    def _resolver_alerta_rele(self, base: str, fim_ts: datetime) -> dict | None:
        alerta_antigo = self.rele_alerta_chave.get(base)
        self.rele_alertas_ativos.discard(base)
        self.rele_alerta_chave.pop(base, None)
        self.rele_notificados.discard(base)
        self.rele_notificacao_retry_after.pop(base, None)
        self._registrar_fim_incidente_rele(base=base, fim_ts=fim_ts, fallback_alerta=alerta_antigo)
        return alerta_antigo

    def _retry_rele_adiado(self, base: str, agora: datetime) -> bool:
        retry_after = _parse_iso_datetime(self.rele_notificacao_retry_after.get(base))
        if retry_after is None:
            self.rele_notificacao_retry_after.pop(base, None)
            return False
        return agora < retry_after

    def _agendar_retry_rele(self, base: str, agora: datetime) -> None:
        retry_after = agora + RELAY_NOTIFICATION_RETRY_COOLDOWN
        self.rele_notificacao_retry_after[base] = retry_after.isoformat()

    def _ativar_alerta_rele(
        self,
        base: str,
        alerta_fmt: dict,
        *,
        usina_id: str,
        nome: str | None,
        rele_id: str,
        tipo_alerta: str,
        inicio_ts: datetime,
    ) -> None:
        self.rele_alertas_ativos.add(base)
        self.rele_alerta_chave[base] = alerta_fmt
        self._registrar_inicio_incidente_rele(
            base=base,
            usina_id=usina_id,
            usina=nome,
            rele_id=rele_id,
            tipo_falha=tipo_alerta,
            inicio_ts=inicio_ts,
        )

    def _registrar_inicio_incidente_inversor(self, chave_inv: str, usina_id: str, usina: str, inversor_id: str, inicio_ts: datetime):
        if chave_inv not in self.incidentes_inv_ativos:
            self.incidentes_inv_ativos[chave_inv] = self._novo_incidente(
                base_key=chave_inv,
                natureza="INVERSOR",
                tipo_falha=INVERTER_FAILURE_LABEL,
                usina_id=usina_id,
                usina=usina,
                equipamento=inversor_id,
                inicio_ts=inicio_ts,
            )

    def _registrar_fim_incidente_inversor(self, chave_inv: str, fim_ts: datetime, alerta_prev=None, usina_id=None):
        incidente = self.incidentes_inv_ativos.pop(chave_inv, None)
        if incidente is None:
            alerta = alerta_prev if isinstance(alerta_prev, dict) else {}
            fallback_usina_id = usina_id or (chave_inv.split(":", 1)[0] if ":" in chave_inv else "N/A")
            fallback_inv = chave_inv.split(":", 1)[1] if ":" in chave_inv else chave_inv
            inicio_dt = _parse_iso_datetime(alerta.get("ts_iso")) or fim_ts
            incidente = self._novo_incidente(
                base_key=chave_inv,
                natureza="INVERSOR",
                tipo_falha=INVERTER_FAILURE_LABEL,
                usina_id=fallback_usina_id,
                usina=alerta.get("usina"),
                equipamento=alerta.get("inversor", fallback_inv),
                inicio_ts=inicio_dt,
            )
        self._fechar_incidente(incidente, fim_ts)

    def _reconciliar_inversores_ausentes(self, usina_id: str, chaves_observadas):
        if not usina_id:
            return
        observadas = {str(chave) for chave in (chaves_observadas or []) if chave}
        for chave_inv, estado in list(self.estado_inversores.items()):
            if not isinstance(estado, dict):
                continue
            if not chave_inv.startswith(f"{usina_id}:"):
                continue
            if chave_inv in observadas:
                if int(estado.get("ausente_scans", 0)):
                    estado["ausente_scans"] = 0
                    self.estado_inversores[chave_inv] = estado
                continue
            if not estado.get("ativa"):
                if int(estado.get("ausente_scans", 0)):
                    estado["ausente_scans"] = 0
                    self.estado_inversores[chave_inv] = estado
                continue

            ausente_scans = int(estado.get("ausente_scans", 0)) + 1
            if ausente_scans < INVERTER_MISSING_SCAN_TOLERANCE:
                estado["ausente_scans"] = ausente_scans
                self.estado_inversores[chave_inv] = estado
                continue

            if estado.get("ultima_confirmacao_ts") is not None:
                logger_inv.warning(
                    f"Inversor {chave_inv} ausente em {ausente_scans} varreduras validas; suprimindo do heartbeat."
                )
                estado["ultima_confirmacao_ts"] = None
            estado["ausente_scans"] = ausente_scans
            self.estado_inversores[chave_inv] = estado

    # Carrega estado de ultima varredura e listas de alertas persistidos em disco.
    def _load_state(self):
        if not STATE_FILE.exists():
            self._init_state_defaults()
            self._save_state()
            return
        try:
            self._init_state_defaults()
            raw = STATE_FILE.read_text(encoding="utf-8")
            if not raw.strip():
                raise ValueError("state vazio")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("state inválido")
            schema_version = data.get("schema_version")
            if schema_version not in (None, STATE_SCHEMA_VERSION):
                raise ValueError(
                    f"schema inválido: {schema_version} (esperado {STATE_SCHEMA_VERSION})"
                )
            self.ultima_varredura_rele = (
                datetime.fromisoformat(data.get("ultima_varredura_rele"))
                if data.get("ultima_varredura_rele") else None
            )
            self.ultima_varredura_inversor = (
                datetime.fromisoformat(data.get("ultima_varredura_inversor"))
                if data.get("ultima_varredura_inversor") else None
            )
            self.ultima_varredura_rele_por_usina = self._carregar_varredura_por_usina(
                data.get("ultima_varredura_rele_por_usina", {})
            )
            self.ultima_varredura_inversor_por_usina = self._carregar_varredura_por_usina(
                data.get("ultima_varredura_inversor_por_usina", {})
            )
            self.rele_alertas_ativos = set(data.get("rele_alertas_ativos", []))
            self.rele_notificados = set(data.get("rele_notificados", []))
            self.rele_notificacao_retry_after = {}
            raw_retry_rele = data.get("rele_notificacao_retry_after", {})
            if isinstance(raw_retry_rele, dict):
                for base, retry_after in raw_retry_rele.items():
                    if _parse_iso_datetime(retry_after) is not None:
                        self.rele_notificacao_retry_after[str(base)] = str(retry_after)
            self.rele_alerta_chave = data.get("rele_alerta_chave", {})
            self.estado_inversores = {}
            self.pending_notifications = {"rele_normalizados": {}, "inv_normalizados": {}}
            pending = data.get("pending_notifications", {})
            if isinstance(pending, dict):
                rele_norm = pending.get("rele_normalizados", {})
                if isinstance(rele_norm, dict):
                    for usina_id, itens in rele_norm.items():
                        if isinstance(itens, list):
                            cleaned = [i for i in itens if isinstance(i, dict)]
                            if cleaned:
                                self.pending_notifications["rele_normalizados"][str(usina_id)] = cleaned
                inv_norm = pending.get("inv_normalizados", {})
                if isinstance(inv_norm, dict):
                    for chave, payload in inv_norm.items():
                        if isinstance(payload, dict):
                            self.pending_notifications["inv_normalizados"][str(chave)] = payload
            self.last_weekly_report_id = data.get("last_weekly_report_id")
            if self.last_weekly_report_id is not None:
                self.last_weekly_report_id = str(self.last_weekly_report_id)

            self.historico_incidentes = []
            raw_historico = data.get("historico_incidentes", [])
            if isinstance(raw_historico, list):
                for item in raw_historico:
                    if not isinstance(item, dict):
                        continue
                    if not item.get("inicio_ts"):
                        continue
                    self.historico_incidentes.append(
                        {
                            "chave": str(item.get("chave", "")),
                            "natureza": str(item.get("natureza", "")),
                            "tipo_falha": str(item.get("tipo_falha", "")),
                            "usina_id": str(item.get("usina_id", "")),
                            "usina": item.get("usina"),
                            "equipamento": str(item.get("equipamento", "")),
                            "inicio_ts": str(item.get("inicio_ts")),
                            "fim_ts": str(item.get("fim_ts")) if item.get("fim_ts") else None,
                        }
                    )

            self.incidentes_rele_ativos = self._carregar_incidentes_ativos(
                data.get("incidentes_rele_ativos", {}), "RELE", ""
            )
            self.incidentes_inv_ativos = self._carregar_incidentes_ativos(
                data.get("incidentes_inv_ativos", {}), "INVERSOR", INVERTER_FAILURE_LABEL
            )

            def _legacy_key_to_estado(chave: str) -> str:
                if not isinstance(chave, str):
                    return str(chave)
                if ":" in chave:
                    return chave
                if "_" in chave:
                    usina, inv = chave.split("_", 1)
                    return f"{usina}:{inv}"
                return chave

            def _is_notificado(chave: str, legado: set) -> bool:
                if chave in legado:
                    return True
                if ":" in chave and chave.replace(":", "_") in legado:
                    return True
                return False

            raw_estado = data.get("estado_inversores")
            if isinstance(raw_estado, dict):
                for chave, estado in raw_estado.items():
                    if isinstance(estado, bool):
                        estado = {"ativa": estado}
                    if not isinstance(estado, dict):
                        continue
                    self.estado_inversores[str(chave)] = {
                        "ativa": bool(estado.get("ativa", False)),
                        "rec_seq": int(estado.get("rec_seq", 0)),
                        "seq_zero": int(estado.get("seq_zero", 0)),
                        "alerta": estado.get("alerta"),
                        "notificado": bool(estado.get("notificado", False)),
                        "ausente_scans": int(estado.get("ausente_scans", 0)),
                        "ultima_confirmacao_ts": estado.get("ultima_confirmacao_ts"),
                    }
            else:
                raw_falhas = data.get("falhas_ativas_por_inv", {})
                raw_alertas = data.get("inversores_ativos", {})
                raw_notificados = set(data.get("inv_notificados", []))
                if isinstance(raw_falhas, dict):
                    for chave, estado in raw_falhas.items():
                        if isinstance(estado, bool):
                            estado = {"ativa": estado}
                        if not isinstance(estado, dict):
                            continue
                        estado_key = _legacy_key_to_estado(str(chave))
                        self.estado_inversores[estado_key] = {
                            "ativa": bool(estado.get("ativa", False)),
                            "rec_seq": int(estado.get("rec_seq", 0)),
                            "seq_zero": int(estado.get("seq_zero", 0)),
                            "alerta": None,
                            "notificado": _is_notificado(estado_key, raw_notificados),
                            "ausente_scans": int(estado.get("ausente_scans", 0)),
                            "ultima_confirmacao_ts": estado.get("ultima_confirmacao_ts"),
                        }
                if isinstance(raw_alertas, dict):
                    for chave, alerta in raw_alertas.items():
                        estado_key = _legacy_key_to_estado(str(chave))
                        entry = self.estado_inversores.get(
                            estado_key,
                            {"ativa": True, "rec_seq": 0, "seq_zero": 0, "alerta": None, "notificado": False},
                        )
                        entry["alerta"] = alerta
                        entry["notificado"] = entry.get("notificado", False) or _is_notificado(estado_key, raw_notificados)
                        entry["ausente_scans"] = int(entry.get("ausente_scans", 0))
                        entry["ultima_confirmacao_ts"] = entry.get("ultima_confirmacao_ts")
                        self.estado_inversores[estado_key] = entry

            for chave, estado in self.estado_inversores.items():
                if (
                    estado.get("ativa")
                    and _parse_iso_datetime(estado.get("ultima_confirmacao_ts")) is None
                    and int(estado.get("ausente_scans", 0)) < INVERTER_MISSING_SCAN_TOLERANCE
                ):
                    usina_id = chave.split(":", 1)[0] if ":" in chave else None
                    if usina_id:
                        varredura_dt = self.ultima_varredura_inversor_por_usina.get(str(usina_id))
                        if varredura_dt:
                            estado["ultima_confirmacao_ts"] = varredura_dt.isoformat()

            for base in list(self.rele_alertas_ativos):
                if base in self.incidentes_rele_ativos:
                    continue
                if not isinstance(base, str) or ":" not in base:
                    continue
                usina_id, rele_id, tipo, _ = _partes_chave_rele(base)
                alerta = self.rele_alerta_chave.get(base, {})
                inicio = _parse_iso_datetime(alerta.get("ts_iso")) or datetime.now()
                self.incidentes_rele_ativos[base] = self._novo_incidente(
                    base_key=base,
                    natureza="RELE",
                    tipo_falha=alerta.get("tipo", tipo),
                    usina_id=usina_id,
                    usina=alerta.get("usina"),
                    equipamento=alerta.get("rele", rele_id),
                    inicio_ts=inicio,
                )

            for chave_inv, estado in self.estado_inversores.items():
                if not isinstance(estado, dict):
                    continue
                if not estado.get("ativa"):
                    continue
                if chave_inv in self.incidentes_inv_ativos:
                    continue
                usina_id = chave_inv.split(":", 1)[0] if ":" in chave_inv else "N/A"
                inv_id = chave_inv.split(":", 1)[1] if ":" in chave_inv else chave_inv
                alerta = estado.get("alerta") if isinstance(estado.get("alerta"), dict) else {}
                inicio = _parse_iso_datetime(alerta.get("ts_iso")) or datetime.now()
                self.incidentes_inv_ativos[chave_inv] = self._novo_incidente(
                    base_key=chave_inv,
                    natureza="INVERSOR",
                    tipo_falha=INVERTER_FAILURE_LABEL,
                    usina_id=usina_id,
                    usina=alerta.get("usina"),
                    equipamento=alerta.get("inversor", inv_id),
                    inicio_ts=inicio,
                )
            # recalcula usinas com rele ativo a partir do estado persistido
            self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}
            self._limitar_pendencias()
            self._limitar_historico_incidentes()
            logger.info("Estado carregado do disco.")
        except (json.JSONDecodeError, ValueError) as e:
            self._backup_corrupt_state(str(e))
            self._init_state_defaults()
            self._save_state()
        except Exception as e:
            self._backup_corrupt_state(f"erro inesperado ao carregar state: {e}")
            self._init_state_defaults()
            logger.warning(f"Não foi possível carregar estado salvo: {e}")

    # Salva em disco o ponto de controle atual das varreduras e alertas ativos.
    def _save_state(self):
        try:
            self._limitar_pendencias()
            self._limitar_historico_incidentes()
            payload = {
                "schema_version": STATE_SCHEMA_VERSION,
                "ultima_varredura_rele": self.ultima_varredura_rele.isoformat() if self.ultima_varredura_rele else None,
                "ultima_varredura_inversor": self.ultima_varredura_inversor.isoformat() if self.ultima_varredura_inversor else None,
                "ultima_varredura_rele_por_usina": {
                    str(k): v.isoformat() if v else None for k, v in self.ultima_varredura_rele_por_usina.items()
                },
                "ultima_varredura_inversor_por_usina": {
                    str(k): v.isoformat() if v else None for k, v in self.ultima_varredura_inversor_por_usina.items()
                },
                "rele_alertas_ativos": list(self.rele_alertas_ativos),
                "rele_notificados": list(self.rele_notificados),
                "rele_notificacao_retry_after": self.rele_notificacao_retry_after,
                "rele_alerta_chave": self.rele_alerta_chave,
                "estado_inversores": self.estado_inversores,
                "pending_notifications": self.pending_notifications,
                "incidentes_rele_ativos": self.incidentes_rele_ativos,
                "incidentes_inv_ativos": self.incidentes_inv_ativos,
                "historico_incidentes": self.historico_incidentes,
                "last_weekly_report_id": self.last_weekly_report_id,
            }
            tmp_path = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
            with self._state_lock:
                tmp_path.write_text(json.dumps(payload), encoding="utf-8")
                os.replace(tmp_path, STATE_FILE)
            self._save_state_fail_count = 0
        except Exception as e:
            self._save_state_fail_count += 1
            logger.warning(f"Falha ao salvar estado: {e}")
            if self._save_state_fail_count == SAVE_STATE_FAIL_THRESHOLD:
                _teams_post_card(
                    title="Monitor: falha ao salvar estado",
                    text=(
                        f"Estado não persistido por {self._save_state_fail_count} "
                        f"tentativas consecutivas. Verifique disco/permissões. Erro: {e}"
                    ),
                    severity="danger",
                    facts=None,
                )

    # Loop central que coordena varreduras de relé e inversor em ordem determinística.
    def _loop_scans(self):
        next_rele = datetime.now()
        next_inv = datetime.now()
        while not self.stop_event.is_set():
            agora = datetime.now()
            if agora >= next_rele:
                try:
                    self.executar_varredura_rele()
                except Exception:
                    logger.exception("Erro na varredura de relé")
                next_rele = datetime.now() + timedelta(seconds=RELAY_INTERVAL)

            if self.stop_event.is_set():
                break

            agora = datetime.now()
            if agora >= next_inv:
                try:
                    self.executar_varredura_inversor()
                except Exception:
                    logger_inv.exception("Erro na varredura de inversor")
                next_inv = datetime.now() + timedelta(seconds=INVERTER_INTERVAL)

            proximo = min(next_rele, next_inv)
            espera = max(1, (proximo - datetime.now()).total_seconds())
            if self.stop_event.wait(espera):
                break

    # Loop de heartbeat para enviar notificacao em horarios fixos.
    def _loop_heartbeat(self):
        while not self.stop_event.is_set():
            agora = datetime.now()
            proximo = self._proximo_horario_heartbeat(agora)
            espera = max(1, (proximo - agora).total_seconds())
            if self.stop_event.wait(espera):
                break
            try:
                self._enviar_heartbeat(proximo)
            except Exception:
                logger.exception("Erro ao enviar heartbeat")

    # Loop dedicado para gerar relatório semanal de forma automática.
    def _loop_weekly_report(self):
        while not self.stop_event.is_set():
            try:
                self._gerar_relatorio_semanal_se_pendente()
            except Exception:
                logger.exception("Erro ao gerar relatorio semanal")
            if self.stop_event.wait(WEEKLY_REPORT_CHECK_INTERVAL):
                break

    @staticmethod
    def _inicio_semana(dt_ref: datetime) -> datetime:
        return datetime.combine(dt_ref.date() - timedelta(days=dt_ref.weekday()), datetime.min.time())

    def _periodo_relatorio_pendente(self, agora: datetime):
        inicio_semana_atual = self._inicio_semana(agora)
        liberacao = datetime.combine(inicio_semana_atual.date(), WEEKLY_REPORT_GENERATION_TIME)
        if agora < liberacao:
            return None
        inicio_semana_relatorio = inicio_semana_atual - timedelta(days=7)
        report_id = inicio_semana_relatorio.date().isoformat()
        if self.last_weekly_report_id == report_id:
            return None
        return inicio_semana_relatorio, inicio_semana_atual, report_id

    @staticmethod
    def _fmt_ts(valor):
        if isinstance(valor, datetime):
            return valor.strftime("%d/%m/%Y %H:%M:%S")
        return ""

    def _classificar_rele_conteudo_relatorio(self, conteudo):
        identidade = self._identidade_rele_conteudo_relatorio(conteudo)
        if not identidade:
            return None
        tipo, _ = identidade
        return tipo

    def _identidade_rele_conteudo_relatorio(self, conteudo):
        if not isinstance(conteudo, dict):
            return None
        ativos = _extrair_parametros_ativos_rele(conteudo)
        if not ativos:
            return None
        tipo = "OUTROS"
        for classe, lista in RELAY_PARAMS_CLASSIF.items():
            if any(p in lista for p in ativos):
                tipo = classe
                break
        return tipo, _normalizar_parametros_rele(ativos)

    def _coletar_incidentes_rele_semana_api(self, usina_id: str, usina_nome: str, inicio_semana: datetime, fim_semana: datetime):
        inicio_busca = inicio_semana - timedelta(days=WEEKLY_REPORT_WARMUP_DAYS)
        fim_busca = fim_semana - timedelta(seconds=1)
        leituras_por_rele = defaultdict(list)

        dia = inicio_busca.date()
        while dia <= fim_busca.date():
            data_resp, timeout_flag = self.api_rele.post_day("day_relay", int(usina_id), datetime.combine(dia, datetime.min.time()))
            if timeout_flag:
                logger_rele.warning(
                    f"Timeout parcial no backfill semanal de rele (usina {usina_id}, dia {dia})."
                )
            if data_resp is None:
                dia += timedelta(days=1)
                continue
            if not isinstance(data_resp, list):
                dia += timedelta(days=1)
                continue
            for registro in data_resp:
                if not isinstance(registro, dict):
                    continue
                conteudo = registro.get("conteudojson")
                if not isinstance(conteudo, dict):
                    continue
                rele_id = (
                    registro.get("idrele")
                    or registro.get("idRele")
                    or registro.get("IdRele")
                    or registro.get("id_rele")
                    or conteudo.get("idrele")
                    or conteudo.get("Rele")
                    or conteudo.get("rele")
                )
                if not rele_id:
                    continue
                try:
                    ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if ts < inicio_busca or ts > fim_busca:
                    continue
                identidade = self._identidade_rele_conteudo_relatorio(conteudo)
                leituras_por_rele[str(rele_id)].append((ts, identidade))
            dia += timedelta(days=1)

        incidentes = []
        for rele_id, itens in leituras_por_rele.items():
            itens.sort(key=lambda x: x[0])
            identidade_ativa = None
            inicio_ativo = None
            for ts, identidade_atual in itens:
                if identidade_ativa is None:
                    if identidade_atual:
                        identidade_ativa = identidade_atual
                        inicio_ativo = ts
                    continue
                if identidade_atual == identidade_ativa:
                    continue
                tipo_ativo, parametros_ativo = identidade_ativa
                incidentes.append(self._novo_incidente(
                    base_key=_chave_evento_rele(usina_id, rele_id, tipo_ativo, parametros_ativo),
                    natureza="RELE",
                    tipo_falha=tipo_ativo,
                    usina_id=usina_id,
                    usina=usina_nome,
                    equipamento=str(rele_id),
                    inicio_ts=(inicio_ativo or ts),
                    fim_ts=ts.isoformat(),
                ))
                identidade_ativa = identidade_atual
                inicio_ativo = ts if identidade_atual else None

            if identidade_ativa:
                tipo_ativo, parametros_ativo = identidade_ativa
                incidentes.append(self._novo_incidente(
                    base_key=_chave_evento_rele(usina_id, rele_id, tipo_ativo, parametros_ativo),
                    natureza="RELE",
                    tipo_falha=tipo_ativo,
                    usina_id=usina_id,
                    usina=usina_nome,
                    equipamento=str(rele_id),
                    inicio_ts=(inicio_ativo or inicio_semana),
                    fim_ts=None,
                ))
        return incidentes

    def _coletar_incidentes_inversor_semana_api(self, usina_id: str, usina_nome: str, inicio_semana: datetime, fim_semana: datetime):
        inicio_busca = inicio_semana - timedelta(days=WEEKLY_REPORT_WARMUP_DAYS)
        fim_busca = fim_semana - timedelta(seconds=1)
        janela_inicio, janela_fim = _obter_janela_solar_inversor(usina_nome)
        falhas, recuperados, _, _, _, _ = detectar_falhas_inversores(
            self.api_inversor,
            usina_id,
            inicio_busca,
            fim_busca,
            {},
            janela_inicio=janela_inicio,
            janela_fim=janela_fim,
        )
        eventos = []
        for falha in falhas:
            eventos.append(("falha", falha.get("ts_leitura"), falha))
        for rec in recuperados:
            eventos.append(("rec", rec.get("ts_leitura"), rec))
        eventos = [e for e in eventos if isinstance(e[1], datetime)]
        eventos.sort(key=lambda item: item[1])

        ativos = {}
        incidentes = []
        for tipo, ts, item in eventos:
            inv_id = str(item.get("inversor_id"))
            if not inv_id:
                continue
            chave = f"{usina_id}:{inv_id}"
            if tipo == "falha":
                ativos.setdefault(chave, ts)
                continue
            inicio_inc = ativos.pop(chave, inicio_semana)
            if ts < inicio_inc:
                inicio_inc = ts
            incidentes.append(self._novo_incidente(
                base_key=chave,
                natureza="INVERSOR",
                tipo_falha=INVERTER_FAILURE_LABEL,
                usina_id=usina_id,
                usina=usina_nome,
                equipamento=inv_id,
                inicio_ts=inicio_inc,
                fim_ts=ts.isoformat(),
            ))

        for chave, inicio_inc in ativos.items():
            inv_id = chave.split(":", 1)[1] if ":" in chave else chave
            incidentes.append(self._novo_incidente(
                base_key=chave,
                natureza="INVERSOR",
                tipo_falha=INVERTER_FAILURE_LABEL,
                usina_id=usina_id,
                usina=usina_nome,
                equipamento=inv_id,
                inicio_ts=inicio_inc,
                fim_ts=None,
            ))
        return incidentes

    def _coletar_incidentes_semana_api(self, inicio_semana: datetime, fim_semana: datetime):
        plantas = self.api_rele.get_plants()
        if plantas is None:
            return None
        if not plantas:
            return []

        incidentes = []
        for p in plantas:
            usina_id_raw = p.get("id")
            try:
                usina_id = str(int(usina_id_raw))
            except (TypeError, ValueError):
                continue
            usina_nome = p.get("nome")
            try:
                incidentes.extend(
                    self._coletar_incidentes_rele_semana_api(
                        usina_id=usina_id,
                        usina_nome=usina_nome,
                        inicio_semana=inicio_semana,
                        fim_semana=fim_semana,
                    )
                )
            except Exception as e:
                logger_rele.warning(
                    f"Falha no backfill semanal de rele para usina {usina_id}: {e}"
                )
            try:
                incidentes.extend(
                    self._coletar_incidentes_inversor_semana_api(
                        usina_id=usina_id,
                        usina_nome=usina_nome,
                        inicio_semana=inicio_semana,
                        fim_semana=fim_semana,
                    )
                )
            except Exception as e:
                logger_inv.warning(
                    f"Falha no backfill semanal de inversor para usina {usina_id}: {e}"
                )
        return incidentes

    def _coletar_incidentes_semana_state(self, inicio_semana: datetime, fim_semana: datetime):
        incidentes = []
        for item in list(self.historico_incidentes):
            if not isinstance(item, dict):
                continue
            inicio_dt = _parse_iso_datetime(item.get("inicio_ts"))
            if not inicio_dt:
                continue
            fim_dt = _parse_iso_datetime(item.get("fim_ts")) or fim_semana
            if fim_dt <= inicio_semana or inicio_dt >= fim_semana:
                continue
            incidentes.append(dict(item))

        for item in list(self.incidentes_rele_ativos.values()) + list(self.incidentes_inv_ativos.values()):
            if not isinstance(item, dict):
                continue
            inicio_dt = _parse_iso_datetime(item.get("inicio_ts"))
            if not inicio_dt:
                continue
            fim_dt = _parse_iso_datetime(item.get("fim_ts")) or fim_semana
            if fim_dt <= inicio_semana or inicio_dt >= fim_semana:
                continue
            incidentes.append(dict(item))

        return incidentes

    @staticmethod
    def _incidente_overlap_key(item):
        return (
            str(item.get("natureza", "")),
            str(item.get("usina_id", "")),
            str(item.get("equipamento", "")),
            str(item.get("tipo_falha", "")),
        )

    @staticmethod
    def _intervalos_se_sobrepoem(inicio_a, fim_a, inicio_b, fim_b):
        return inicio_a <= fim_b and inicio_b <= fim_a

    def _mesclar_incidentes_relatorio(self, incidentes, fim_semana: datetime):
        grupos = defaultdict(list)
        for item in incidentes:
            if not isinstance(item, dict):
                continue
            inicio_dt = _parse_iso_datetime(item.get("inicio_ts"))
            if not inicio_dt:
                continue
            fim_dt = _parse_iso_datetime(item.get("fim_ts")) or fim_semana
            if fim_dt < inicio_dt:
                fim_dt = inicio_dt
            grupos[self._incidente_overlap_key(item)].append(
                {
                    "raw": dict(item),
                    "inicio": inicio_dt,
                    "fim": fim_dt,
                    "fim_real": _parse_iso_datetime(item.get("fim_ts")),
                }
            )

        saida = []
        for _, itens in grupos.items():
            itens.sort(key=lambda x: (x["inicio"], x["fim"]))
            acumulados = []
            for item in itens:
                merged = False
                for acc in acumulados:
                    if not self._intervalos_se_sobrepoem(acc["inicio"], acc["fim"], item["inicio"], item["fim"]):
                        continue
                    acc["inicio"] = min(acc["inicio"], item["inicio"])
                    acc["fim"] = max(acc["fim"], item["fim"])
                    if acc["fim_real"] is None and item["fim_real"] is not None:
                        acc["fim_real"] = item["fim_real"]
                    elif acc["fim_real"] is not None and item["fim_real"] is not None:
                        acc["fim_real"] = max(acc["fim_real"], item["fim_real"])
                    merged = True
                    break
                if not merged:
                    acumulados.append(item)

            for item in acumulados:
                raw = dict(item["raw"])
                raw["inicio_ts"] = item["inicio"].isoformat()
                raw["fim_ts"] = item["fim_real"].isoformat() if item["fim_real"] else None
                saida.append(raw)

        return sorted(
            saida,
            key=lambda x: (
                str(x.get("usina", "")),
                str(x.get("natureza", "")),
                _parse_iso_datetime(x.get("inicio_ts")) or datetime.min,
            ),
        )

    def _montar_relatorio_semanal(self, inicio_semana: datetime, fim_semana: datetime, historico, ativos_rele, ativos_inv):
        ocorrencias = []
        dedupe = set()

        def _add_occ(base):
            if not isinstance(base, dict):
                return
            inicio_dt = _parse_iso_datetime(base.get("inicio_ts"))
            if not inicio_dt:
                return
            fim_dt = _parse_iso_datetime(base.get("fim_ts")) or fim_semana
            if fim_dt < inicio_dt:
                fim_dt = inicio_dt
            clip_total = _calcular_sobreposicao_segundos(inicio_dt, fim_dt, inicio_semana, fim_semana)
            if clip_total <= 0:
                return
            clip_ini = max(inicio_dt, inicio_semana)
            clip_fim = min(fim_dt, fim_semana)
            janela_inicio = SOLAR_WINDOW_START
            janela_fim = SOLAR_WINDOW_END
            if str(base.get("natureza", "")).upper() == "INVERSOR":
                janela_inicio, janela_fim = _obter_janela_solar_inversor(base.get("usina"))
            solar_sec = _calcular_sobreposicao_janela_solar(
                clip_ini,
                clip_fim,
                janela_inicio=janela_inicio,
                janela_fim=janela_fim,
            )
            key = (
                str(base.get("chave", "")),
                str(base.get("inicio_ts", "")),
                str(base.get("fim_ts", "")),
            )
            if key in dedupe:
                return
            dedupe.add(key)
            ocorrencias.append(
                {
                    "usina": base.get("usina") or f"Usina {base.get('usina_id', 'N/A')}",
                    "usina_id": str(base.get("usina_id", "")),
                    "natureza": str(base.get("natureza", "")),
                    "tipo_falha": str(base.get("tipo_falha", "")),
                    "equipamento": str(base.get("equipamento", "")),
                    "inicio": inicio_dt,
                    "fim": _parse_iso_datetime(base.get("fim_ts")),
                    "clip_ini": clip_ini,
                    "clip_fim": clip_fim,
                    "dur_total_sec": clip_total,
                    "dur_solar_sec": solar_sec,
                }
            )

        for item in historico:
            _add_occ(item)
        for item in ativos_rele.values():
            _add_occ(item)
        for item in ativos_inv.values():
            _add_occ(item)

        agregados = defaultdict(
            lambda: {"qtd": 0, "dur_total_sec": 0.0, "dur_solar_sec": 0.0}
        )
        for it in ocorrencias:
            chave = (it["usina"], it["natureza"], it["tipo_falha"])
            agg = agregados[chave]
            agg["qtd"] += 1
            agg["dur_total_sec"] += it["dur_total_sec"]
            agg["dur_solar_sec"] += it["dur_solar_sec"]

        semana_txt = (
            f"{inicio_semana.strftime('%d/%m/%Y')} a "
            f"{(fim_semana - timedelta(seconds=1)).strftime('%d/%m/%Y')}"
        )
        resumo_rows = [
            [
                "Semana",
                "Usina",
                "Natureza",
                "Tipo de Falha",
                "Quantidade de Falhas",
                "Indisponibilidade Total",
                "Indisponibilidade Janela Solar",
                "Indisponibilidade Janela Solar (h)",
            ]
        ]
        for (usina, natureza, tipo_falha), agg in sorted(agregados.items()):
            resumo_rows.append(
                [
                    semana_txt,
                    usina,
                    natureza,
                    tipo_falha,
                    int(agg["qtd"]),
                    _formatar_duracao(agg["dur_total_sec"]),
                    _formatar_duracao(agg["dur_solar_sec"]),
                    round(agg["dur_solar_sec"] / 3600.0, 2),
                ]
            )

        ocorrencias_rows = [
            [
                "Usina",
                "Natureza",
                "Tipo de Falha",
                "Equipamento",
                "Inicio da Falha",
                "Normalizacao",
                "Periodo Considerado (Semana)",
                "Indisponibilidade no Periodo",
                "Indisponibilidade na Janela Solar",
                "Indisponibilidade Janela Solar (h)",
            ]
        ]
        for it in sorted(ocorrencias, key=lambda x: x["clip_ini"]):
            inicio_txt = self._fmt_ts(it["inicio"])
            fim_txt = self._fmt_ts(it["fim"]) if it["fim"] else "EM ABERTO"
            periodo_txt = f"{self._fmt_ts(it['clip_ini'])} ate {self._fmt_ts(it['clip_fim'])}"
            ocorrencias_rows.append(
                [
                    it["usina"],
                    it["natureza"],
                    it["tipo_falha"],
                    it["equipamento"],
                    inicio_txt,
                    fim_txt,
                    periodo_txt,
                    _formatar_duracao(it["dur_total_sec"]),
                    _formatar_duracao(it["dur_solar_sec"]),
                    round(it["dur_solar_sec"] / 3600.0, 2),
                ]
            )

        return resumo_rows, ocorrencias_rows, semana_txt

    def _gerar_relatorio_semanal_se_pendente(self, ref: datetime = None):
        agora = ref or datetime.now()
        with self._scan_lock:
            pendente = self._periodo_relatorio_pendente(agora)
            if not pendente:
                return False
            inicio_semana, fim_semana, report_id = pendente
            incidentes_state = self._coletar_incidentes_semana_state(inicio_semana, fim_semana)

        # Coleta da API fora do lock para não bloquear scans e heartbeat.
        _t0_rel_api = time.monotonic()
        incidentes_api = self._coletar_incidentes_semana_api(inicio_semana, fim_semana)
        logger.info("[RELATORIO] Coleta API semanal concluida em %.1fs", time.monotonic() - _t0_rel_api)

        if incidentes_api is None:
            incidentes_finais = self._mesclar_incidentes_relatorio(incidentes_state, fim_semana)
            logger.warning(
                "Relatorio semanal usando apenas state local (coleta direta da API indisponivel)."
            )
        else:
            incidentes_finais = self._mesclar_incidentes_relatorio(
                list(incidentes_api) + list(incidentes_state), fim_semana
            )
            logger.info(
                "[RELATORIO] Incidentes semanais consolidados | API: %s | State: %s | Final: %s",
                len(incidentes_api),
                len(incidentes_state),
                len(incidentes_finais),
            )

        resumo_rows, ocorrencias_rows, semana_txt = self._montar_relatorio_semanal(
            inicio_semana, fim_semana, incidentes_finais, {}, {}
        )
        fim_legivel = (fim_semana - timedelta(days=1)).strftime("%Y%m%d")
        arquivo = REPORT_DIR / f"relatorio_semanal_{inicio_semana.strftime('%Y%m%d')}_{fim_legivel}.xlsx"
        try:
            _write_xlsx_file(
                arquivo,
                [
                    ("Resumo", resumo_rows),
                    ("Ocorrencias", ocorrencias_rows),
                ],
            )
        except Exception as e:
            logger.error(f"[RELATORIO] Falha ao escrever arquivo xlsx: {e}")
            _teams_post_card(
                title="Monitor: falha ao gerar relatório semanal",
                text=f"Erro ao escrever arquivo: {e}",
                severity="warning",
                facts=[("Arquivo", str(arquivo))],
            )
            return False

        with self._scan_lock:
            if self.last_weekly_report_id == report_id:
                return True
            self.last_weekly_report_id = report_id
            self._save_state()
        logger.info(
            f"Relatorio semanal gerado: {arquivo} | Janela solar rele: {SOLAR_WINDOW_LABEL} | "
            f"Janela solar inversor: {INVERTER_SOLAR_WINDOW_LABEL} | "
            f"Janela solar inversor (Ibimirim): {IBIMIRIM_INVERTER_SOLAR_WINDOW_LABEL} | Semana: {semana_txt}"
        )
        return True

    def _coletar_alertas_rele_usina(
        self,
        *,
        usina_id: str,
        nome: str | None,
        inicio_padrao: datetime,
        agora: datetime,
    ) -> tuple[list, bool, datetime | None]:
        last_usina = self.ultima_varredura_rele_por_usina.get(usina_id)
        if last_usina:
            inicio_janela = last_usina + timedelta(seconds=WINDOW_DELTA_SECONDS)
        else:
            inicio_janela = inicio_padrao

        alertas, tem_dados, teve_timeout, max_ts_rele = detectar_alertas_rele(
            self.api_rele, usina_id, inicio_janela, agora
        )
        if not tem_dados:
            motivo = "TIMEOUT" if teve_timeout else "SEM_DADOS"
            logger_rele.warning(f"Sem dados de relé em {nome} (motivo: {motivo}). Mantendo alertas ativos.")
            return [], True, max_ts_rele
        if teve_timeout:
            logger_rele.warning(
                f"Dados parciais de relé em {nome} (motivo: TIMEOUT_PARCIAL). Mantendo alertas ativos."
            )
            return [], True, max_ts_rele
        return alertas, False, max_ts_rele

    def _montar_alerta_rele_formatado(
        self,
        alerta_raw: dict,
        *,
        base: str,
        nome: str | None,
        capacidade,
    ) -> dict:
        ts_first = alerta_raw.get("ts_primeiro", alerta_raw["ts_leitura"])
        ts_last = alerta_raw.get("ts_ultimo", alerta_raw["ts_leitura"])
        intervalo_txt = self.formatar_intervalo_alerta(ts_first, ts_last)
        parametros = alerta_raw["parametros"]
        return {
            "base": base,
            "usina": nome,
            "capacidade": capacidade,
            "rele": alerta_raw["rele_id"],
            "horario": alerta_raw["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
            "tipo": alerta_raw["tipo_alerta"],
            "ts_iso": alerta_raw["ts_leitura"].isoformat(),
            "parametros": f"{parametros} | {intervalo_txt}" if intervalo_txt else parametros,
        }

    def _registrar_alerta_rele_detectado(
        self,
        *,
        alerta_raw: dict,
        usina_id: str,
        nome: str | None,
        capacidade,
        pend_norm: dict,
        bases_ativos_atual: set,
        novos_por_usina: dict,
        agora: datetime,
    ) -> None:
        parametros_base = alerta_raw.get("parametros_chave") or alerta_raw.get("parametros", "")
        base = _chave_evento_rele(usina_id, alerta_raw["rele_id"], alerta_raw["tipo_alerta"], parametros_base)
        bases_legadas = {
            f"{usina_id}:{alerta_raw['rele_id']}:{alerta_raw['tipo_alerta']}",
            _chave_legada_rele(usina_id, alerta_raw["rele_id"], alerta_raw["tipo_alerta"]),
        }
        for base_legada in bases_legadas:
            self._migrar_chave_rele_ativa(base_legada, base)

        pend_list = pend_norm.get(usina_id, [])
        if pend_list:
            pend_norm[usina_id] = [
                i for i in pend_list if i.get("base") not in ({base} | bases_legadas)
            ]
            if not pend_norm[usina_id]:
                pend_norm.pop(usina_id, None)

        bases_ativos_atual.add(base)
        alerta_fmt = self._montar_alerta_rele_formatado(
            alerta_raw,
            base=base,
            nome=nome,
            capacidade=capacidade,
        )

        is_novo = base not in self.rele_alertas_ativos
        self._ativar_alerta_rele(
            base, alerta_fmt,
            usina_id=usina_id,
            nome=nome,
            rele_id=alerta_raw["rele_id"],
            tipo_alerta=alerta_raw["tipo_alerta"],
            inicio_ts=alerta_raw["ts_leitura"],
        )
        if base in self.rele_notificados:
            logger_rele.info(
                f"[RELE] Duplicidade suprimida | base={base} | "
                f"usina={nome} | rele={alerta_raw['rele_id']} | tipo={alerta_raw['tipo_alerta']} | "
                f"parametros={parametros_base}"
            )
        elif not is_novo and self._retry_rele_adiado(base, agora):
            retry_after = self.rele_notificacao_retry_after.get(base)
            logger_rele.info(
                f"[RELE] Retry de alerta pendente adiado | base={base} | "
                f"retry_after={retry_after} | usina={nome} | rele={alerta_raw['rele_id']} | "
                f"tipo={alerta_raw['tipo_alerta']} | parametros={parametros_base}"
            )
        else:
            novos_por_usina.setdefault(
                usina_id, {"usina": nome, "capacidade": capacidade, "itens": []}
            )["itens"].append(alerta_fmt)
            logger_rele.info(
                f"[RELE] Alerta novo/pendente marcado para envio | base={base} | "
                f"usina={nome} | rele={alerta_raw['rele_id']} | tipo={alerta_raw['tipo_alerta']} | "
                f"parametros={parametros_base}"
            )

    def _registrar_resolucoes_rele(self, bases_ativos_atual: set, agora: datetime) -> dict:
        resolvidos_por_usina = {}
        resolved = self.rele_alertas_ativos - bases_ativos_atual
        for base in resolved:
            alerta_antigo = self._resolver_alerta_rele(base, fim_ts=agora)
            if alerta_antigo:
                usina_id, rele_id, tipo, _ = _partes_chave_rele(base)
                resolvidos_por_usina.setdefault(
                    usina_id, {"usina": alerta_antigo.get("usina"), "capacidade": alerta_antigo.get("capacidade"), "itens": []}
                )["itens"].append(
                    {
                        "base": base,
                        "usina": alerta_antigo.get("usina"),
                        "capacidade": alerta_antigo.get("capacidade"),
                        "rele": alerta_antigo.get("rele", rele_id),
                        "tipo": alerta_antigo.get("tipo", tipo),
                        "horario": alerta_antigo.get("horario"),
                        "ts_iso": alerta_antigo.get("ts_iso"),
                        "parametros": alerta_antigo.get("parametros"),
                    }
                )
        return resolvidos_por_usina

    def _montar_jobs_notificacao_rele(
        self,
        novos_por_usina: dict,
        resolvidos_por_usina: dict,
        pend_norm: dict,  # mutado in-place: normalizados confirmados são acumulados aqui
    ) -> list:
        notification_jobs = []
        usinas = set(novos_por_usina.keys()) | set(resolvidos_por_usina.keys()) | set(pend_norm.keys())
        for usina_id in usinas:
            pacote = {"usina": None, "capacidade": None, "novos": [], "normalizados": []}
            if usina_id in novos_por_usina:
                pacote["usina"] = novos_por_usina[usina_id].get("usina")
                pacote["capacidade"] = novos_por_usina[usina_id].get("capacidade")
                pacote["novos"] = novos_por_usina[usina_id].get("itens", [])
            if usina_id in resolvidos_por_usina:
                pacote["usina"] = pacote["usina"] or resolvidos_por_usina[usina_id].get("usina")
                pacote["capacidade"] = pacote["capacidade"] or resolvidos_por_usina[usina_id].get("capacidade")
                pacote["normalizados"] = resolvidos_por_usina[usina_id].get("itens", [])
            pend_itens = pend_norm.get(usina_id, [])
            if pend_itens:
                pacote["normalizados"].extend(pend_itens)
                if not pacote["usina"]:
                    pacote["usina"] = pend_itens[0].get("usina")
                    pacote["capacidade"] = pend_itens[0].get("capacidade")

            pacote["novos"] = _dedupe_por_base(pacote["novos"])
            pacote["normalizados"] = _dedupe_por_base(pacote["normalizados"])
            pacote["novos"] = sorted(pacote["novos"], key=_alerta_ts_key)
            pacote["normalizados"] = sorted(pacote["normalizados"], key=_alerta_ts_key)
            if not pacote["novos"] and not pacote["normalizados"]:
                continue

            if pacote["normalizados"]:
                pend_list = pend_norm.setdefault(usina_id, [])
                existentes = {i.get("base") for i in pend_list if i.get("base")}
                for item in pacote["normalizados"]:
                    base = item.get("base")
                    if base and base in existentes:
                        continue
                    pend_list.append(item)
                    if base:
                        existentes.add(base)
            notification_jobs.append((usina_id, pacote))
        return notification_jobs

    def _aplicar_resultados_notificacao_rele(self, job_results: dict) -> None:
        if not job_results:
            return
        with self._scan_lock:
            pend_norm = self.pending_notifications.setdefault("rele_normalizados", {})
            for usina_id, (ok_novos, ok_norm, pacote) in job_results.items():
                if ok_novos:
                    for item in pacote["novos"]:
                        base = item.get("base")
                        if base:
                            self.rele_notificados.add(base)
                            self.rele_notificacao_retry_after.pop(base, None)
                elif pacote.get("novos"):
                    agora_retry = datetime.now()
                    bases_falha = [item.get("base") for item in pacote["novos"] if item.get("base")]
                    for base in bases_falha:
                        self._agendar_retry_rele(base, agora_retry)
                    logger_rele.warning(
                        f"[RELE] Falha ao enviar alerta; evento permanece pendente para retry controlado | "
                        f"usina_id={usina_id} | bases={bases_falha} | "
                        f"retry_after={(agora_retry + RELAY_NOTIFICATION_RETRY_COOLDOWN).isoformat()}"
                    )
                if ok_norm:
                    bases_norm = {item.get("base") for item in pacote["normalizados"] if item.get("base")}
                    if bases_norm and usina_id in pend_norm:
                        pend_norm[usina_id] = [
                            i for i in pend_norm.get(usina_id, []) if i.get("base") not in bases_norm
                        ]
                        if not pend_norm[usina_id]:
                            pend_norm.pop(usina_id, None)
            self._save_state()

    # Busca alertas de rele nas usinas e dispara notificacoes unicas por evento.
    def executar_varredura_rele(self):
        with self._scan_lock:
            _t0_scan_rele = time.monotonic()
            agora = datetime.now()
            # começa no último fim de varredura + delta; primeira vez vai até 00:00
            if self.ultima_varredura_rele:
                inicio_padrao = self.ultima_varredura_rele + timedelta(seconds=WINDOW_DELTA_SECONDS)
            else:
                inicio_padrao = datetime.combine(agora.date(), datetime.min.time())
            logger_rele.info("Varredura de rele iniciada.")
            if RELE_DEBUG:
                logger_rele.info(
                    f"[RELE][DEBUG] entrada | "
                    f"rele_alertas_ativos={len(self.rele_alertas_ativos)} | "
                    f"rele_notificados={len(self.rele_notificados)} | "
                    f"retry_after={len(self.rele_notificacao_retry_after)} | "
                    f"inicio_padrao={inicio_padrao.isoformat()} | "
                    f"ultima_varredura_rele={self.ultima_varredura_rele.isoformat() if self.ultima_varredura_rele else 'None'}"
                )
            pend_norm = self.pending_notifications.setdefault("rele_normalizados", {})

            plantas, sem_plantas = self._obter_plantas(self.api_rele, logger_rele, "rele")
            if sem_plantas:
                logger_rele.info("Mantendo alertas ativos.")
                self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}

            ausentes_rele = set()
            if plantas:
                ausentes_rele = self._detectar_lista_parcial(
                    plantas, self.ultima_varredura_rele_por_usina, self.rele_alertas_ativos, logger_rele, "rele"
                )

            bases_ativos_atual = set()
            novos_por_usina = {}
            usinas_sem_dados = set(ausentes_rele)

            for p in plantas:
                usina_id_raw = p.get("id")
                try:
                    usina_id_int = int(usina_id_raw)
                except (TypeError, ValueError):
                    logger_rele.warning(f"Usina com id inválido (rele): {usina_id_raw!r}. Pulando.")
                    continue
                usina_id = str(usina_id_int)
                if usina_id not in RELE_PLANT_IDS:
                    continue
                nome = p.get("nome")
                cap = p.get("capacidade")

                alertas, preservar_ativos, max_ts_rele = self._coletar_alertas_rele_usina(
                    usina_id=usina_id,
                    nome=nome,
                    inicio_padrao=inicio_padrao,
                    agora=agora,
                )
                if preservar_ativos:
                    usinas_sem_dados.add(usina_id)
                    continue

                for a in alertas:
                    self._registrar_alerta_rele_detectado(
                        alerta_raw=a,
                        usina_id=usina_id,
                        nome=nome,
                        capacidade=cap,
                        pend_norm=pend_norm,
                        bases_ativos_atual=bases_ativos_atual,
                        novos_por_usina=novos_por_usina,
                        agora=agora,
                    )

                if max_ts_rele is not None:
                    self.ultima_varredura_rele_por_usina[usina_id] = max_ts_rele

            if usinas_sem_dados:
                for base in self.rele_alertas_ativos:
                    if base.split(":", 1)[0] in usinas_sem_dados:
                        bases_ativos_atual.add(base)
            resolvidos_por_usina = self._registrar_resolucoes_rele(bases_ativos_atual, agora)
            # recalcula usinas com rele ativo a partir do conjunto de alertas ativos
            self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}

            # envia uma notificação por usina consolidando alertas novos, normalizados e pendentes
            notification_jobs = self._montar_jobs_notificacao_rele(
                novos_por_usina=novos_por_usina,
                resolvidos_por_usina=resolvidos_por_usina,
                pend_norm=pend_norm,
            )

            if not sem_plantas:
                self.ultima_varredura_rele = agora
            self._save_state()
            lock_api_duration = time.monotonic() - _t0_scan_rele
        # Lock released — send Teams outside the lock

        job_results = {}
        for usina_id, pacote in notification_jobs:
            ok_novos, ok_norm = self._notificar_rele_agrupado(pacote)
            job_results[usina_id] = (ok_novos, ok_norm, pacote)

        self._aplicar_resultados_notificacao_rele(job_results)

        logger_rele.info("[SCAN] Varredura rele fase lock/API concluida em %.1fs", lock_api_duration)
        logger_rele.info("Varredura de rele concluida.")

    # Analisa inversores e alerta se houver falha persistente ou recuperacao.
    def executar_varredura_inversor(self):
        with self._scan_lock:
            _t0_scan_inv = time.monotonic()
            agora = datetime.now()
            if self.ultima_varredura_inversor:
                inicio_padrao = self.ultima_varredura_inversor + timedelta(seconds=WINDOW_DELTA_SECONDS)
            else:
                inicio_padrao = datetime.combine(agora.date(), datetime.min.time())
            logger_inv.info("Varredura de inversor iniciada.")
            pend_norm = self.pending_notifications.setdefault("inv_normalizados", {})

            notification_inv_jobs = []

            plantas, sem_plantas = self._obter_plantas(self.api_inversor, logger_inv, "inversor")

            if plantas:
                self._detectar_lista_parcial(
                    plantas, self.ultima_varredura_inversor_por_usina, self.estado_inversores, logger_inv, "inversor"
                )

            for p in plantas:
                usina_id_raw = p.get("id")
                try:
                    usina_id_int = int(usina_id_raw)
                except (TypeError, ValueError):
                    logger_inv.warning(f"Usina com id inválido (inversor): {usina_id_raw!r}. Pulando.")
                    continue
                usina_id = str(usina_id_int)
                if usina_id in self.usinas_alerta_rele_recente:
                    logger_inv.info(f"Pulando inversores de {p.get('nome')} devido a alerta de rele recente.")
                    # Regra oficial: com relé ativo, pausa inversores sem alterar estado.
                    continue

                nome = p.get("nome")
                cap = p.get("capacidade")
                janela_inicio_inv, janela_fim_inv = _obter_janela_solar_inversor(nome)
                janela_label_inv = _formatar_janela_solar_label(janela_inicio_inv, janela_fim_inv)

                last_usina = self.ultima_varredura_inversor_por_usina.get(usina_id)
                if last_usina:
                    inicio_janela = last_usina + timedelta(seconds=WINDOW_DELTA_SECONDS)
                else:
                    inicio_janela = inicio_padrao

                falhas, recuperados, tem_dados_inv, falhas_ativas_atual, teve_timeout, max_ts_inv = detectar_falhas_inversores(
                    self.api_inversor,
                    usina_id,
                    inicio_janela,
                    agora,
                    self.estado_inversores,
                    janela_inicio=janela_inicio_inv,
                    janela_fim=janela_fim_inv,
                )
                if teve_timeout:
                    logger_inv.warning(
                        f"Dados parciais de inversor em {nome} (motivo: TIMEOUT_PARCIAL). Mantendo alertas ativos."
                    )
                    continue

                eventos = []
                for rec in recuperados:
                    eventos.append(("rec", rec["ts_leitura"], rec))
                for falha in falhas:
                    eventos.append(("falha", falha["ts_leitura"], falha))
                eventos.sort(key=lambda item: item[1])
                chaves_observadas = {
                    chave for chave, estado in falhas_ativas_atual.items()
                    if isinstance(estado, dict) and estado.get("tem_dado_valido")
                }
                chaves_vistas = {
                    chave for chave, estado in falhas_ativas_atual.items()
                    if isinstance(estado, dict)
                }

                tentativas_envio = set()

                for tipo, _, item in eventos:
                    if tipo == "rec":
                        inv_base = item["inversor_id"]
                        chave_inv = f"{usina_id}:{inv_base}"
                        alerta_prev = self.estado_inversores.get(chave_inv, {}).get("alerta")
                        alerta = _montar_alerta_inversor(item, nome, cap, janela_label_inv)
                        pend_norm[chave_inv] = {"alerta": alerta, "alerta_prev": alerta_prev}
                        notification_inv_jobs.append({"tipo": "rec", "chave": chave_inv, "alerta": alerta, "alerta_prev": alerta_prev})
                        if chave_inv in self.estado_inversores:
                            entry_rec = self.estado_inversores[chave_inv]
                            entry_rec["alerta"] = None
                            entry_rec["notificado"] = False
                            self.estado_inversores[chave_inv] = entry_rec
                        self._registrar_fim_incidente_inversor(
                            chave_inv=chave_inv,
                            fim_ts=item["ts_leitura"],
                            alerta_prev=alerta_prev,
                            usina_id=usina_id,
                        )
                        tentativas_envio.add(chave_inv)
                    else:
                        chave_inv = f"{usina_id}:{item['inversor_id']}"
                        pend_norm.pop(chave_inv, None)
                        entry = self.estado_inversores.get(
                            chave_inv,
                            {"ativa": True, "rec_seq": 0, "seq_zero": 0, "alerta": None, "notificado": False},
                        )
                        alerta = _montar_alerta_inversor(item, nome, cap, janela_label_inv)
                        entry["alerta"] = alerta
                        self._registrar_inicio_incidente_inversor(
                            chave_inv=chave_inv,
                            usina_id=usina_id,
                            usina=nome,
                            inversor_id=item["inversor_id"],
                            inicio_ts=item["ts_leitura"],
                        )
                        if not entry.get("notificado", False):
                            notification_inv_jobs.append({"tipo": "falha", "chave": chave_inv, "alerta": alerta})
                            tentativas_envio.add(chave_inv)
                        self.estado_inversores[chave_inv] = entry

                if chaves_vistas:
                    self._reconciliar_inversores_ausentes(
                        usina_id=usina_id,
                        chaves_observadas=chaves_observadas,
                    )

                if not tem_dados_inv:
                    motivo = "TIMEOUT" if teve_timeout else "SEM_DADOS"
                    for inversor_serial in _inversores_sem_dados_para_log(
                        usina_id,
                        falhas_ativas_atual,
                        self.estado_inversores,
                    ):
                        logger_inv.warning(_mensagem_sem_dados_inversor(nome, inversor_serial, motivo))

                for chave_inv, estado in list(self.estado_inversores.items()):
                    if not chave_inv.startswith(f"{usina_id}:"):
                        continue
                    if not estado.get("ativa"):
                        continue
                    if estado.get("notificado"):
                        continue
                    if chave_inv in tentativas_envio:
                        continue
                    alerta = estado.get("alerta")
                    if not isinstance(alerta, dict):
                        continue
                    notification_inv_jobs.append({"tipo": "falha_resend", "chave": chave_inv, "alerta": alerta})

                for chave_inv, estado in falhas_ativas_atual.items():
                    if isinstance(estado, bool):
                        estado = {"ativa": estado}
                    if not isinstance(estado, dict):
                        continue
                    prev_entry = self.estado_inversores.get(chave_inv, {})
                    tem_dado_valido = chave_inv in chaves_observadas
                    self.estado_inversores[chave_inv] = _compor_entrada_estado_inversor(
                        prev_entry, estado, tem_dado_valido
                    )

                if max_ts_inv is not None:
                    self.ultima_varredura_inversor_por_usina[usina_id] = max_ts_inv

            already_rec = {j["chave"] for j in notification_inv_jobs if j["tipo"] == "rec"}
            for chave, payload in list(pend_norm.items()):
                if chave in already_rec:
                    continue
                uid = chave.split(":", 1)[0] if ":" in chave else None
                if uid and uid in self.usinas_alerta_rele_recente:
                    continue
                alerta = payload.get("alerta") if isinstance(payload, dict) else None
                alerta_prev = payload.get("alerta_prev") if isinstance(payload, dict) else None
                if not isinstance(alerta, dict):
                    pend_norm.pop(chave, None)
                    continue
                notification_inv_jobs.append({"tipo": "rec_retry", "chave": chave, "alerta": alerta, "alerta_prev": alerta_prev})

            if not sem_plantas:
                self.ultima_varredura_inversor = agora
            self._save_state()
            lock_api_duration = time.monotonic() - _t0_scan_inv
        # Lock released — send Teams outside the lock

        inv_results = {}
        for job in notification_inv_jobs:
            tipo = job["tipo"]
            chave = job["chave"]
            if tipo in ("rec", "rec_retry"):
                ok = self._notificar_inversor_recuperado(job["alerta"], job.get("alerta_prev"))
            else:
                ok = self._notificar_inversor(job["alerta"])
            inv_results.setdefault(chave, {})[tipo] = ok

        if inv_results:
            with self._scan_lock:
                pend_norm = self.pending_notifications.setdefault("inv_normalizados", {})
                for chave, resultados in inv_results.items():
                    if resultados.get("rec") or resultados.get("rec_retry"):
                        pend_norm.pop(chave, None)
                    if resultados.get("falha") or resultados.get("falha_resend"):
                        estado = self.estado_inversores.get(chave)
                        if isinstance(estado, dict) and estado.get("ativa"):
                            estado["notificado"] = True
                            self.estado_inversores[chave] = estado
                self._save_state()

        logger_inv.info("[SCAN] Varredura inversor fase lock/API concluida em %.1fs", lock_api_duration)
        logger.info("Varredura de inversor concluída.")

    # Formata intervalo de tempo das leituras para texto amigavel.
    @staticmethod
    def formatar_intervalo_alerta(ts_first: datetime | None, ts_last: datetime | None) -> str:
        if not ts_first or not ts_last:
            return ""
        if ts_first == ts_last:
            return f"Alerta às {ts_first.strftime('%H:%M')}"
        return f"Primeiro alerta às {ts_first.strftime('%H:%M')} e último às {ts_last.strftime('%H:%M')}"

    @staticmethod
    def _inversor_conta_no_heartbeat(estado: dict, referencia: datetime) -> bool:
        if not isinstance(estado, dict):
            return False
        if not estado.get("ativa"):
            return False
        ultima_confirmacao = _parse_iso_datetime(estado.get("ultima_confirmacao_ts"))
        if not ultima_confirmacao or not isinstance(referencia, datetime):
            return False
        return (referencia - ultima_confirmacao) <= INVERTER_HEARTBEAT_CONFIRMATION_TTL

    @staticmethod
    def _proximo_horario_heartbeat(ref: datetime) -> datetime:
        # encontra o próximo horário programado a partir de ref
        hoje = ref.date()
        for t in HEARTBEAT_TIMES:
            candidato = datetime.combine(hoje, t)
            if candidato >= ref:
                return candidato
        # se nenhum restante no dia, pega o primeiro do próximo dia
        amanha = hoje + timedelta(days=1)
        return datetime.combine(amanha, HEARTBEAT_TIMES[0])

    # Envia notificacao de heartbeat/saude em horarios fixos.
    def _enviar_heartbeat(self, previsto: datetime):
        referencia_hb = previsto if isinstance(previsto, datetime) else datetime.now()
        _wait_t0 = time.monotonic()
        with self._scan_lock:
            lock_wait = time.monotonic() - _wait_t0
            rele_alertas = list(self.rele_alertas_ativos)
            rele_alerta_chave = dict(self.rele_alerta_chave)
            estado_inversores = dict(self.estado_inversores)
            ativos_rele = len(rele_alertas)
            ativos_inv = sum(
                1 for estado in estado_inversores.values() if self._inversor_conta_no_heartbeat(estado, referencia_hb)
            )
            ultima_rele = self.ultima_varredura_rele
            ultima_inv = self.ultima_varredura_inversor
        logger.info("[HEARTBEAT] Aguardou %.2fs pelo scan_lock", lock_wait)

        agora_hb = datetime.now()
        rele_atrasado = (
            ultima_rele is not None
            and (agora_hb - ultima_rele).total_seconds() > 2 * RELAY_INTERVAL
        )
        inv_atrasado = (
            ultima_inv is not None
            and (agora_hb - ultima_inv).total_seconds() > 2 * INVERTER_INTERVAL
        )

        rele_usinas = []
        if ativos_rele:
            for base in rele_alertas:
                alerta = rele_alerta_chave.get(base, {})
                nome = alerta.get("usina")
                if not nome and isinstance(base, str) and ":" in base:
                    nome = f"Usina {base.split(':', 1)[0]}"
                if nome:
                    rele_usinas.append(nome)
            rele_usinas = sorted(set(rele_usinas))

        inv_usina_counts = {}
        if ativos_inv:
            for chave, estado in estado_inversores.items():
                if not self._inversor_conta_no_heartbeat(estado, referencia_hb):
                    continue
                alerta = estado.get("alerta") or {}
                nome = alerta.get("usina")
                if not nome and isinstance(chave, str) and ":" in chave:
                    nome = f"Usina {chave.split(':', 1)[0]}"
                if not nome:
                    continue
                inv_usina_counts[nome] = inv_usina_counts.get(nome, 0) + 1

        texto = _formatar_texto_heartbeat(
            rele_atrasado=rele_atrasado,
            inv_atrasado=inv_atrasado,
            ultima_rele=ultima_rele,
            ultima_inv=ultima_inv,
            ativos_rele=ativos_rele,
            ativos_inv=ativos_inv,
            rele_usinas=rele_usinas,
            inv_usina_counts=inv_usina_counts,
            previsto=previsto,
        )
        heartbeat_line = texto.replace("  \n", " | ")
        logger.info(f"[HEARTBEAT] {heartbeat_line}")
        try:
            _teams_post_card(
                title="Heartbeat: monitor rodando",
                text=texto,
                severity="info",
                facts=None,
            )
        except Exception:
            logger.exception("Falha ao enviar heartbeat")

    # Monta e envia notificacao de falha/normalizacao de relé por usina.
    def _notificar_rele_agrupado(self, pacote: dict) -> tuple[bool, bool]:
        novos = pacote.get("novos", []) or []
        normalizados = pacote.get("normalizados", []) or []
        if not novos and not normalizados:
            return True, True

        usina = pacote.get("usina", "N/A")

        ok_novos = True
        if novos:
            card = _montar_card_rele_falha(pacote)
            logger_rele.warning(
                f"[RELE] Falha | Usina: {usina} | Itens: {len(novos)} | "
                + _formatar_blocos_rele(novos).replace("  \n", " | ")
            )
            if card:
                logger_rele.info(
                    f"[RELE][SEND] tentando envio falha | usina={usina} | "
                    f"title={card.get('title')!r} | severity={card.get('severity')} | "
                    f"text_len={len(card.get('text') or '')} | "
                    f"bases={[i.get('base') for i in novos]}"
                )
                try:
                    # Mesma politica de retry do inversor (default 3 tentativas).
                    ok_novos = _teams_post_card(**card)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele falha)")
                    ok_novos = False
                logger_rele.info(
                    f"[RELE][SEND] resultado falha | usina={usina} | ok={ok_novos}"
                )
            else:
                logger_rele.warning(
                    f"[RELE] Card de falha veio None apesar de novos={len(novos)} | usina={usina}"
                )

        ok_norm = True
        if normalizados:
            card = _montar_card_rele_normalizacao(pacote)
            logger_rele.info(
                f"[RELE] Normalizacao | Usina: {usina} | Itens: {len(normalizados)} | "
                + _formatar_blocos_rele(normalizados).replace("  \n", " | ")
            )
            if card:
                logger_rele.info(
                    f"[RELE][SEND] tentando envio normalizacao | usina={usina} | "
                    f"title={card.get('title')!r} | severity={card.get('severity')} | "
                    f"text_len={len(card.get('text') or '')} | "
                    f"bases={[i.get('base') for i in normalizados]}"
                )
                try:
                    ok_norm = _teams_post_card(**card)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele normalizacao)")
                    ok_norm = False
                logger_rele.info(
                    f"[RELE][SEND] resultado normalizacao | usina={usina} | ok={ok_norm}"
                )

        return ok_novos, ok_norm

    @staticmethod
    def _preparar_contexto_notificacao_inversor(alerta: dict) -> tuple:
        inds = alerta.get("indicadores", {})
        detalhes_txt = f"Pac: {inds.get('pac', 'N/A')}"
        janela_inicio, janela_fim = _obter_janela_solar_inversor(alerta.get("usina"))
        janela_label = alerta.get("janela_solar_label", _formatar_janela_solar_label(janela_inicio, janela_fim))
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"Inversor: {alerta['inversor']}\n"
            f"Status: {alerta['status']}\n"
            f"Horário: {alerta['horario']}\n"
            f"{detalhes_txt}"
        )
        return detalhes_txt, janela_label, msg

    # Monta mensagem de falha de inversor (Pac zerado) e envia para Teams.
    def _notificar_inversor(self, alerta: dict) -> bool:
        detalhes_txt, janela_label, msg = self._preparar_contexto_notificacao_inversor(alerta)
        logger_inv.warning(f"[ALERTA INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            return _teams_post_card(
                title=f"⚠️ Falha de Inversor (Pac=0; {INVERTER_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="danger",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (inversor)")
            return False

    # Comunica quando um inversor voltou a produzir apos falha de Pac 0.
    def _notificar_inversor_recuperado(self, alerta: dict, alerta_prev: dict | None = None) -> bool:
        detalhes_txt, janela_label, msg = self._preparar_contexto_notificacao_inversor(alerta)
        logger_inv.info(f"[RECUPERACAO INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            return _teams_post_card(
                title=f"✔️ Normalização de Inversor (Pac normalizado; {INVERTER_RECOVERY_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="info",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (recuperacao inversor)")
            return False


# Ponto de entrada do script: instancia API, inicia servico e aguarda interrupcao.
def main():
    validate_config()
    api_rele = PVOperationAPI(email=PVOP_EMAIL, password=PVOP_PASSWORD, base_url=PVOP_BASE_URL)
    api_inv = PVOperationAPI(email=PVOP_EMAIL, password=PVOP_PASSWORD, base_url=PVOP_BASE_URL)
    service = MonitorService(api_rele, api_inv)

    def _handle_exit(signum=None, frame=None):
        logger.info("Encerrando monitor...")
        try:
            service.stop()
        finally:
            logger.info("Monitor encerrado com sucesso.")
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, _handle_exit)
        signal.signal(signal.SIGTERM, _handle_exit)
    except Exception:
        logger.warning("Nao foi possivel registrar sinais de encerramento.")

    service.start()
    logger.info("Monitor headless iniciado. Pressione Ctrl+C para sair.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _handle_exit()


# Executa a aplicacao somente quando o arquivo for chamado diretamente.
if __name__ == "__main__":
    main()
