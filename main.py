# ===========================================
# Monitor de Relés/Inversores (headless, Teams)
# - Sem UI/monitor; roda em servidor e envia alertas para Teams.
# - SSL: use verificação adequada. No servidor, aponte a variável
#   de ambiente SSL_CERT_FILE ou REQUESTS_CA_BUNDLE para o bundle
#   de CA válido (ex.: .pem fornecido pela infra) ou ajuste VERIFY_CA.
# ===========================================

# Imports principais: bibliotecas nativas e de terceiros usadas em toda a aplicacao.
import os
import json
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import threading
from datetime import datetime, timedelta, time as dtime
from pathlib import Path
from requests import Session
from requests.exceptions import Timeout
import requests
import re
import atexit
import sys
import socket
import signal
from statistics import median

# =========================
# CONFIGURACAO (EDITAR AQUI)
# =========================
PVOP_BASE_URL = "https://apipv.pvoperation.com.br/api/v1"
PVOP_EMAIL = "monitoramento@settaenergia.com.br"
PVOP_PASSWORD = "$$Setta1324"
TEAMS_WEBHOOK_URL = "https://settaenergiarecife.webhook.office.com/webhookb2/ff6efec5-9ceb-4932-89ba-d4d8082a1975@77b21bc1-b0b7-4df6-9225-2e24fc9de0f6/IncomingWebhook/38f7efca2b124a17abc7dcc8a5a40c95/a29266d7-870f-4855-96b0-c21a4710f37b/V2rB2XbXOgznVTxAoIWIeDPnlRZ203j0jsNsLKr4cNK141"
TEAMS_ENABLED = True
# =========================

# Lock de instância: fcntl (Unix) ou msvcrt (Windows)
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
STOP_JOIN_TIMEOUT = 35        # aguarda encerramento das threads antes de forcar saida
HEARTBEAT_TIMES = [
    dtime(7, 0),
    dtime(12, 0),
    dtime(17, 0),
    dtime(20, 0),
    dtime(23, 0)
]

# alias para compatibilidade interna
BASE_URL = PVOP_BASE_URL

# SSL: ajuste para o bundle correto no servidor (ex.: /etc/ssl/certs/ca.pem)
VERIFY_CA = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or True

# Diretórios/arquivos de controle
BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "monitor_state.json"
LOCK_FILE = STATE_DIR / ".monitor_lock"
LOG_DIR = BASE_DIR / "logs"
LOG_RELE_DIR = LOG_DIR / "rele"
LOG_INV_DIR = LOG_DIR / "inversor"

# evite reprocessar a borda final da janela (pula 1 segundo além do último fim)
WINDOW_DELTA_SECONDS = 1
STATE_SCHEMA_VERSION = 1


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

    logger_rele = logging.getLogger("RelayMonitorHeadless.rele")
    logger_rele.setLevel(logging.INFO)
    logger_rele.handlers.clear()
    try:
        LOG_RELE_DIR.mkdir(parents=True, exist_ok=True)
        LOG_INV_DIR.mkdir(parents=True, exist_ok=True)
        h_rele = TimedRotatingFileHandler(LOG_RELE_DIR / "rele.log", when="midnight", backupCount=7, encoding="utf-8")
        h_rele.setLevel(logging.INFO)
        h_rele.setFormatter(fmt)
        logger_rele.addHandler(h_rele)
    except Exception as e:
        base_logger.warning(f"Falha ao inicializar log de rele em arquivo: {e}")
    logger_rele.propagate = True

    logger_inv = logging.getLogger("RelayMonitorHeadless.inversor")
    logger_inv.setLevel(logging.INFO)
    logger_inv.handlers.clear()
    try:
        h_inv = TimedRotatingFileHandler(LOG_INV_DIR / "inversor.log", when="midnight", backupCount=7, encoding="utf-8")
        h_inv.setLevel(logging.INFO)
        h_inv.setFormatter(fmt)
        logger_inv.addHandler(h_inv)
    except Exception as e:
        base_logger.warning(f"Falha ao inicializar log de inversor em arquivo: {e}")
    logger_inv.propagate = True


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
        missing.append("PVOP_EMAIL")
    if _is_placeholder(PVOP_PASSWORD):
        missing.append("PVOP_PASSWORD")
    if missing:
        raise SystemExit(
            "Configuracao obrigatoria ausente ou placeholder: "
            + ", ".join(missing)
            + ". Edite a secao CONFIGURACAO no topo do maindebug.py."
        )
    if TEAMS_ENABLED and _is_placeholder(TEAMS_WEBHOOK_URL):
        raise SystemExit(
            "TEAMS_ENABLED=True, mas TEAMS_WEBHOOK_URL esta ausente ou placeholder. "
            "Edite a secao CONFIGURACAO no topo do maindebug.py."
        )

# Envia cartao padrao (MessageCard) para Teams quando alertas ocorrem.
def _teams_post_card(title, text, severity="info", facts=None):
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
    max_tentativas = 3
    backoff_base = 2
    for tentativa in range(1, max_tentativas + 1):
        try:
            r = requests.post(
                TEAMS_WEBHOOK_URL,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            r.raise_for_status()
            return True
        except Exception as e:
            if tentativa == max_tentativas:
                logger.warning(f"[TEAMS] Falha ao enviar webhook: {e}")
                return False
            time.sleep(backoff_base * tentativa)
    return False


# Cliente responsavel por autenticar na API PVOperation e expor chamadas encapsuladas.
class PVOperationAPI:
    """Cliente da API PVOperation com retry e verificação SSL configurável."""

    # Inicializa credenciais, sessao HTTP e dispara autenticacao inicial.
    def __init__(self, email, password, base_url=BASE_URL, verify=VERIFY_CA):
        self.email = email
        self.password = password
        self.base_url = base_url
        self._verify = verify  # guarda configuracao de verificacao SSL
        self.session = Session()
        self.session.verify = self._verify
        self.token = None
        self.headers = {}
        self._login()

    def _reset_session(self):
        try:
            self.session.close()
        except Exception:
            pass
        self.session = Session()
        self.session.verify = self._verify

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
    def get_plants(self):
        url = f"{self.base_url}/plants"
        try:
            r = self.session.get(url, headers=self.headers, timeout=20)
            if r.status_code == 401:
                if not self.verificar_token():
                    return []
                r = self.session.get(url, headers=self.headers, timeout=20)
            if r.status_code == 200:
                return r.json() or []
            logger.error(f"Erro ao buscar plantas. Status: {r.status_code}")
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            logger.warning(f"Erro de conexão em get_plants: {e}. Tentando recriar sessão e reautenticar.")
            self._reset_session()
            if self._login():
                try:
                    r = self.session.get(url, headers=self.headers, timeout=20)
                    if r.status_code == 200:
                        return r.json() or []
                except Exception as e2:
                    logger.error(f"Falha ao repetir get_plants após recriar sessão: {e2}")
        except Exception as e:
            logger.error(f"Exceção em get_plants: {e}")
        return []

    # Faz chamada para endpoint diario (day_*) com retry e backoff exponencial leve.
    def post_day(self, endpoint: str, plant_id: int, date: datetime):
        """Chama endpoints day_* com retry/backoff. Retorna (dados ou None, timeout_flag)."""
        payload = {"id": int(plant_id), "date": date.strftime("%Y-%m-%d")}
        url = f"{self.base_url}/{endpoint}"
        max_tentativas = 3
        backoff_base = 2

        for tentativa in range(1, max_tentativas + 1):
            try:
                r = self.session.post(url, json=payload, headers=self.headers, timeout=30)
            except Timeout:
                logger.warning(
                    f"Timeout em {endpoint} (usina {plant_id}, {date.date()}) - "
                    f"tentativa {tentativa}/{max_tentativas}."
                )
                if tentativa == max_tentativas:
                    return None, True
                time.sleep(backoff_base * tentativa)
                continue
            except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                logger.warning(
                    f"Erro de conexão em {endpoint} (usina {plant_id}): {e}. Tentando recriar sessão."
                )
                self._reset_session()
                if not self._login():
                    return None, False
                if tentativa == max_tentativas:
                    return None, False
                time.sleep(backoff_base * tentativa)
                continue
            except Exception as e:
                logger.error(f"Erro em {endpoint}: {e}")
                return None, False

            if r.status_code == 401:
                if not self.verificar_token():
                    return None, False
                time.sleep(1)
                continue

            if r.status_code == 200:
                return r.json(), False

            logger.warning(
                f"Status {r.status_code} em {endpoint} (usina {plant_id}, {date.date()}) - "
                f"tentativa {tentativa}/{max_tentativas}."
            )
            if tentativa == max_tentativas:
                return None, False
            time.sleep(backoff_base * tentativa)
        return None, False


# Normaliza valores numericos vindos como string ou numero bruto para float.
def extrair_valor_numerico(valor):
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


# Varre leituras de rele no intervalo informado para encontrar eventos e classifica-los.
def detectar_alertas_rele(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime):
    def _valor_ativo(valor):
        if isinstance(valor, bool):
            return valor
        if isinstance(valor, (int, float)):
            return valor == 1
        if isinstance(valor, str):
            txt = valor.strip().lower()
            if txt in {"true", "1"}:
                return True
            try:
                return float(txt) == 1.0
            except Exception:
                return False
        return False

    PARAMS_CLASSIF = {
        "SOBRETENSÃO": {"r59A", "r59B", "r59C", "r59N"},
        "SUBTENSÃO": {"r27A", "r27B", "r27C", "r27_0"},
        "FREQUÊNCIA": {"r81O", "r81U"},
        "TÉRMICO": {"r49", "r49_2"},
        "BLOQUEIO": {"rAR", "rBA", "rDO"},
    }
    PARAMETROS_RELE = {
        "r27A","r27B","r27C","r27_0","r32A","r32A_2","r32B","r32B_2","r32C","r32C_2",
        "r46Q","r47","r59A","r59B","r59C","r59N","r67A","r67A_2","r67B","r67B_2",
        "r67C","r67C_2","r67N_1","r67N_2","r78","r81O","r81U","r86","rAR","rBA",
        "rDO","rEPwd","rERLS","rEl2t","rFR","rGS","rHLT","rRL1","rRL2","rRL3",
        "rRL4","rRL5","rRR","r49","r49_2"
    }

    candidatos = []
    tem_dados = False
    tem_resposta = False
    teve_timeout = False

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag:
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue

        if isinstance(data_resp, list):
            tem_dados = True
        else:
            logger_rele.warning(f"Resposta inesperada em day_relay (usina {plant_id}): {type(data_resp).__name__}")
            d += timedelta(days=1)
            continue

        for registro in (data_resp or []):
            if not isinstance(registro, dict):
                logger_rele.warning(f"Item inesperado em day_relay (usina {plant_id}): {type(registro).__name__}")
                continue
            conteudo_raw = registro.get("conteudojson", {})
            if not isinstance(conteudo_raw, dict):
                logger_rele.warning(
                    f"conteudojson invalido em day_relay (usina {plant_id}): {type(conteudo_raw).__name__}"
                )
                continue
            conteudo = conteudo_raw
            idrele = registro.get("idrele")
            if not idrele:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if not (inicio <= ts <= fim):
                continue

            ativos = [p for p in PARAMETROS_RELE if _valor_ativo(conteudo.get(p))]
            if not ativos:
                continue

            tipo = "OUTROS"
            for classe, lista in PARAMS_CLASSIF.items():
                if any(p in lista for p in ativos):
                    tipo = classe
                    break

            candidatos.append(
                {
                    "ts_leitura": ts,
                    "rele_id": idrele,
                    "parametros": ", ".join(sorted(ativos)),
                    "tipo_alerta": tipo,
                }
            )
        d += timedelta(days=1)

    if not candidatos:
        return [], tem_dados, teve_timeout

    candidatos.sort(key=lambda a: a["ts_leitura"])
    return candidatos, tem_dados, teve_timeout


# Avalia leituras de inversores para identificar falha (Pac 0) e recuperacao (Pac > 0).
def detectar_falhas_inversores(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime, falhas_ativas_previas: dict):
    JANELA_INICIO = dtime(6, 30)
    JANELA_FIM = dtime(17, 30)

    leituras_por_inv = {}
    tem_dados = False
    tem_resposta = False
    teve_timeout = False

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag:
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue
        if not isinstance(data_resp, list):
            logger_inv.warning(f"Resposta inesperada em day_inverter (usina {plant_id}): {type(data_resp).__name__}")
            d += timedelta(days=1)
            continue
        tem_resposta = True

        for reg in (data_resp or []):
            if not isinstance(reg, dict):
                logger_inv.warning(f"Item inesperado em day_inverter (usina {plant_id}): {type(reg).__name__}")
                continue
            conteudo_raw = reg.get("conteudojson", {})
            if not isinstance(conteudo_raw, dict):
                logger_inv.warning(
                    f"conteudojson invalido em day_inverter (usina {plant_id}): {type(conteudo_raw).__name__}"
                )
                continue
            conteudo = conteudo_raw
            inv_id = reg.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if not inv_id:
                continue
            inv_id = str(inv_id)
            try:
                ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if not (inicio <= ts <= fim):
                continue
            if not (JANELA_INICIO <= ts.time() <= JANELA_FIM):
                continue

            pac_raw = None
            for k in ("Pac", "PAC", "Potencia_Saida", "Pout", "Potencia"):
                if k in conteudo:
                    pac_raw = conteudo.get(k)
                    break

            if pac_raw is None:
                leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "cond_ok": False, "sem_dados": True, "pac": None})
                continue

            pac = extrair_valor_numerico(pac_raw)
            if pac is None:
                leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "cond_ok": False, "sem_dados": True, "pac": None})
                continue

            cond = pac == 0.0
            leituras_por_inv.setdefault(inv_id, []).append({"ts": ts, "cond_ok": cond, "sem_dados": False, "pac": pac})
            tem_dados = True
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
        last_valid_ts = None

        for item in lst:
            ts = item["ts"]
            if item["sem_dados"]:
                continue
            if last_valid_ts and expected_interval and (ts - last_valid_ts) > (expected_interval * 2):
                seq_zero = 0
                rec_seq = 0

            pac_zero = item["cond_ok"]  # True se potência == 0.0
            if pac_zero:
                seq_zero = seq_zero + 1
                rec_seq = 0
            else:
                seq_zero = 0
                rec_seq = rec_seq + 1
            last_valid_ts = ts

            if seq_zero >= 3 and not ativa:
                falhas.append(
                    {
                        "inversor_id": str(inv_id),
                        "ts_leitura": ts,
                        "status": "FALHA",
                        "indicadores": {"pac": 0.0},
                    }
                )
                ativa = True
                rec_seq = 0

            if ativa and rec_seq >= 3:
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

        falhas_ativas[state_key] = {"ativa": ativa, "rec_seq": rec_seq, "seq_zero": seq_zero}

    def _intervalo_atinge_janela(inicio_dt: datetime, fim_dt: datetime) -> bool:
        if fim_dt < inicio_dt:
            return False
        dia = inicio_dt.date()
        while dia <= fim_dt.date():
            janela_ini = datetime.combine(dia, JANELA_INICIO)
            janela_fim = datetime.combine(dia, JANELA_FIM)
            if inicio_dt <= janela_fim and fim_dt >= janela_ini:
                return True
            dia += timedelta(days=1)
        return False

    # Fora da janela de geração, lista vazia não deve bloquear avanço de janela
    dentro_janela = _intervalo_atinge_janela(inicio, fim)
    tem_dados_efetivo = tem_dados or (tem_resposta and not dentro_janela)
    return falhas, recuperados, tem_dados_efetivo, falhas_ativas, teve_timeout


# Servico central que orquestra varreduras de reles/inversores e envia notificacoes.
class MonitorService:
    """Serviço headless: varre relés e inversores e notifica Teams."""

    def _init_state_defaults(self):
        self.ultima_varredura_rele = None
        self.ultima_varredura_inversor = None
        self.ultima_varredura_rele_por_usina = {}
        self.ultima_varredura_inversor_por_usina = {}
        self.rele_alertas_ativos = set()      # usina:rele:tipo
        self.rele_alerta_chave = {}
        self.rele_notificados = set()
        self.estado_inversores = {}           # usina:inv -> estado (seq + alerta)
        self.pending_notifications = {"rele_normalizados": {}, "inv_normalizados": {}}
        self.usinas_alerta_rele_recente = set()

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

    # Inicia o monitor em modo daemon criando threads de varredura.
    def start(self):
        self._acquire_lock()
        self._load_state()
        atexit.register(self._shutdown_cleanup)
        self._threads = [
            threading.Thread(target=self._loop_scans, daemon=True),
            threading.Thread(target=self._loop_heartbeat, daemon=True),
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
            logger.warning("Lock mantido porque ainda existem threads ativas.")
            return
        self._save_state()
        self._release_lock()

    # Cria lock de arquivo para evitar multiplas instancias simultaneas.
    def _acquire_lock(self):
        try:
            self._lock_fd = open(LOCK_FILE, "a+")
            self._lock_fd.seek(0)
            if os.name == "nt":
                if not msvcrt:
                    raise RuntimeError("Lock de Windows nÇœo disponÇ­vel (msvcrt ausente).")
                try:
                    msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise BlockingIOError("Lock jÇ  ativa em Windows.")
            else:
                if not fcntl:
                    raise RuntimeError("Lock de Unix nÇœo disponÇ­vel (fcntl ausente).")
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
            self.ultima_varredura_rele_por_usina = {}
            raw_rele_por_usina = data.get("ultima_varredura_rele_por_usina", {})
            if isinstance(raw_rele_por_usina, dict):
                for usina_id, ts in raw_rele_por_usina.items():
                    if not ts:
                        continue
                    try:
                        self.ultima_varredura_rele_por_usina[str(usina_id)] = datetime.fromisoformat(ts)
                    except Exception:
                        continue
            self.ultima_varredura_inversor_por_usina = {}
            raw_inv_por_usina = data.get("ultima_varredura_inversor_por_usina", {})
            if isinstance(raw_inv_por_usina, dict):
                for usina_id, ts in raw_inv_por_usina.items():
                    if not ts:
                        continue
                    try:
                        self.ultima_varredura_inversor_por_usina[str(usina_id)] = datetime.fromisoformat(ts)
                    except Exception:
                        continue
            self.rele_alertas_ativos = set(data.get("rele_alertas_ativos", []))
            self.rele_notificados = set(data.get("rele_notificados", []))
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
                        self.estado_inversores[estado_key] = entry
            # recalcula usinas com rele ativo a partir do estado persistido
            self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}
            logger.info("Estado carregado do disco.")
        except (json.JSONDecodeError, ValueError) as e:
            self._backup_corrupt_state(str(e))
            self._init_state_defaults()
            self._save_state()
        except Exception as e:
            logger.warning(f"Não foi possível carregar estado salvo: {e}")

    # Salva em disco o ponto de controle atual das varreduras e alertas ativos.
    def _save_state(self):
        try:
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
                "rele_alerta_chave": self.rele_alerta_chave,
                "estado_inversores": self.estado_inversores,
                "pending_notifications": self.pending_notifications,
            }
            tmp_path = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
            with self._state_lock:
                tmp_path.write_text(json.dumps(payload), encoding="utf-8")
                os.replace(tmp_path, STATE_FILE)
        except Exception as e:
            logger.warning(f"Falha ao salvar estado: {e}")

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

    def _loop_rele(self):
        while not self.stop_event.is_set():
            try:
                self.executar_varredura_rele()
            except Exception:
                logger.exception("Erro na varredura de relé")
            self.stop_event.wait(RELAY_INTERVAL)

    # Loop continuo que dispara varredura de inversores no intervalo definido.
    def _loop_inversor(self):
        while not self.stop_event.is_set():
            try:
                self.executar_varredura_inversor()
            except Exception:
                logger_inv.exception("Erro na varredura de inversor")
            self.stop_event.wait(INVERTER_INTERVAL)

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

    # Busca alertas de rele nas usinas e dispara notificacoes unicas por evento.
    def executar_varredura_rele(self):
        with self._scan_lock:
            agora = datetime.now()
            # começa no último fim de varredura + delta; primeira vez vai até 00:00
            if self.ultima_varredura_rele:
                inicio_padrao = self.ultima_varredura_rele + timedelta(seconds=WINDOW_DELTA_SECONDS)
            else:
                inicio_padrao = datetime.combine(agora.date(), datetime.min.time())
            logger_rele.info("Varredura de rele iniciada.")
            sem_plantas = False
            pend_norm = self.pending_notifications.setdefault("rele_normalizados", {})

            plantas = self.api_rele.get_plants()
            if not plantas:
                logger_rele.warning("Nenhuma usina encontrada (rele).")
                # mantem/recalcula bloqueios a partir dos alertas ativos conhecidos
                self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}
                sem_plantas = True
                plantas = []

            bases_ativos_atual = set()
            novos_por_usina = {}
            resolvidos_por_usina = {}
            usinas_sem_dados = set()

            for p in plantas:
                usina_id_raw = p.get("id")
                try:
                    usina_id_int = int(usina_id_raw)
                except (TypeError, ValueError):
                    logger_rele.warning(f"Usina com id inválido (rele): {usina_id_raw!r}. Pulando.")
                    continue
                usina_id = str(usina_id_int)
                nome = p.get("nome")
                cap = p.get("capacidade")

                last_usina = self.ultima_varredura_rele_por_usina.get(usina_id)
                if last_usina:
                    inicio_janela = last_usina + timedelta(seconds=WINDOW_DELTA_SECONDS)
                else:
                    inicio_janela = inicio_padrao

                alertas, tem_dados, teve_timeout = detectar_alertas_rele(self.api_rele, usina_id, inicio_janela, agora)
                if not tem_dados:
                    motivo = "TIMEOUT" if teve_timeout else "SEM_DADOS"
                    logger_rele.warning(f"Sem dados de relé em {nome} (motivo: {motivo}). Mantendo alertas ativos.")
                    usinas_sem_dados.add(usina_id)
                    continue
                if teve_timeout:
                    logger_rele.warning(
                        f"Dados parciais de relé em {nome} (motivo: TIMEOUT_PARCIAL). Mantendo alertas ativos."
                    )
                    usinas_sem_dados.add(usina_id)
                    continue

                for a in alertas:
                    base = f"{usina_id}:{a['rele_id']}:{a['tipo_alerta']}"
                    pend_list = pend_norm.get(usina_id, [])
                    if pend_list:
                        pend_norm[usina_id] = [i for i in pend_list if i.get("base") != base]
                        if not pend_norm[usina_id]:
                            pend_norm.pop(usina_id, None)
                    bases_ativos_atual.add(base)
                    ts_first = a.get("ts_primeiro", a["ts_leitura"])
                    ts_last = a.get("ts_ultimo", a["ts_leitura"])
                    intervalo_txt = self.formatar_intervalo_alerta(ts_first, ts_last)
                    alerta_fmt = {
                        "base": base,
                        "usina": nome,
                        "capacidade": cap,
                        "rele": a["rele_id"],
                        "horario": a["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                        "tipo": a["tipo_alerta"],
                        "ts_iso": a["ts_leitura"].isoformat(),
                        "parametros": f"{a['parametros']} | {intervalo_txt}" if intervalo_txt else a["parametros"],
                    }

                    if base in self.rele_alertas_ativos:
                        # atualiza detalhes com o último evento
                        self.rele_alerta_chave[base] = alerta_fmt
                        if base not in self.rele_notificados:
                            novos_por_usina.setdefault(
                                usina_id, {"usina": nome, "capacidade": cap, "itens": []}
                            )["itens"].append(alerta_fmt)
                        continue

                    self.rele_alertas_ativos.add(base)
                    self.rele_alerta_chave[base] = alerta_fmt
                    novos_por_usina.setdefault(usina_id, {"usina": nome, "capacidade": cap, "itens": []})["itens"].append(alerta_fmt)

                if not teve_timeout:
                    self.ultima_varredura_rele_por_usina[usina_id] = agora

            if usinas_sem_dados:
                for base in self.rele_alertas_ativos:
                    if base.split(":", 1)[0] in usinas_sem_dados:
                        bases_ativos_atual.add(base)
            resolved = self.rele_alertas_ativos - bases_ativos_atual
            for base in resolved:
                alerta_antigo = self.rele_alerta_chave.get(base)
                self.rele_alertas_ativos.discard(base)
                self.rele_alerta_chave.pop(base, None)
                self.rele_notificados.discard(base)
                if alerta_antigo:
                    usina_id, rele_id, tipo = base.split(":", 2)
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
            # recalcula usinas com rele ativo a partir do conjunto de alertas ativos
            self.usinas_alerta_rele_recente = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}

            # envia uma notificação por usina consolidando alertas novos, normalizados e pendentes
            def _dedupe_por_base(itens):
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
                def _ts_key(item):
                    ts = item.get("ts_iso")
                    if not ts:
                        return datetime.min
                    try:
                        return datetime.fromisoformat(ts)
                    except Exception:
                        return datetime.min
                pacote["novos"] = sorted(pacote["novos"], key=_ts_key)
                pacote["normalizados"] = sorted(pacote["normalizados"], key=_ts_key)
                if not pacote["novos"] and not pacote["normalizados"]:
                    continue

                ok_novos, ok_norm = self._notificar_rele_agrupado(pacote)
                if pacote["novos"] and ok_novos:
                    for item in pacote["novos"]:
                        base = item.get("base")
                        if base:
                            self.rele_notificados.add(base)
                if pacote["normalizados"]:
                    if ok_norm:
                        bases_norm = {item.get("base") for item in pacote["normalizados"] if item.get("base")}
                        if bases_norm and usina_id in pend_norm:
                            pend_norm[usina_id] = [
                                i for i in pend_norm.get(usina_id, []) if i.get("base") not in bases_norm
                            ]
                            if not pend_norm[usina_id]:
                                pend_norm.pop(usina_id, None)
                    else:
                        pend_list = pend_norm.setdefault(usina_id, [])
                        existentes = {i.get("base") for i in pend_list if i.get("base")}
                        for item in pacote["normalizados"]:
                            base = item.get("base")
                            if base and base in existentes:
                                continue
                            pend_list.append(item)
                            if base:
                                existentes.add(base)

            if not sem_plantas:
                self.ultima_varredura_rele = agora
            # salva estado ao fim da varredura para evitar retrabalho após quedas
            self._save_state()
            logger_rele.info("Varredura de rele concluida.")

    # Analisa inversores e alerta se houver falha persistente ou recuperacao.
    def executar_varredura_inversor(self):
        with self._scan_lock:
            agora = datetime.now()
            if self.ultima_varredura_inversor:
                inicio_padrao = self.ultima_varredura_inversor + timedelta(seconds=WINDOW_DELTA_SECONDS)
            else:
                inicio_padrao = datetime.combine(agora.date(), datetime.min.time())
            logger_inv.info("Varredura de inversor iniciada.")
            sem_plantas = False
            pend_norm = self.pending_notifications.setdefault("inv_normalizados", {})

            def _reenviar_normalizacoes_pendentes():
                if not pend_norm:
                    return
                for chave, payload in list(pend_norm.items()):
                    usina_id = chave.split(":", 1)[0] if ":" in chave else None
                    if usina_id and usina_id in self.usinas_alerta_rele_recente:
                        continue
                    alerta = payload.get("alerta") if isinstance(payload, dict) else None
                    alerta_prev = payload.get("alerta_prev") if isinstance(payload, dict) else None
                    if not isinstance(alerta, dict):
                        pend_norm.pop(chave, None)
                        continue
                    if self._notificar_inversor_recuperado(alerta, alerta_prev):
                        pend_norm.pop(chave, None)

            plantas = self.api_inversor.get_plants()
            if not plantas:
                logger_inv.warning("Nenhuma usina encontrada (inversor).")
                sem_plantas = True
                plantas = []

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
                    self.ultima_varredura_inversor_por_usina[usina_id] = agora
                    continue

                nome = p.get("nome")
                cap = p.get("capacidade")

                last_usina = self.ultima_varredura_inversor_por_usina.get(usina_id)
                if last_usina:
                    inicio_janela = last_usina + timedelta(seconds=WINDOW_DELTA_SECONDS)
                else:
                    inicio_janela = inicio_padrao

                falhas, recuperados, tem_dados_inv, falhas_ativas_atual, teve_timeout = detectar_falhas_inversores(
                    self.api_inversor, usina_id, inicio_janela, agora, self.estado_inversores
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

                tentativas_envio = set()

                for tipo, _, item in eventos:
                    if tipo == "rec":
                        inv_base = item["inversor_id"]
                        chave_inv = f"{usina_id}:{inv_base}"
                        alerta_prev = self.estado_inversores.get(chave_inv, {}).get("alerta")
                        alerta = {
                            "usina": nome,
                            "capacidade": cap,
                            "inversor": inv_base,
                            "horario": item["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                            "ts_iso": item["ts_leitura"].isoformat(),
                            "status": item["status"],
                            "indicadores": item.get("indicadores", {}),
                        }
                        enviado = self._notificar_inversor_recuperado(alerta, alerta_prev)
                        if enviado:
                            pend_norm.pop(chave_inv, None)
                        else:
                            pend_norm[chave_inv] = {"alerta": alerta, "alerta_prev": alerta_prev}
                        if chave_inv in self.estado_inversores:
                            self.estado_inversores[chave_inv]["alerta"] = None
                            self.estado_inversores[chave_inv]["notificado"] = False
                        tentativas_envio.add(chave_inv)
                    else:
                        chave_inv = f"{usina_id}:{item['inversor_id']}"
                        pend_norm.pop(chave_inv, None)
                        entry = self.estado_inversores.get(
                            chave_inv,
                            {"ativa": True, "rec_seq": 0, "seq_zero": 0, "alerta": None, "notificado": False},
                        )
                        alerta = {
                            "usina": nome,
                            "capacidade": cap,
                            "inversor": item["inversor_id"],
                            "horario": item["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                            "ts_iso": item["ts_leitura"].isoformat(),
                            "status": item["status"],
                            "indicadores": item.get("indicadores", {}),
                        }
                        entry["alerta"] = alerta
                        if not entry.get("notificado", False):
                            enviado = self._notificar_inversor(alerta)
                            entry["notificado"] = bool(enviado)
                            tentativas_envio.add(chave_inv)
                        self.estado_inversores[chave_inv] = entry

                if not tem_dados_inv:
                    motivo = "TIMEOUT" if teve_timeout else "SEM_DADOS"
                    logger_inv.warning(f"Sem dados de inversor em {nome} (motivo: {motivo}).")

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
                    if self._notificar_inversor(alerta):
                        estado["notificado"] = True
                        self.estado_inversores[chave_inv] = estado

                for chave_inv, estado in falhas_ativas_atual.items():
                    if isinstance(estado, bool):
                        estado = {"ativa": estado}
                    if not isinstance(estado, dict):
                        continue
                    prev_entry = self.estado_inversores.get(chave_inv, {})
                    entry = {
                        "ativa": bool(estado.get("ativa", False)),
                        "rec_seq": int(estado.get("rec_seq", 0)),
                        "seq_zero": int(estado.get("seq_zero", 0)),
                        "alerta": prev_entry.get("alerta"),
                        "notificado": bool(prev_entry.get("notificado", False)),
                    }
                    if not entry["ativa"]:
                        entry["alerta"] = None
                        entry["notificado"] = False
                    self.estado_inversores[chave_inv] = entry

                if tem_dados_inv:
                    self.ultima_varredura_inversor_por_usina[usina_id] = agora

            _reenviar_normalizacoes_pendentes()
            if not sem_plantas:
                self.ultima_varredura_inversor = agora
            # salva estado ao fim da varredura para evitar retrabalho após quedas
            self._save_state()
            logger.info("Varredura de inversor concluída.")

    # Formata intervalo de tempo das leituras para texto amigavel.
    @staticmethod
    def formatar_intervalo_alerta(ts_first, ts_last) -> str:
        if not ts_first or not ts_last:
            return ""
        if ts_first == ts_last:
            return f"Alerta às {ts_first.strftime('%H:%M')}"
        return f"Primeiro alerta às {ts_first.strftime('%H:%M')} e último às {ts_last.strftime('%H:%M')}"

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
        with self._scan_lock:
            rele_alertas = list(self.rele_alertas_ativos)
            rele_alerta_chave = dict(self.rele_alerta_chave)
            estado_inversores = dict(self.estado_inversores)
            ativos_rele = len(rele_alertas)
            ativos_inv = sum(1 for estado in estado_inversores.values() if estado.get("ativa"))
            ultima_rele = self.ultima_varredura_rele
            ultima_inv = self.ultima_varredura_inversor

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
                if not estado.get("ativa"):
                    continue
                alerta = estado.get("alerta") or {}
                nome = alerta.get("usina")
                if not nome and isinstance(chave, str) and ":" in chave:
                    nome = f"Usina {chave.split(':', 1)[0]}"
                if not nome:
                    continue
                inv_usina_counts[nome] = inv_usina_counts.get(nome, 0) + 1

        info = [
            "Heartbeat: monitor rodando",
            "Status: OK",
            f"Última varredura relé: {ultima_rele.strftime('%d/%m %H:%M:%S') if ultima_rele else 'N/D'}",
            f"Última varredura inversor: {ultima_inv.strftime('%d/%m %H:%M:%S') if ultima_inv else 'N/D'}",
            f"Host/PID: {socket.gethostname()} / {os.getpid()}",
            f"Heartbeat previsto: {previsto.strftime('%d/%m %H:%M')}",
            f"Alertas de relé ativos: {ativos_rele}",
        ]
        if rele_usinas:
            for nome in rele_usinas:
                info.append(f"  {nome}")
        info.append(f"Alertas de inversor ativos: {ativos_inv}")
        if inv_usina_counts:
            for nome in sorted(inv_usina_counts):
                info.append(f"  {nome} ({inv_usina_counts[nome]})")
        texto = "  \n".join(info)
        logger.info(f"[HEARTBEAT] {texto.replace('  \n', ' | ')}")
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
    def _notificar_rele_agrupado(self, pacote):
        novos = pacote.get("novos", []) or []
        normalizados = pacote.get("normalizados", []) or []
        if not novos and not normalizados:
            return True, True

        def _formatar_blocos(itens):
            blocos = []
            for it in itens:
                blocos.append(
                    "  \n".join(
                        [
                            f"Relé: {it.get('rele','N/A')}",
                            f"Tipo: {it.get('tipo','N/A')}",
                            f"Horário: {it.get('horario','?')}",
                            f"Parâmetros: {it.get('parametros','')}",
                        ]
                    )
                )
            return "  \n  \n".join(blocos)

        cap_txt = f"{pacote.get('capacidade','N/A')} kWp"
        facts = [("Capacidade", cap_txt)]
        usina = pacote.get("usina", "N/A")
        severos = {"SOBRETENSÃO", "TÉRMICO", "BLOQUEIO"}
        severity_falha = "danger" if any(i.get("tipo") in severos for i in novos) else "warning"

        ok_novos = True
        if novos:
            texto = _formatar_blocos(novos)
            logger_rele.warning(
                f"[RELE] Falha | Usina: {usina} | Itens: {len(novos)} | "
                + texto.replace("  \n", " | ")
            )
            try:
                ok_novos = _teams_post_card(
                    title=f"⚠️ Falha de relé - {usina}",
                    text=f"  \n{texto}",
                    severity=severity_falha,
                    facts=facts,
                )
            except Exception:
                logger_rele.exception("Falha ao notificar Teams (rele falha)")
                ok_novos = False

        ok_norm = True
        if normalizados:
            texto = _formatar_blocos(normalizados)
            logger_rele.info(
                f"[RELE] Normalizacao | Usina: {usina} | Itens: {len(normalizados)} | "
                + texto.replace("  \n", " | ")
            )
            try:
                ok_norm = _teams_post_card(
                    title=f"✔️ Normalização de relé - {usina}",
                    text=f"  \n{texto}",
                    severity="info",
                    facts=facts,
                )
            except Exception:
                logger_rele.exception("Falha ao notificar Teams (rele normalizacao)")
                ok_norm = False

        return ok_novos, ok_norm

    # Monta mensagem de falha de inversor (Pac zerado) e envia para Teams.
    def _notificar_inversor(self, alerta):
        inds = alerta.get("indicadores", {})
        detalhes_txt = f"Pac: {inds.get('pac','N/A')}"
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"Inversor: {alerta['inversor']}\n"
            f"Status: {alerta['status']}\n"
            f"Horário: {alerta['horario']}\n"
            f"{detalhes_txt}"
        )
        logger_inv.warning(f"[ALERTA INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            return _teams_post_card(
                title="⚠️ Falha de Inversor (Pac=0; 3 leituras; 06:30-17:30)",
                text=(
                    f"**Usina:** {alerta['usina']}  \n"
                    f"**Inversor:** {alerta['inversor']}  \n"
                    f"**Horário:** {alerta['horario']}  \n"
                    f"**Detalhes:** {detalhes_txt}"
                ),
                severity="danger",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (inversor)")
            return False

    # Comunica quando um inversor voltou a produzir apos falha de Pac 0.
    def _notificar_inversor_recuperado(self, alerta, alerta_prev=None):
        inds = alerta.get("indicadores", {})
        detalhes_txt = f"Pac: {inds.get('pac','N/A')}"
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"Inversor: {alerta['inversor']}\n"
            f"Status: {alerta['status']}\n"
            f"Horário: {alerta['horario']}\n"
            f"{detalhes_txt}"
        )
        logger_inv.info(f"[RECUPERACAO INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            return _teams_post_card(
                title="✔️ Normalização de Inversor (Pac=0; 3 leituras; 06:30-17:30)",
                text=(
                    f"**Usina:** {alerta['usina']}  \n"
                    f"**Inversor:** {alerta['inversor']}  \n"
                    f"**Horário:** {alerta['horario']}  \n"
                    f"**Detalhes:** {detalhes_txt}"
                ),
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
