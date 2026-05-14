"""
Monitor de RelÃ©s/Inversores executando como daemon (processo Ãºnico).

MantÃ©m a mesma lÃ³gica de detecÃ§Ã£o do main.py original, porÃ©m estruturado
para rodar como serviÃ§o de longa duraÃ§Ã£o, sem depender de cron e evitando
instÃ¢ncias sobrepostas.
"""

import os
import sys
import json
import time
import atexit
import logging
import threading
from datetime import datetime, timedelta, time as dtime
from pathlib import Path
from requests import Session
from requests.exceptions import Timeout
import requests
import re

# --- ConfiguraÃ§Ã£o geral ---
RELAY_INTERVAL = 600          # 10 min
INVERTER_INTERVAL = 900       # 15 min

# Configuracao via ambiente, espelhando o main.py.
PVOP_BASE_URL = os.environ.get("PVOP_BASE_URL", "https://apipv.pvoperation.com.br/api/v1").strip()
PVOP_EMAIL = os.environ.get("MONITOR_EMAIL", "").strip()
PVOP_PASSWORD = os.environ.get("MONITOR_PASSWORD", "").strip()
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)

# Aliases mantidos para compatibilidade com usos externos antigos do modulo.
BASE_URL = PVOP_BASE_URL
EMAIL = PVOP_EMAIL
PASSWORD = PVOP_PASSWORD

# SSL
# Pergunta direta: onde estÃ¡ o bundle de certificados CA do servidor?
# Exemplos para preencher: /etc/ssl/certs/ca-bundle.crt (Linux) ou C:\\certs\\ca.pem (Windows)
SSL_BUNDLE = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or ""
VERIFY_CA = SSL_BUNDLE if SSL_BUNDLE else True

# Estado/lock
BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "monitor_state.json"
LOCK_FILE = BASE_DIR / ".monitor_lock"

WINDOW_DELTA_SECONDS = 1

# Apenas estas usinas possuem relÃ© de proteÃ§Ã£o e devem ser varridas no fluxo de relÃ©.
RELE_PLANT_IDS = {
    "19478", "19815", "19816", "21544", "22275", "22283", "22290", "22291",
    "22873", "22874", "24129", "24130", "53209", "53222", "53297", "59991",
    "60003", "60559", "297443", "297444", "297445", "297446", "297449",
    "18744051", "18744052",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("RelayMonitorDaemon")


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


def _teams_post_card(title, text, severity="info", facts=None):
    if not TEAMS_ENABLED:
        return
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
    try:
        r = requests.post(
            TEAMS_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
    except Exception as e:
        logger.warning(f"[TEAMS] Falha ao enviar webhook: {e}")


class PVOperationAPI:
    def __init__(self, email, password, base_url=PVOP_BASE_URL, verify=VERIFY_CA):
        self.email = email
        self.password = password
        self.base_url = base_url
        self.session = Session()
        self.session.verify = verify
        self.token = None
        self.headers = {}
        self._login()

    def _login(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.base_url}/authenticate",
                json={"username": self.email, "password": self.password},
                timeout=20,
            )
            if resp.status_code == 200:
                self.token = resp.json().get("token")
                self.headers = {"x-access-token": self.token}
                logger.info("AutenticaÃ§Ã£o realizada com sucesso.")
                return True
            logger.error(f"Falha na autenticaÃ§Ã£o. Status: {resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"Erro durante login: {e}")
            return False

    def verificar_token(self) -> bool:
        logger.warning("Tentando renovar token...")
        ok = self._login()
        if not ok:
            logger.error("NÃ£o foi possÃ­vel renovar o token.")
        return ok

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
            logger.warning(f"Erro de conexÃ£o em get_plants: {e}. Tentando recriar sessÃ£o e reautenticar.")
            try:
                self.session.close()
            except Exception:
                pass
            self.session = Session()
            self.session.verify = self.session.verify
            if self._login():
                try:
                    r = self.session.get(url, headers=self.headers, timeout=20)
                    if r.status_code == 200:
                        return r.json() or []
                except Exception as e2:
                    logger.error(f"Falha ao repetir get_plants apÃ³s recriar sessÃ£o: {e2}")
        except Exception as e:
            logger.error(f"ExceÃ§Ã£o em get_plants: {e}")
        return []

    def post_day(self, endpoint: str, plant_id: int, date: datetime):
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


def _valor_ativo_rele(valor) -> bool:
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


def detectar_alertas_rele(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime):
    PARAMS_CLASSIF = {
        "SOBRETENSÃƒO": {"r59A", "r59B", "r59C", "r59N"},
        "SUBTENSÃƒO": {"r27A", "r27B", "r27C", "r27_0"},
        "FREQUÃŠNCIA": {"r81O", "r81U"},
        "TÃ‰RMICO": {"r49", "r49_2"},
        "BLOQUEIO": {"rAR", "rBA", "rDO"},
    }
    PARAMETROS_RELE = {
        "r27A", "r27B", "r27C", "r27_0", "r32A", "r32A_2", "r32B", "r32B_2", "r32C", "r32C_2",
        "r46Q", "r47", "r59A", "r59B", "r59C", "r59N", "r67A", "r67A_2", "r67B", "r67B_2",
        "r67C", "r67C_2", "r67N_1", "r67N_2", "r78", "r81O", "r81U", "r86", "rAR", "rBA",
        "rDO", "rEPwd", "rERLS", "rEl2t", "rFR", "rGS", "rHLT", "rRL1", "rRL2", "rRL3",
        "rRL4", "rRL5", "rRR", "r49", "r49_2"
    }

    candidatos = []
    tem_dados = False
    teve_timeout = False

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag:
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue

        for registro in (data_resp or []):
            conteudo = registro.get("conteudojson", {}) or {}
            idrele = registro.get("idrele")
            if not idrele:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if not (inicio <= ts <= fim):
                continue
            tem_dados = True

            ativos = [p for p in PARAMETROS_RELE if _valor_ativo_rele(conteudo.get(p))]
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


def detectar_falhas_inversores(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime, falhas_ativas_previas: dict):
    JANELA_INICIO = dtime(6, 30)
    JANELA_FIM = dtime(17, 0)

    leituras_por_inv = {}
    tem_dados = False
    teve_timeout = False

    d = inicio.date()
    while d <= fim.date():
        data_resp, timeout_flag = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if timeout_flag:
            teve_timeout = True
        if data_resp is None:
            d += timedelta(days=1)
            continue

        for reg in (data_resp or []):
            conteudo = reg.get("conteudojson", {}) or {}
            inv_id = reg.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if not inv_id:
                continue
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
            cond = pac <= 0
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

        state_key = f"{plant_id}:{inv_id}"
        prev_state = falhas_ativas_previas.get(state_key, {"ativa": False, "rec_seq": 0, "seq_zero": 0})
        if isinstance(prev_state, bool):
            prev_state = {"ativa": prev_state, "rec_seq": 0, "seq_zero": 0}
        ativa = bool(prev_state.get("ativa", False))
        rec_seq = int(prev_state.get("rec_seq", 0))
        seq_zero = int(prev_state.get("seq_zero", 0))

        for item in lst:
            ts = item["ts"]
            if item["sem_dados"]:
                continue

            pac_zero = item["cond_ok"]  # True se potÃªncia == 0.0
            if pac_zero:
                seq_zero = seq_zero + 1
                rec_seq = 0
            else:
                seq_zero = 0
                rec_seq = rec_seq + 1

            if seq_zero >= 3 and not ativa:
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

            if ativa and rec_seq >= 2:
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

    return falhas, recuperados, tem_dados, falhas_ativas, teve_timeout


class PIDFileLock:
    """Lock de instÃ¢ncia Ãºnica com arquivo, compatÃ­vel com Windows e Unix."""

    def __init__(self, path: Path):
        self.path = path
        self.fp = None

    def acquire(self):
        self.fp = open(self.path, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fp.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.lockf(self.fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception as e:
            raise RuntimeError(f"Lock ativo ou erro ao criar lock: {e}") from e
        self.fp.seek(0)
        self.fp.truncate(0)
        self.fp.write(str(os.getpid()))
        self.fp.flush()

    def release(self):
        if not self.fp:
            return
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fp.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.lockf(self.fp, fcntl.LOCK_UN)
        finally:
            self.fp.close()
            self.fp = None


class MonitorDaemon:
    """Processo Ãºnico com duas threads de varredura; pronto para rodar como serviÃ§o."""

    def __init__(self, api: PVOperationAPI):
        self.api = api
        self.rele_alertas_ativos = set()
        self.rele_alerta_chave = {}
        self.inversores_ativos = {}
        self.rele_notificados = set()
        self.inv_notificados = set()
        self.falhas_ativas_por_inv = {}
        self.usinas_alerta_rele_recente = set()
        self.stop_event = threading.Event()
        self.ultima_varredura_rele = None
        self.ultima_varredura_inversor = None
        self.lock = PIDFileLock(LOCK_FILE)
        self._threads = []

    def start(self):
        self.lock.acquire()
        atexit.register(self._cleanup)
        self._load_state()
        self._threads = [
            threading.Thread(target=self._loop_rele, daemon=True, name="loop-rele"),
            threading.Thread(target=self._loop_inversor, daemon=True, name="loop-inversor"),
        ]
        for t in self._threads:
            t.start()
        logger.info("Monitor daemon iniciado (threads de relÃ© e inversor ativas).")

    def stop(self):
        self.stop_event.set()
        for t in self._threads:
            t.join(timeout=5)
        self._save_state()
        self.lock.release()
        logger.info("Monitor daemon encerrado.")

    def _cleanup(self):
        try:
            self._save_state()
        finally:
            self.lock.release()

    def _load_state(self):
        if not STATE_FILE.exists():
            return
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            self.ultima_varredura_rele = (
                datetime.fromisoformat(data.get("ultima_varredura_rele"))
                if data.get("ultima_varredura_rele") else None
            )
            self.ultima_varredura_inversor = (
                datetime.fromisoformat(data.get("ultima_varredura_inversor"))
                if data.get("ultima_varredura_inversor") else None
            )
            self.rele_alertas_ativos = set(data.get("rele_alertas_ativos", []))
            self.rele_notificados = set(data.get("rele_notificados", []))
            self.rele_alerta_chave = data.get("rele_alerta_chave", {})
            self.inversores_ativos = data.get("inversores_ativos", {})
            self.inv_notificados = set(data.get("inv_notificados", []))
            self.falhas_ativas_por_inv = data.get("falhas_ativas_por_inv", {})
            logger.info("Estado carregado do disco.")
        except Exception as e:
            logger.warning(f"NÃ£o foi possÃ­vel carregar estado salvo: {e}")

    def _save_state(self):
        try:
            payload = {
                "ultima_varredura_rele": self.ultima_varredura_rele.isoformat() if self.ultima_varredura_rele else None,
                "ultima_varredura_inversor": self.ultima_varredura_inversor.isoformat() if self.ultima_varredura_inversor else None,
                "rele_alertas_ativos": list(self.rele_alertas_ativos),
                "rele_notificados": list(self.rele_notificados),
                "rele_alerta_chave": self.rele_alerta_chave,
                "inversores_ativos": self.inversores_ativos,
                "inv_notificados": list(self.inv_notificados),
                "falhas_ativas_por_inv": self.falhas_ativas_por_inv,
            }
            STATE_FILE.write_text(json.dumps(payload), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Falha ao salvar estado: {e}")

    def _loop_rele(self):
        while not self.stop_event.is_set():
            try:
                self.executar_varredura_rele()
            except Exception:
                logger.exception("Erro na varredura de relÃ©")
            self.stop_event.wait(RELAY_INTERVAL)

    def _loop_inversor(self):
        while not self.stop_event.is_set():
            try:
                self.executar_varredura_inversor()
            except Exception:
                logger.exception("Erro na varredura de inversor")
            self.stop_event.wait(INVERTER_INTERVAL)

    def executar_varredura_rele(self):
        agora = datetime.now()
        if self.ultima_varredura_rele:
            inicio_janela = self.ultima_varredura_rele + timedelta(seconds=WINDOW_DELTA_SECONDS)
        else:
            inicio_janela = datetime.combine(agora.date(), datetime.min.time())
        logger.info("Varredura de relÃ© iniciada.")

        plantas = self.api.get_plants()
        if not plantas:
            logger.warning("Nenhuma usina encontrada (relÃ©).")
            self.usinas_alerta_rele_recente = set()
            return

        ids_retornados = {str(p.get("id")) for p in plantas}
        usinas_com_rele_ativo = {k.split(":", 1)[0] for k in self.rele_alertas_ativos}
        ausentes = usinas_com_rele_ativo - ids_retornados
        if ausentes:
            logger.warning(f"Lista parcial de usinas (rele); ausentes: {sorted(ausentes)}")

        usinas_com_alerta_rele = set()
        bases_ativos_atual = set()

        for p in plantas:
            usina_id = str(p.get("id"))
            if usina_id not in RELE_PLANT_IDS:
                continue
            nome = p.get("nome")
            cap = p.get("capacidade")

            alertas, _, _ = detectar_alertas_rele(self.api, usina_id, inicio_janela, agora)
            for a in alertas:
                usinas_com_alerta_rele.add(usina_id)
                base = f"{usina_id}:{a['rele_id']}:{a['tipo_alerta']}"
                bases_ativos_atual.add(base)
                if base in self.rele_alertas_ativos:
                    continue

                ts_first = a.get("ts_primeiro", a["ts_leitura"])
                ts_last = a.get("ts_ultimo", a["ts_leitura"])
                intervalo_txt = self.formatar_intervalo_alerta(ts_first, ts_last)
                alerta_fmt = {
                    "usina": nome,
                    "capacidade": cap,
                    "rele": a["rele_id"],
                    "horario": a["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                    "tipo": a["tipo_alerta"],
                    "parametros": f"{a['parametros']} | {intervalo_txt}" if intervalo_txt else a["parametros"],
                }

                self.rele_alertas_ativos.add(base)
                self.rele_alerta_chave[base] = alerta_fmt
                if base not in self.rele_notificados:
                    self.rele_notificados.add(base)
                    self._notificar_rele(alerta_fmt)

        self.usinas_alerta_rele_recente = usinas_com_alerta_rele
        resolved = {b for b in (self.rele_alertas_ativos - bases_ativos_atual)
                    if b.split(":", 1)[0] in ids_retornados}
        for base in resolved:
            self.rele_alertas_ativos.discard(base)
            self.rele_alerta_chave.pop(base, None)
            self.rele_notificados.discard(base)

        self.ultima_varredura_rele = agora
        logger.info("Varredura de relÃ© concluÃ­da.")

    def executar_varredura_inversor(self):
        agora = datetime.now()
        if self.ultima_varredura_inversor:
            inicio_janela = self.ultima_varredura_inversor + timedelta(seconds=WINDOW_DELTA_SECONDS)
        else:
            inicio_janela = datetime.combine(agora.date(), datetime.min.time())
        logger.info("Varredura de inversor iniciada.")

        plantas = self.api.get_plants()
        if not plantas:
            logger.warning("Nenhuma usina encontrada (inversor).")
            return

        ids_retornados_inv = {str(p.get("id")) for p in plantas}
        usinas_esperadas_inv = {k.split(":", 1)[0] for k in self.falhas_ativas_por_inv}
        ausentes_inv = usinas_esperadas_inv - ids_retornados_inv
        if ausentes_inv:
            logger.warning(f"Lista parcial de usinas (inversor); ausentes: {sorted(ausentes_inv)}")

        for p in plantas:
            usina_id = str(p.get("id"))
            if usina_id in self.usinas_alerta_rele_recente:
                logger.info(f"Pulando inversores de {p.get('nome')} devido a alerta de relÃ© recente.")
                continue  # preserva falhas_ativas_por_inv; nÃ£o limpa estado

            nome = p.get("nome")
            cap = p.get("capacidade")

            falhas, recuperados, tem_dados_inv, falhas_ativas_atual, teve_timeout = detectar_falhas_inversores(
                self.api, usina_id, inicio_janela, agora, self.falhas_ativas_por_inv
            )
            self.falhas_ativas_por_inv.update(falhas_ativas_atual)

            for rec in recuperados:
                inv_base = rec["inversor_id"]
                chave_inv = f"{usina_id}_{inv_base}"
                if chave_inv in self.inversores_ativos:
                    del self.inversores_ativos[chave_inv]
                self.inv_notificados.discard(chave_inv)
                self._notificar_inversor_recuperado(
                    {
                        "usina": nome,
                        "capacidade": cap,
                        "inversor": inv_base,
                        "horario": rec["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                        "status": rec["status"],
                        "indicadores": rec.get("indicadores", {}),
                    }
                )

            if not tem_dados_inv:
                motivo = "TIMEOUT" if teve_timeout else "SEM_DADOS"
                logger.warning(f"Sem dados de inversor em {nome} (motivo: {motivo}).")

            for f in falhas:
                chave_inv = f"{usina_id}_{f['inversor_id']}"
                if chave_inv in self.inversores_ativos:
                    continue
                alerta = {
                    "usina": nome,
                    "capacidade": cap,
                    "inversor": f["inversor_id"],
                    "horario": f["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                    "status": f["status"],
                    "indicadores": f.get("indicadores", {}),
                }
                self.inversores_ativos[chave_inv] = alerta
                if chave_inv not in self.inv_notificados:
                    self.inv_notificados.add(chave_inv)
                    self._notificar_inversor(alerta)

        self.ultima_varredura_inversor = agora
        logger.info("Varredura de inversor concluÃ­da.")

    @staticmethod
    def formatar_intervalo_alerta(ts_first, ts_last) -> str:
        if not ts_first or not ts_last:
            return ""
        if ts_first == ts_last:
            return f"Alerta Ã s {ts_first.strftime('%H:%M')}"
        return f"Primeiro alerta Ã s {ts_first.strftime('%H:%M')} e Ãºltimo Ã s {ts_last.strftime('%H:%M')}"

    def _notificar_rele(self, alerta):
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"RelÃ©: {alerta['rele']}\n"
            f"Tipo: {alerta['tipo']}\n"
            f"HorÃ¡rio: {alerta['horario']}\n"
            f"ParÃ¢metros: {alerta['parametros']}"
        )
        logger.warning(f"[ALERTA RELÃ‰] {msg.replace(chr(10), ' | ')}")
        try:
            _teams_post_card(
                title=f"ðŸš¨ Alerta de RelÃ© ({alerta['tipo']})",
                text=(
                    f"**Usina:** {alerta['usina']}  \n"
                    f"**RelÃ©:** {alerta['rele']}  \n"
                    f"**HorÃ¡rio:** {alerta['horario']}  \n"
                    f"**ParÃ¢metros:** {alerta['parametros']}"
                ),
                severity="danger" if alerta["tipo"] in ("SOBRETENSÃƒO", "TÃ‰RMICO", "BLOQUEIO") else "warning",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger.exception("Falha ao notificar Teams (relÃ©)")

    def _notificar_inversor(self, alerta):
        inds = alerta.get("indicadores", {})
        detalhes_txt = f"Pac: {inds.get('pac', 'N/A')}"
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"Inversor: {alerta['inversor']}\n"
            f"Status: {alerta['status']}\n"
            f"HorÃ¡rio: {alerta['horario']}\n"
            f"{detalhes_txt}"
        )
        logger.warning(f"[ALERTA INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            _teams_post_card(
                title="ðŸš¨ Falha de Inversor (PAC<=0; 3 leituras consecutivas; 06:30â€“17:00)",
                text=(
                    f"**Usina:** {alerta['usina']}  \n"
                    f"**Inversor:** {alerta['inversor']}  \n"
                    f"**HorÃ¡rio:** {alerta['horario']}  \n"
                    f"**Detalhes:** {detalhes_txt}"
                ),
                severity="danger",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger.exception("Falha ao notificar Teams (inversor)")

    def _notificar_inversor_recuperado(self, alerta):
        inds = alerta.get("indicadores", {})
        pac_val = inds.get("pac", "N/A")
        detalhes_txt = f"Pac: {pac_val}"
        msg = (
            f"Usina: {alerta['usina']}\n"
            f"Inversor: {alerta['inversor']}\n"
            f"Status: NORMALIZADO\n"
            f"HorÃ¡rio: {alerta['horario']}\n"
            f"{detalhes_txt}"
        )
        logger.info(f"[RECUPERACAO INVERSOR] {msg.replace(chr(10), ' | ')}")
        try:
            _teams_post_card(
                title="âœ… Inversor Normalizado",
                text=(
                    f"**Usina:** {alerta['usina']}  \n"
                    f"**Inversor:** {alerta['inversor']}  \n"
                    f"**HorÃ¡rio:** {alerta['horario']}  \n"
                    f"**Detalhes:** {detalhes_txt}"
                ),
                severity="info",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger.exception("Falha ao notificar Teams (inversor recuperado)")


def run_daemon():
    validate_config()
    api = PVOperationAPI(email=PVOP_EMAIL, password=PVOP_PASSWORD, base_url=PVOP_BASE_URL)
    service = MonitorDaemon(api)
    service.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Encerrando monitor por interrupÃ§Ã£o do usuÃ¡rio...")
    finally:
        service.stop()
        time.sleep(1)


if __name__ == "__main__":
    run_daemon()

