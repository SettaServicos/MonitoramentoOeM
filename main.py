import json
import logging
import os
import re
import time
from datetime import datetime, time as dtime, timedelta
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv
from requests import Session
from requests.exceptions import Timeout

load_dotenv()

# =====================================
# CONFIGURAÇÕES GERAIS
# =====================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("RelayMonitor")

# Webhook Teams (fallback)
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")

# Graph (threads em canal): requer app registrado e permissões (ChannelMessage.Send, Group.ReadWrite.All)
GRAPH_TENANT_ID = os.environ.get("GRAPH_TENANT_ID")
GRAPH_CLIENT_ID = os.environ.get("GRAPH_CLIENT_ID")
GRAPH_CLIENT_SECRET = os.environ.get("GRAPH_CLIENT_SECRET")
GRAPH_TEAM_ID = os.environ.get("GRAPH_TEAM_ID")
GRAPH_CHANNEL_ID = os.environ.get("GRAPH_CHANNEL_ID")

# Timezone: API retorna timestamps sem offset; assume UTC
API_TZ = ZoneInfo("UTC")
LOCAL_TZ = ZoneInfo("America/Sao_Paulo")
SCAN_INTERVAL_MIN = 20
WINDOW_TOLERANCE_MIN = 10  # cobre tempo de execução/atrasos; janela efetiva = 30min


# =====================================
# TEAMS / GRAPH
# =====================================
def _teams_post_card(title, text, severity="info", facts=None):
    """Envia um 'MessageCard' para o Microsoft Teams via webhook."""
    if not TEAMS_WEBHOOK_URL:
        logger.warning("[TEAMS] TEAMS_WEBHOOK_URL não configurada; notificação não enviada.")
        return

    colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
    theme = colors.get(severity, "0078D4")

    sections = []
    if facts:
        sections.append({"facts": [{"name": k, "value": v} for k, v in facts]})

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": theme,
        "title": title,
        "text": text,
        "sections": sections,
    }

    try:
        r = requests.post(
            TEAMS_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
        logger.info(f"[TEAMS] Notificação enviada: {title}")
    except Exception as e:
        logger.warning(f"[TEAMS] Falha ao enviar webhook: {e}")


def _graph_available() -> bool:
    return all([GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, GRAPH_TEAM_ID, GRAPH_CHANNEL_ID])


_graph_token_cache = {"token": None, "expires_at": 0}


def _graph_get_token() -> str:
    now = time.time()
    if _graph_token_cache["token"] and now < _graph_token_cache["expires_at"] - 30:
        return _graph_token_cache["token"]

    url = f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": GRAPH_CLIENT_ID,
        "client_secret": GRAPH_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=10)
    r.raise_for_status()
    resp = r.json()
    token = resp["access_token"]
    expires_in = int(resp.get("expires_in", 3600))
    _graph_token_cache["token"] = token
    _graph_token_cache["expires_at"] = now + expires_in
    return token


def _graph_post_message(title: str, text: str, facts=None) -> str | None:
    """Cria uma mensagem no canal. Retorna message_id."""
    if not _graph_available():
        return None
    try:
        token = _graph_get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body_lines = [f"<strong>{title}</strong>", text.replace("\n", "<br>")]
        if facts:
            facts_html = "<br>".join([f"<strong>{k}:</strong> {v}" for k, v in facts])
            body_lines.append(facts_html)
        payload = {
            "body": {"contentType": "html", "content": "<br>".join(body_lines)},
        }
        url = f"https://graph.microsoft.com/v1.0/teams/{GRAPH_TEAM_ID}/channels/{GRAPH_CHANNEL_ID}/messages"
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json().get("id")
    except Exception as e:
        logger.error(f"[GRAPH] Falha ao postar mensagem: {e}")
        return None


def _graph_reply_message(parent_id: str, text: str) -> bool:
    """Responde em thread. Retorna True se ok."""
    if not _graph_available():
        return False
    try:
        token = _graph_get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "body": {"contentType": "html", "content": text.replace("\n", "<br>")},
        }
        url = f"https://graph.microsoft.com/v1.0/teams/{GRAPH_TEAM_ID}/channels/{GRAPH_CHANNEL_ID}/messages/{parent_id}/replies"
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"[GRAPH] Falha ao responder em thread: {e}")
        return False


# =====================================
# CLIENTE DE API PVOperation
# =====================================
class PVOperationAPI:
    def __init__(self, email, password, base_url="https://apipv.pvoperation.com.br/api/v1"):
        self.email = email
        self.password = password
        self.base_url = base_url
        self.session = Session()
        self.token = None
        self.headers = {}
        self._login()

    def _login(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.base_url}/authenticate",
                json={"username": self.email, "password": self.password},
                timeout=15,
            )
            if resp.status_code == 200:
                self.token = resp.json().get("token")
                self.headers = {"x-access-token": self.token}
                logger.info("Autenticação realizada com sucesso.")
                return True
            logger.error(f"Falha na autenticação. Status: {resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"Erro durante login: {e}")
            return False

    def verificar_token(self) -> bool:
        logger.warning("Tentando renovar token...")
        return self._login()

    def get_plants(self):
        url = f"{self.base_url}/plants"
        try:
            r = self.session.get(url, headers=self.headers, timeout=15)
            if r.status_code == 401 and self.verificar_token():
                r = self.session.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.json() or []
            logger.error(f"Erro ao buscar plantas. Status: {r.status_code}")
        except Exception as e:
            logger.error(f"Erro em get_plants: {e}")
        return []

    def post_day(self, endpoint: str, plant_id: int, date: datetime):
        try:
            r = self.session.post(
                f"{self.base_url}/{endpoint}",
                json={"id": int(plant_id), "date": date.strftime("%Y-%m-%d")},
                headers=self.headers,
                timeout=(5, 30),
            )
            if r.status_code == 401 and self.verificar_token():
                r = self.session.post(
                    f"{self.base_url}/{endpoint}",
                    json={"id": int(plant_id), "date": date.strftime("%Y-%m-%d")},
                    headers=self.headers,
                    timeout=(5, 30),
                )
            if r.status_code == 200:
                return r.json()
        except Timeout:
            logger.warning(f"Timeout em {endpoint} (usina {plant_id}, {date.date()})")
        except Exception as e:
            logger.error(f"Erro em {endpoint}: {e}")
        return None


# =====================================
# FUNÇÕES DE ANÁLISE
# =====================================
def extrair_valor_numerico(valor) -> float:
    if isinstance(valor, (int, float)):
        return float(valor)
    if isinstance(valor, str):
        m = re.search(r"([-+]?\d*\.\d+|\d+)", valor)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return 0.0
    return 0.0


def is_true(value) -> bool:
    """Normaliza valores que representem verdadeiro."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "on", "yes", "y", "sim"}
    return False


def detectar_alertas_rele(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime, api_tz: ZoneInfo):
    PARAMS_CLASSIF = {
        "SOBRETENSÃO": {"r59A", "r59B", "r59C", "r59N"},
        "SUBTENSÃO": {"r27A", "r27B", "r27C", "r27_0"},
        "FREQUÊNCIA": {"r81O", "r81U"},
        "TÉRMICO": {"r49", "r49_2"},
        "BLOQUEIO": {"rAR", "rBA", "rDO"},
    }
    PARAMETROS_RELE = set().union(*PARAMS_CLASSIF.values())

    candidatos = []
    dias = sorted({inicio.date(), fim.date()})
    for d in dias:
        data_resp = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if not data_resp:
            continue
        for registro in data_resp:
            conteudo = registro.get("conteudojson", {}) or {}
            idrele = registro.get("idrele")
            if not idrele:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=api_tz)
            except Exception:
                continue
            if not (inicio <= ts <= fim):
                continue
            ativos = [p for p in PARAMETROS_RELE if is_true(conteudo.get(p))]
            if not ativos:
                continue
            tipo = next((classe for classe, lista in PARAMS_CLASSIF.items() if any(p in lista for p in ativos)), "OUTROS")
            candidatos.append(
                {
                    "ts_leitura": ts,
                    "rele_id": idrele,
                    "parametros": ", ".join(sorted(ativos)),
                    "tipo_alerta": tipo,
                }
            )
    candidatos.sort(key=lambda a: a["ts_leitura"])
    return candidatos


def detectar_falhas_inversores(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime, api_tz: ZoneInfo):
    JANELA_INICIO, JANELA_FIM = dtime(6, 30), dtime(17, 30)
    leituras_por_inv, falhas = {}, []
    dias = sorted({inicio.date(), fim.date()})
    for d in dias:
        data_resp = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if not data_resp:
            continue
        for reg in data_resp:
            conteudo = reg.get("conteudojson", {}) or {}
            inv_id = reg.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if not inv_id:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=api_tz)
            except Exception:
                continue
            if not (inicio <= ts <= fim) or not (JANELA_INICIO <= ts.time() <= JANELA_FIM):
                continue
            pac_raw = next((conteudo.get(k) for k in ("Pac", "PAC", "Potencia_Saida", "Pout", "Potencia") if k in conteudo), None)
            pac = extrair_valor_numerico(pac_raw or 0)
            leituras_por_inv.setdefault(inv_id, []).append((ts, pac))

    for inv_id, leituras in leituras_por_inv.items():
        leituras.sort(key=lambda x: x[0])
        seq = 0
        for ts, pac in leituras:
            if pac == 0:
                seq += 1
                if seq >= 3:
                    falhas.append({"inversor_id": inv_id, "ts_leitura": ts, "pac": pac})
                    break
            else:
                seq = 0
    return falhas


# =====================================
# UTILITÁRIOS PARA EVITAR DUPLICAÇÕES
# =====================================
LAST_ALERT_FILE = os.getenv("LAST_ALERT_FILE", "last_alert.json")
DEFAULT_STATE = {"relay": {}, "inverter": {}}
LOCK_TIMEOUT = 5


def _fresh_state():
    return {"relay": {}, "inverter": {}}


def _legacy_to_state(data: dict) -> dict:
    """Converte arquivo antigo (global) para formato novo ou retorna estado limpo."""
    state = _fresh_state()
    if not data:
        return state
    return state


def _lock_path():
    return LAST_ALERT_FILE + ".lock"


def _acquire_lock():
    path = _lock_path()
    start = time.time()
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            return fd
        except FileExistsError:
            if time.time() - start > LOCK_TIMEOUT:
                raise TimeoutError(f"Timeout aguardando lock em {path}")
            time.sleep(0.1)


def _release_lock(fd):
    path = _lock_path()
    try:
        os.close(fd)
    finally:
        if os.path.exists(path):
            os.remove(path)


def load_alert_state() -> dict:
    if not os.path.exists(LAST_ALERT_FILE):
        return _fresh_state()
    # Aguarda lock se outro processo estiver gravando
    while os.path.exists(_lock_path()):
        time.sleep(0.1)
    try:
        with open(LAST_ALERT_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if "relay" in data and "inverter" in data:
            return data
        return _legacy_to_state(data)
    except Exception as e:
        logger.warning(f"Não foi possível ler {LAST_ALERT_FILE}: {e}")
        return _fresh_state()


def save_alert_state(state: dict):
    fd = None
    try:
        fd = _acquire_lock()
        with open(LAST_ALERT_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception as e:
        logger.error(f"Falha ao gravar {LAST_ALERT_FILE}: {e}")
        raise
    finally:
        if fd is not None:
            _release_lock(fd)


def decide_delivery(kind: str, plant_id: str, ts: datetime, signature: str, state: dict):
    """Retorna ('post', None) ou ('reply', msg_id) conforme histórico por usina/dia/assinatura."""
    plant_id = str(plant_id)
    state.setdefault(kind, {})
    current_day = ts.date().isoformat()
    last_info = state[kind].get(plant_id)
    if not last_info:
        return "post", None

    last_day = last_info.get("day")
    last_sig = last_info.get("sig")
    last_msg = last_info.get("msg_id")

    if last_day != current_day or signature != last_sig:
        return "post", None

    if last_msg:
        return "reply", last_msg
    return "post", None


def update_state(kind: str, plant_id: str, ts: datetime, signature: str, state: dict, msg_id: str | None):
    state.setdefault(kind, {})
    state[kind][str(plant_id)] = {
        "ts": ts.isoformat(),
        "sig": signature,
        "day": ts.date().isoformat(),
        "msg_id": msg_id,
    }
    save_alert_state(state)


# =====================================
# EXECUÇÃO AUTOMÁTICA
# =====================================
def main():
    logger.info("Iniciando varredura automática...")

    if not _graph_available() and not TEAMS_WEBHOOK_URL:
        logger.error("Nenhum canal de notificação configurado (Graph ou Webhook). Encerrando.")
        return
    if not _graph_available():
        logger.warning("Graph indisponível; usando apenas webhook.")

    email = os.getenv("EMAIL")
    password = os.getenv("PASSWORD")
    if not email or not password:
        logger.error("Credenciais EMAIL/PASSWORD não configuradas. Encerrando.")
        return

    api = PVOperationAPI(email, password)

    plantas = api.get_plants()
    if not plantas:
        logger.error("Nenhuma usina encontrada.")
        return

    agora = datetime.now(API_TZ)
    inicio_janela = agora - timedelta(minutes=SCAN_INTERVAL_MIN + WINDOW_TOLERANCE_MIN)
    estado_alertas = load_alert_state()
    logger.info(f"Analisando período entre {inicio_janela} e {agora} (TZ API)")

    for p in plantas:
        usina_id = str(p.get("id"))
        nome = p.get("nome")
        cap = p.get("capacidade")
        logger.info(f"Analisando usina: {nome} ({usina_id})")

        # RELÉS
        alertas = detectar_alertas_rele(api, usina_id, inicio_janela, agora, API_TZ)
        relay_processed = False
        for a in alertas:
            assinatura = f"{usina_id}:{a['rele_id']}:{a['tipo_alerta']}:{a['parametros']}"
            action, parent_msg_id = decide_delivery("relay", usina_id, a["ts_leitura"], assinatura, estado_alertas)
            msg = (
                f"🚨 Alerta de Relé ({a['tipo_alerta']})\n"
                f"Usina: {nome}\n"
                f"Relé: {a['rele_id']}\n"
                f"Horário: {a['ts_leitura']}\n"
                f"Parâmetros: {a['parametros']}"
            )
            logger.warning(msg)
            msg_id = None
            if action == "reply" and parent_msg_id and _graph_available():
                replied = _graph_reply_message(parent_msg_id, "Alerta persiste")
                if replied:
                    msg_id = parent_msg_id
                    logger.info(f"[GRAPH] Reply enviado em thread (relé) usina {nome}")
                else:
                    action = "post"  # fallback

            if action == "post":
                if _graph_available():
                    msg_id = _graph_post_message(
                        title=f"🚨 Alerta de Relé ({a['tipo_alerta']})",
                        text=msg,
                        facts=[("Capacidade", f"{cap} kWp")],
                    )
                if not msg_id:
                    _teams_post_card(
                        title=f"🚨 Alerta de Relé ({a['tipo_alerta']})",
                        text=msg.replace("\n", "  \n"),
                        severity="danger",
                        facts=[("Capacidade", f"{cap} kWp")],
                    )
            update_state("relay", usina_id, a["ts_leitura"], assinatura, estado_alertas, msg_id)
            relay_processed = True

        if relay_processed:
            continue  # não verifica inversores se houve alerta de relé processado

        # INVERSORES
        hora_atual = datetime.now(API_TZ).time()
        LIMITE_INVERSOR = dtime(17, 0)
        if hora_atual >= LIMITE_INVERSOR:
            logger.info(f"⚠️ Após {LIMITE_INVERSOR.strftime('%H:%M')}, ignorando alertas de inversor para {nome}.")
            continue

        falhas = detectar_falhas_inversores(api, usina_id, inicio_janela, agora, API_TZ)
        for f in falhas:
            assinatura = f"{usina_id}:{f['inversor_id']}:pac0"
            action, parent_msg_id = decide_delivery("inverter", usina_id, f["ts_leitura"], assinatura, estado_alertas)
            msg = (
                f"🚨 Falha de Inversor\n"
                f"Usina: {nome}\n"
                f"Inversor: {f['inversor_id']}\n"
                f"Horário: {f['ts_leitura']}\n"
                f"Pac: {f['pac']}"
            )
            logger.warning(msg)
            msg_id = None
            if action == "reply" and parent_msg_id and _graph_available():
                replied = _graph_reply_message(parent_msg_id, "Alerta persiste")
                if replied:
                    msg_id = parent_msg_id
                    logger.info(f"[GRAPH] Reply enviado em thread (inversor) usina {nome}")
                else:
                    action = "post"

            if action == "post":
                if _graph_available():
                    msg_id = _graph_post_message(
                        title="🚨 Falha de Inversor (Pac=0)",
                        text=msg,
                        facts=[("Capacidade", f"{cap} kWp")],
                    )
                if not msg_id:
                    _teams_post_card(
                        title="🚨 Falha de Inversor (Pac=0)",
                        text=msg.replace("\n", "  \n"),
                        severity="danger",
                        facts=[("Capacidade", f"{cap} kWp")],
                    )
            update_state("inverter", usina_id, f["ts_leitura"], assinatura, estado_alertas, msg_id)

    logger.info("Varredura concluída com sucesso.")
    print("OK. Concluído.")


if __name__ == "__main__":
    # Comportamento padrão: executar uma vez (ideal para agendador externo).
    # Para habilitar loop interno, defina LOOP_ENABLED=1 e opcionalmente LOOP_INTERVAL_MIN (padrão 20 min).
    loop_enabled = os.getenv("LOOP_ENABLED", "").strip() == "1"
    if not loop_enabled:
        main()
    else:
        interval_min = int(os.getenv("LOOP_INTERVAL_MIN", SCAN_INTERVAL_MIN))
        while True:
            ciclo_inicio = time.time()
            try:
                main()
            except Exception as e:
                logger.error(f"Erro não tratado durante varredura: {e}")
            elapsed = time.time() - ciclo_inicio
            sleep_s = max(0, interval_min * 60 - elapsed)
            logger.info(f"Próxima varredura em {sleep_s/60:.1f} minutos.")
            time.sleep(sleep_s)
