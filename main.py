import json
import logging
import os
import re
from datetime import datetime
from datetime import time as dtime
from datetime import timedelta

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
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RelayMonitor")

# --- Teams Webhook (Incoming Webhook) ---
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")
# =====================================

def _teams_post_card(title, text, severity="info", facts=None):
    """Envia um 'MessageCard' para o Microsoft Teams."""
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
                timeout=15
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
                timeout=20
            )
            if r.status_code == 401 and self.verificar_token():
                r = self.session.post(
                    f"{self.base_url}/{endpoint}",
                    json={"id": int(plant_id), "date": date.strftime("%Y-%m-%d")},
                    headers=self.headers,
                    timeout=60
                )
            if r.status_code == 200:
                return r.json()
        # except Timeout:
        #     logger.warning(f"Timeout em {endpoint} (usina {plant_id}, {date.date()})")
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
        m = re.search(r'([-+]?\d*\.\d+|\d+)', valor)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return 0.0
    return 0.0

def detectar_alertas_rele(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime):
    PARAMS_CLASSIF = {
        "SOBRETENSÃO": {"r59A", "r59B", "r59C", "r59N"},
        "SUBTENSÃO": {"r27A", "r27B", "r27C", "r27_0"},
        "FREQUÊNCIA": {"r81O", "r81U"},
        "TÉRMICO": {"r49", "r49_2"},
        "BLOQUEIO": {"rAR", "rBA", "rDO"},
    }
    PARAMETROS_RELE = set().union(*PARAMS_CLASSIF.values())

    candidatos = []
    d = inicio.date()
    while d <= fim.date():
        data_resp = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if not data_resp:
            d += timedelta(days=1)
            continue
        for registro in data_resp:
            conteudo = registro.get("conteudojson", {}) or {}
            idrele = registro.get("idrele")
            if not idrele:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura",""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if not (inicio <= ts <= fim):
                continue
            ativos = [p for p in PARAMETROS_RELE if conteudo.get(p) is True]
            if not ativos:
                continue
            tipo = next((classe for classe, lista in PARAMS_CLASSIF.items() if any(p in lista for p in ativos)), "OUTROS")
            candidatos.append({
                "ts_leitura": ts,
                "rele_id": idrele,
                "parametros": ", ".join(sorted(ativos)),
                "tipo_alerta": tipo
            })
        d += timedelta(days=1)
    candidatos.sort(key=lambda a: a["ts_leitura"])
    return [candidatos[0]] if candidatos else []

def detectar_falhas_inversores(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime):
    JANELA_INICIO, JANELA_FIM = dtime(6,30), dtime(17,30)
    leituras_por_inv, falhas = {}, []
    d = inicio.date()
    while d <= fim.date():
        data_resp = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if not data_resp:
            d += timedelta(days=1)
            continue
        for reg in data_resp:
            conteudo = reg.get("conteudojson", {}) or {}
            inv_id = reg.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if not inv_id:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura",""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if not (inicio <= ts <= fim) or not (JANELA_INICIO <= ts.time() <= JANELA_FIM):
                continue
            pac_raw = next((conteudo.get(k) for k in ("Pac","PAC","Potencia_Saida","Pout","Potencia") if k in conteudo), None)
            pac = extrair_valor_numerico(pac_raw or 0)
            leituras_por_inv.setdefault(inv_id, []).append((ts, pac))
        d += timedelta(days=1)

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
LAST_ALERT_FILE = "last_alert.json"

def get_last_alert_times():
    """Lê o último timestamp de alerta salvo (relé e inversor)."""
    default = {"last_relay_ts": datetime.min.isoformat(), "last_inverter_ts": datetime.min.isoformat()}
    if os.path.exists(LAST_ALERT_FILE):
        try:
            with open(LAST_ALERT_FILE) as f:
                data = json.load(f)
                return {
                    "last_relay_ts": datetime.fromisoformat(data.get("last_relay_ts", default["last_relay_ts"])),
                    "last_inverter_ts": datetime.fromisoformat(data.get("last_inverter_ts", default["last_inverter_ts"]))
                }
        except Exception:
            pass
    return {
        "last_relay_ts": datetime.min,
        "last_inverter_ts": datetime.min
    }

def update_last_alert_time(tipo: str, ts: datetime):
    """Atualiza o timestamp do último alerta por tipo ('relay' ou 'inverter')."""
    try:
        data = {}
        if os.path.exists(LAST_ALERT_FILE):
            with open(LAST_ALERT_FILE) as f:
                data = json.load(f)
        data[f"last_{tipo}_ts"] = ts.isoformat()
        with open(LAST_ALERT_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning(f"Não foi possível salvar timestamp de alerta ({tipo}): {e}")

# =====================================
# EXECUÇÃO AUTOMÁTICA (ATUALIZADA)
# =====================================
def main():
    logger.info("Iniciando varredura automática...")

    email = os.getenv("EMAIL")
    password = os.getenv("PASSWORD")
    api = PVOperationAPI(email, password)

    plantas = api.get_plants()
    if not plantas:
        logger.error("Nenhuma usina encontrada.")
        return

    agora = datetime.now()
    # Janela móvel de 25 minutos (tolerância para cron atrasado)
    inicio_janela = agora - timedelta(minutes=25)
    last_times = get_last_alert_times()
    logger.info(f"Analisando período entre {inicio_janela} e {agora}")

    for p in plantas:
        usina_id = str(p.get("id"))
        nome = p.get("nome")
        cap = p.get("capacidade")
        logger.info(f"Analisando usina: {nome} ({usina_id})")

        # RELÉS
        alertas = detectar_alertas_rele(api, usina_id, inicio_janela, agora)
        for a in alertas:
            if a["ts_leitura"] <= last_times["last_relay_ts"]:
                continue

            msg = (
                f"⚠ Alerta de Relé ({a['tipo_alerta']})\n"
                f"Usina: {nome}\n"
                f"Relé: {a['rele_id']}\n"
                f"Horário: {a['ts_leitura']}\n"
                f"Parâmetros: {a['parametros']}"
            )
            logger.warning(msg)
            _teams_post_card(
                title=f"⚠ Alerta de Relé ({a['tipo_alerta']})",
                text=msg.replace("\n", "  \n"),
                severity="danger",
                facts=[("Capacidade", f"{cap} kWp")]
            )
            update_last_alert_time("relay", a["ts_leitura"])
            break

        else:  # só roda inversores se não houve alerta de relé
            hora_atual = datetime.now().time()
            LIMITE_INVERSOR = dtime(17, 0)
            if hora_atual >= LIMITE_INVERSOR:
                logger.info(f"⏸ Após {LIMITE_INVERSOR.strftime('%H:%M')}, ignorando alertas de inversor para {nome}.")
                continue

            falhas = detectar_falhas_inversores(api, usina_id, inicio_janela, agora)
            for f in falhas:
                if f["ts_leitura"] <= last_times["last_inverter_ts"]:
                    continue

                msg = (
                    f"⚠ Falha de Inversor\n"
                    f"Usina: {nome}\n"
                    f"Inversor: {f['inversor_id']}\n"
                    f"Horário: {f['ts_leitura']}\n"
                    f"Pac: {f['pac']}"
                )
                logger.warning(msg)
                _teams_post_card(
                    title="⚠ Falha de Inversor (Pac=0)",
                    text=msg.replace("\n", "  \n"),
                    severity="danger",
                    facts=[("Capacidade", f"{cap} kWp")]
                )
                update_last_alert_time("inverter", f["ts_leitura"])

    logger.info("Varredura concluída com sucesso.")
    print("✅ Concluído.")

if __name__ == "__main__":
    main()