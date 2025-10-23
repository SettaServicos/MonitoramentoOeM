# =========================
# Monitor de Relés e Inversores - Setta Serviços
# BACKEND (API + Regras)  |  FRONTEND (Tkinter)
# =========================
# Requisitos vigentes:
# 1) Primeira varredura do início do dia até agora (relés e inversores).
# 2) Próximas varreduras sempre 20 min após o término da anterior (contador na UI).
# 3) Prioridade: havendo ALERTA DE RELÉ para a usina, não processa/alerta inversores
#    no ciclo e ZERA sequências de inversores dessa usina no ciclo.
# 4) INVERSORES (NOVA REGRA):
#    - Considera APENAS o período 06:30–17:30 (hora da leitura).
#    - Condição de falha: Pac == 0 (Status é ignorado).
#    - Dispara após 3 leituras CONSECUTIVAS em passos exatos de 5 minutos.
#    - Sequência reinicia a cada varredura; falha ativa limpa com Pac > 0.
# 5) "Sem Dados" é registrado SOMENTE para INVERSOR (não registrar para RELÉ).

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta, time as dtime
from requests import Session
import logging
import os
from PIL import Image, ImageTk
from ttkthemes import ThemedStyle
import threading
import time as _time
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import winsound
from threading import Thread
from queue import Queue
from requests.exceptions import Timeout
import re
# --- Teams Webhook (Incoming Webhook) ---
import json
import requests  # já usamos requests na API

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "https://settaenergiarecife.webhook.office.com/webhookb2/ff6efec5-9ceb-4932-89ba-d4d8082a1975@77b21bc1-b0b7-4df6-9225-2e24fc9de0f6/IncomingWebhook/38f7efca2b124a17abc7dcc8a5a40c95/a29266d7-870f-4855-96b0-c21a4710f37b/V2rB2XbXOgznVTxAoIWIeDPnlRZ203j0jsNsLKr4cNK141").strip()
# se preferir fixar no código, comente a linha acima e DESCOMENTE a de baixo:
# TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/SEU_LINK_AQUI"

TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)


def _teams_post_card(title, text, severity="info", facts=None):

    """
    Envia um 'MessageCard' para um Incoming Webhook do Microsoft Teams.
    severity: 'info' | 'warning' | 'danger'
    """
    if not TEAMS_ENABLED:
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
    except Exception as e:
        logger.warning(f"[TEAMS] Falha ao enviar webhook: {e}")

# ============ CONFIG GERAIS ============
ROOT_DIR = r"D:\\appsetta"
LOGO_PATH = os.path.join(ROOT_DIR, "logotipo.jpg")
STYLE_CONFIG = {
    "font": ("Segoe UI", 10),
    "bg": "#f8f9fa",
    "fg": "#212529",
    "active_bg": "#e9ecef",
    "highlight": "#0d6efd",
    "error": "#dc3545",
    "success": "#198754"
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RelayMonitor")


# =========================
# BACKEND: POPUP DE ALERTA
# =========================
class AlertPopup:
    """Popup de alerta com fila para evitar múltiplos simultâneos."""
    popup_queue = Queue()
    popup_active = False

    def __init__(self, parent, message, alert_type):
        self.parent = parent
        self.message = message
        self.alert_type = alert_type
        AlertPopup.popup_queue.put(self)
        self.try_show_next()

    def try_show_next(self):
        if not AlertPopup.popup_active and not AlertPopup.popup_queue.empty():
            AlertPopup.popup_active = True
            next_popup = AlertPopup.popup_queue.get()
            next_popup._show()

    def _show(self):
        self.popup = tk.Toplevel(self.parent.root)
        self.popup.title("ALERTA DE FALHA - ATENÇÃO!")
        self.popup.geometry("420x220")
        self.popup.resizable(False, False)
        self.popup.attributes('-topmost', True)

        colors = {
            "SOBRETENSÃO": ("#ffebee", "#b71c1c"),
            "SUBTENSÃO": ("#e3f2fd", "#0d47a1"),
            "FREQUÊNCIA": ("#fff8e1", "#ff6f00"),
            "TÉRMICO": ("#ffebee", "#e53935"),
            "BLOQUEIO": ("#e8f5e9", "#2e7d32"),
            "OUTROS": ("#f5f5f5", "#424242"),
            "INVERSOR": ("#fff3e0", "#e65100")
        }
        bg_color, fg_color = colors.get(self.alert_type, ("#ffffff", "#000000"))

        tk.Label(
            self.popup,
            text="⚠ ALERTA CRÍTICO ⚠",
            font=("Segoe UI", 14, "bold"),
            fg=fg_color,
            bg=bg_color
        ).pack(pady=10)

        tk.Label(
            self.popup,
            text=self.message,
            font=("Segoe UI", 11),
            fg=fg_color,
            bg=bg_color,
            wraplength=380,
            justify="left"
        ).pack(pady=5)

        tk.Button(
            self.popup,
            text="CONFIRMAR E FECHAR",
            command=self.close,
            bg=fg_color,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=10
        ).pack(pady=15)

        self.playing_sound = True
        Thread(target=self.play_sound, daemon=True).start()
        self.popup.focus_force()
        self.popup.protocol("WM_DELETE_WINDOW", self.close)

    def play_sound(self):
        try:
            while self.playing_sound:
                winsound.Beep(1000, 400)
                _time.sleep(0.8)
                winsound.Beep(1500, 400)
                _time.sleep(0.8)
        except Exception:
            pass

    def close(self):
        self.playing_sound = False
        try:
            self.popup.destroy()
        except Exception:
            pass
        AlertPopup.popup_active = False
        self.try_show_next()


# =========================
# BACKEND: CLIENTE DE API
# =========================
class PVOperationAPI:
    """Cliente para autenticar e consultar a API da PVOperation."""
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
        """Renova token quando necessário."""
        logger.warning("Tentando renovar token...")
        ok = self._login()
        if not ok:
            logger.error("Não foi possível renovar o token.")
        return ok

    def get_plants(self):
        """
        Busca a lista de usinas. Se a conexão for encerrada pelo servidor
        (RemoteDisconnected/ConnectionError), recria a sessão e tenta de novo.
        """
        url = f"{self.base_url}/plants"
        try:
            r = self.session.get(url, headers=self.headers, timeout=15)
            if r.status_code == 401:
                # token expirou: renova
                if not self.verificar_token():
                    return []
                r = self.session.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.json() or []
            logger.error(f"Erro ao buscar plantas. Status: {r.status_code}")
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            # servidor fechou a conexão ou conexão foi abortada
            logger.warning(f"Erro de conexão em get_plants: {e}. Tentando recriar sessão e reautenticar.")
            try:
                self.session.close()
            except Exception:
                pass
            # cria uma nova sessão e reautentica
            self.session = Session()
            if self._login():
                try:
                    r = self.session.get(url, headers=self.headers, timeout=15)
                    if r.status_code == 200:
                        return r.json() or []
                except Exception as e2:
                    logger.error(f"Falha ao repetir get_plants após recriar sessão: {e2}")
        except Exception as e:
            logger.error(f"Exceção em get_plants: {e}")
        return []


    def post_day(self, endpoint: str, plant_id: int, date: datetime):
        """Chama endpoints day_* (relay/inverter)."""
        try:
            r = self.session.post(
                f"{self.base_url}/{endpoint}",
                json={"id": int(plant_id), "date": date.strftime("%Y-%m-%d")},
                headers=self.headers,
                timeout=20
            )
            if r.status_code == 401:
                if not self.verificar_token():
                    return None
                r = self.session.post(
                    f"{self.base_url}/{endpoint}",
                    json={"id": int(plant_id), "date": date.strftime("%Y-%m-%d")},
                    headers=self.headers,
                    timeout=20
                )
            if r.status_code == 200:
                return r.json()
            logger.warning(f"Status {r.status_code} em {endpoint} (usina {plant_id}, {date.date()}).")
            return None
        except Timeout:
            logger.warning(f"Timeout em {endpoint} (usina {plant_id}, {date.date()}).")
            return None
        except Exception as e:
            logger.error(f"Erro em {endpoint}: {e}")
            return None


# ==========================================
# BACKEND: REGRAS DE NEGÓCIO (DETECÇÃO)
# ==========================================
def extrair_valor_numerico(valor) -> float:
    """Extrai um float de string/numérico com possíveis unidades."""
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
    """
    Retorna (lista_alertas, tem_dados).

    Regras:
      - Não registra "Sem Dados" para RELÉ.
      - Sempre devolve SOMENTE o PRIMEIRO alerta do range [inicio, fim].
    """
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

    d = inicio.date()
    while d <= fim.date():
        data_resp = api.post_day("day_relay", int(plant_id), datetime.combine(d, datetime.min.time()))
        if data_resp is None:
            d += timedelta(days=1)
            continue

        if isinstance(data_resp, list) and len(data_resp) > 0:
            tem_dados = True

        for registro in (data_resp or []):
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

            tipo = "OUTROS"
            for classe, lista in PARAMS_CLASSIF.items():
                if any(p in lista for p in ativos):
                    tipo = classe
                    break

            candidatos.append({
                "ts_leitura": ts,
                "rele_id": idrele,
                "parametros": ", ".join(sorted(ativos)),
                "tipo_alerta": tipo
            })
        d += timedelta(days=1)

    if not candidatos:
        return [], tem_dados

    # >>> Sempre devolver só o PRIMEIRO do período
    candidatos.sort(key=lambda a: a["ts_leitura"])
    return [candidatos[0]], tem_dados




# A função abaixo foi removida porque a lógica de falha de inversor não exige mais intervalo exato de 5 minutos


def detectar_falhas_inversores(api: PVOperationAPI, plant_id: str, inicio: datetime, fim: datetime,
                               falhas_ativas_previas: dict):
    JANELA_INICIO = dtime(6, 30)
    JANELA_FIM    = dtime(17, 30)

    leituras_por_inv = {}
    tem_dados = False

    d = inicio.date()
    while d <= fim.date():
        data_resp = api.post_day("day_inverter", int(plant_id), datetime.combine(d, datetime.min.time()))
        if data_resp is None:
            d += timedelta(days=1)
            continue

        for reg in (data_resp or []):
            conteudo = reg.get("conteudojson", {}) or {}
            inv_id = reg.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if not inv_id:
                continue
            try:
                ts = datetime.strptime(conteudo.get("tsleitura",""), "%Y-%m-%d %H:%M:%S")
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
                leituras_por_inv.setdefault(inv_id, []).append(
                    {"ts": ts, "cond_ok": False, "sem_dados": True, "pac": None}
                )
                continue

            pac = extrair_valor_numerico(pac_raw)
            cond = (pac == 0.0)
            leituras_por_inv.setdefault(inv_id, []).append(
                {"ts": ts, "cond_ok": cond, "sem_dados": False, "pac": pac}
            )
            tem_dados = True
        d += timedelta(days=1)

    falhas = []
    falhas_ativas = dict(falhas_ativas_previas)

    for inv_id, lst in leituras_por_inv.items():
        if not lst:
            continue
        lst.sort(key=lambda x: x["ts"])

        seq = 0
        state_key = f"{plant_id}:{inv_id}"
        ativa = falhas_ativas.get(state_key, False)

        for item in lst:
            ts = item["ts"]
            if item["sem_dados"]:
                seq = 0
                continue

            if not item["cond_ok"]:
                seq = 0
                if ativa:
                    ativa = False
                continue

            # contabiliza leituras consecutivas sem exigir passo exato de 5 minutos
            if seq == 0:
                seq = 1
            else:
                seq += 1

            if seq >= 3 and not ativa:
                falhas.append({
                    "inversor_id": str(inv_id),
                    "ts_leitura": ts,
                    "status": "FALHA",
                    "indicadores": {"pac": 0.0}
                })
                ativa = True

        falhas_ativas[state_key] = ativa

    return falhas, tem_dados, falhas_ativas



# =========================
# FRONTEND / APP
# =========================
class RelayMonitor:
    def __init__(self, root):
        self.root = root

        # Estados
        self.alertas_ativos = {}
        self.inversores_ativos = {}
        self.alertas_notificados = set()
        self.alertas_inversores_notificados = set()
        self.sem_dados_ativos = {}  # APENAS inversor
        # mapeamento de primeiro alerta por usina removido; nova lógica trata cada varredura de forma independente


        self.falhas_ativas_por_inv = {}  # estado persistente por inversor (limpa com leitura normal)
        self.varredura_ativa = True
        self.thread_lock = threading.Lock()
        self._thread_varredura = None

        self.ultima_varredura = None
        self.ultima_varredura_rele = None
        self.ultima_varredura_inversor = None

        # API
        self.api = PVOperationAPI(
            email="monitoramento@settaenergia.com.br",
            password="$$Setta1324"
        )

        # UI
        self._setup_ui()

        # contador de varreduras realizadas
        self.num_varreduras = 0

        # inicia primeira varredura
        self.executar_varredura_thread()

    def _ui(self, fn, *args, **kwargs):
        """Agenda uma chamada de UI na thread principal do Tkinter."""
        try:
            self.root.after(0, lambda: fn(*args, **kwargs))
        except Exception:
            pass


    # ---------- UI ----------
    def _setup_ui(self):
        self.root.title("Monitor de Relés e Inversores - Setta Serviços")
        self.root.geometry("1200x700")
        self.root.configure(bg=STYLE_CONFIG["bg"])

        style = ThemedStyle(self.root)
        style.set_theme("arc")
        ttk_style = ttk.Style()
        ttk_style.configure("Custom.Treeview",
                            font=STYLE_CONFIG["font"],
                            rowheight=25,
                            bordercolor="#dee2e6",
                            lightcolor="#ffffff",
                            fieldbackground=STYLE_CONFIG["bg"])
        ttk_style.map("Custom.Treeview",
                      background=[("selected", STYLE_CONFIG["highlight"])])

        if os.path.exists(LOGO_PATH):
            img = Image.open(LOGO_PATH)
            img = img.resize((220, 80))
            self.logo_img = ImageTk.PhotoImage(img)
            tk.Label(self.root, image=self.logo_img, bg="#f5f5f5").pack(pady=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)

        # ---- Aba Lista de Alertas (Relé) ----
        table_frame = ttk.Frame(self.notebook)
        self.notebook.add(table_frame, text="Alertas Relés")

        colunas = [("Usina", 200), ("Capacidade", 100), ("Relé", 110),
                   ("Horário", 140), ("Tipo Alerta", 140), ("Parâmetros", 260)]
        self.tree = ttk.Treeview(table_frame, columns=[c for c, _ in colunas],
                                 show="headings", style="Custom.Treeview")
        for col, width in colunas:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", expand=True, fill="both")
        scroll.pack(side="right", fill="y")

        # tags por tipo
        self.tree.tag_configure("SOBRETENSÃO",
                                background='#ffebee', foreground='#b71c1c', font=('Segoe UI', 9, 'bold'))
        self.tree.tag_configure("SUBTENSÃO",
                                background='#e3f2fd', foreground='#0d47a1', font=('Segoe UI', 9, 'bold'))
        self.tree.tag_configure("FREQUÊNCIA",
                                background='#fff8e1', foreground='#ff6f00', font=('Segoe UI', 9, 'italic'))
        self.tree.tag_configure("TÉRMICO",
                                background='#ffebee', foreground='#e53935', font=('Segoe UI', 9))
        self.tree.tag_configure("BLOQUEIO",
                                background='#e8f5e9', foreground='#2e7d32', font=('Segoe UI', 9, 'italic'))
        self.tree.tag_configure("OUTROS",
                                background='#f5f5f5', foreground='#424242', font=('Segoe UI', 9))

        # ---- Aba Status Inversores ----
        inverter_frame = ttk.Frame(self.notebook)
        self.notebook.add(inverter_frame, text="Alertas Inversores")
        colunas_inv = [("Usina", 200), ("Capacidade", 100), ("Inversor", 120),
                       ("Horário", 140), ("Status", 140), ("Detalhes", 260)]
        self.inverter_tree = ttk.Treeview(inverter_frame, columns=[c for c, _ in colunas_inv],
                                          show="headings", style="Custom.Treeview")
        for col, width in colunas_inv:
            self.inverter_tree.heading(col, text=col)
            self.inverter_tree.column(col, width=width, anchor="center")
        scroll_inv = ttk.Scrollbar(inverter_frame, orient="vertical", command=self.inverter_tree.yview)
        self.inverter_tree.configure(yscrollcommand=scroll_inv.set)
        self.inverter_tree.pack(side="left", expand=True, fill="both")
        scroll_inv.pack(side="right", fill="y")
        self.inverter_tree.tag_configure("FALHA",
                                         background='#ffebee', foreground='#c62828', font=('Segoe UI', 9, 'bold'))

        # ---- Aba Estatísticas ----
        self.graph_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.graph_frame, text="Estatísticas")
        self.figure = Figure(figsize=(8, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill="both")
        self.notebook.bind("<<NotebookTabChanged>>", self._update_graph)  # chama sempre que troca aba

        # ---- Aba "Sem Dados" (somente inversor) ----
        self.no_data_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.no_data_frame, text="Sem Dados")
        colunas_sem = [("Usina", 220), ("Tipo", 100), ("Data", 110), ("Última Verificação", 180)]
        self.no_data_tree = ttk.Treeview(self.no_data_frame, columns=[c for c, _ in colunas_sem],
                                         show="headings", style="Custom.Treeview")
        for col, width in colunas_sem:
            self.no_data_tree.heading(col, text=col)
            self.no_data_tree.column(col, width=width, anchor="center")
        scroll_sem = ttk.Scrollbar(self.no_data_frame, orient="vertical", command=self.no_data_tree.yview)
        self.no_data_tree.configure(yscrollcommand=scroll_sem.set)
        self.no_data_tree.pack(side="left", expand=True, fill="both")
        scroll_sem.pack(side="right", fill="y")

        # ---- Barra inferior / status ----

        self.notification_frame = tk.Frame(self.root, bg="#f0f0f0", height=30)
        self.notification_var = tk.StringVar()
        self.notification_label = tk.Label(self.notification_frame, textvariable=self.notification_var,
                                           bg="#fff3e0", fg="#e65100", font=("Segoe UI", 9, "bold"))
        self.notification_label.pack(fill="x", padx=2, pady=2)
        self.notification_frame.pack_forget()

        self.status_frame = tk.Frame(self.root, bg="#f0f0f0", height=24)
        self.status_frame.pack(fill="x", side="bottom", pady=(0, 0))
        self.status_icon = tk.Label(self.status_frame, text="●", font=("Segoe UI", 12),
                                    bg="#f0f0f0", fg="#4CAF50")
        self.status_icon.pack(side="left", padx=(10, 5))
        self.status_var = tk.StringVar(value="Pronto para iniciar monitoramento")
        tk.Label(self.status_frame, textvariable=self.status_var, font=("Segoe UI", 9),
                 bg="#f0f0f0", fg="#333333", anchor="w").pack(side="left", fill="x", expand=True)
        self.alert_count_var = tk.StringVar(value="Alertas: 0")
        tk.Label(self.status_frame, textvariable=self.alert_count_var, font=("Segoe UI", 9),
                 bg="#f0f0f0").pack(side="left", padx=10)
        self.inv_status_var = tk.StringVar(value="Inversores: 0")
        tk.Label(self.status_frame, textvariable=self.inv_status_var, font=("Segoe UI", 9),
                 bg="#f0f0f0").pack(side="left", padx=10)
        self.varreduras_var = tk.StringVar(value="Varreduras: 0")
        tk.Label(self.status_frame, textvariable=self.varreduras_var, font=("Segoe UI", 9),
                 bg="#f0f0f0").pack(side="left", padx=10)
        self.contador_var = tk.StringVar(value="Próxima varredura em: --:--")
        tk.Label(self.status_frame, textvariable=self.contador_var, font=("Segoe UI", 9),
                 bg="#f0f0f0").pack(side="left", padx=10)

    # ---------- Utilidades UI ----------
    def show_notification(self, msg, level="info"):
        self.notification_var.set(msg)
        self.notification_frame.pack(fill="x")
        self.root.after(4000, lambda: self.notification_frame.pack_forget())

    def atualizar_status(self, msg):
        self.status_var.set(msg)
        logger.info(msg)

    # Métodos de filtro foram removidos. Mantidos como no-op para compatibilidade.
    def _apply_filter(self, event=None):
        """Filtro desativado: não faz nada."""
        pass

    def _clear_filter(self):
        """Filtro desativado: não faz nada."""
        pass

    def _update_graph(self, event=None):
        # Atualiza somente quando a aba "Estatísticas" está ativa
        if self.notebook.index("current") != 2:
            return

        # Contagem por tipo (relé)
        tipos = ["SOBRETENSÃO", "SUBTENSÃO", "FREQUÊNCIA", "TÉRMICO", "BLOQUEIO", "OUTROS"]
        alert_counts = {t: 0 for t in tipos}
        for a in self.alertas_ativos.values():
            if a["tipo"] in alert_counts:
                alert_counts[a["tipo"]] += 1

        # Inversores em falha
        inv_falhas = sum(1 for inv in self.inversores_ativos.values() if inv["status"] == "FALHA")

        # Plot
        self.figure.clear()
        ax1 = self.figure.add_subplot(121)
        bars1 = ax1.bar(list(alert_counts.keys()), list(alert_counts.values()))
        ax1.set_title('Alertas de Relés por Tipo')
        ax1.set_ylabel('Quantidade')
        ax1.tick_params(axis='x', rotation=45)
        for b in bars1:
            h = b.get_height()
            ax1.text(b.get_x() + b.get_width()/2., h, f'{int(h)}', ha='center', va='bottom')

        ax2 = self.figure.add_subplot(122)
        bars2 = ax2.bar(["FALHA"], [inv_falhas])
        ax2.set_title('Inversores em Falha')
        ax2.set_ylabel('Quantidade')
        for b in bars2:
            h = b.get_height()
            ax2.text(b.get_x() + b.get_width()/2., h, f'{int(h)}', ha='center', va='bottom')

        self.figure.tight_layout()
        self.canvas.draw()

    # ---------- Fluxo principal ----------
    def executar_varredura_thread(self):
        with self.thread_lock:
            if self._thread_varredura and self._thread_varredura.is_alive():
                self.show_notification("Varredura já está em andamento", "warning")
                return
            self._thread_varredura = threading.Thread(target=self._executar_varredura_segura, daemon=True)
            self._thread_varredura.start()

    def _executar_varredura_segura(self):
        try:
            self.executar_varredura()
        except Exception as e:
            logger.exception("Erro durante varredura")
            self._ui(self.atualizar_status, f"Erro durante varredura: {e}")
            self._ui(self.status_icon.config, fg=STYLE_CONFIG["error"])



    def _iniciar_contagem_regressiva(self):
        """Agenda a próxima varredura em 20 min, atualizando o contador na UI."""
        total = 900  # 20 minutos

        def tick(restante):
            if not self.varredura_ativa:
                return
            mins, segs = divmod(restante, 60)
            self.contador_var.set(f"Próxima varredura em: {mins:02d}:{segs:02d}")
            if restante <= 0:
                self.executar_varredura_thread()
            else:
                self.root.after(1000, lambda: tick(restante - 1))

        tick(total)

    def executar_varredura(self):
        agora = datetime.now()
        inicio_janela = self.ultima_varredura_rele or datetime.combine(agora.date(), datetime.min.time())

        self._ui(self.atualizar_status, "Iniciando varredura...")
        self._ui(self.status_icon.config, fg="#f39c12")



        plantas = self.api.get_plants()
        if not plantas:
            self.atualizar_status("Nenhuma usina encontrada ou falha na API.")
            self.status_icon.config(fg=STYLE_CONFIG["error"])
            self._iniciar_contagem_regressiva()
            return

        novos_alertas_rele = {}
        novos_inversores = {}
        usinas_com_alerta_rele = set()

        # --- RELÉS ---
        for p in plantas:
            usina_id = str(p.get("id"))
            nome = p.get("nome")
            cap = p.get("capacidade")

            self.atualizar_status(f"Relés: analisando {nome}...")
            alertas, tem_dados_rele = detectar_alertas_rele(
                self.api, usina_id, inicio_janela, agora
            )

            # NÃO registrar "sem dados" para relé (requisito)

            for a in alertas:
                usinas_com_alerta_rele.add(usina_id)
                chave = f"{usina_id}_{a['rele_id']}_{a['tipo_alerta']}_{a['ts_leitura'].isoformat()}"
                if chave not in self.alertas_ativos:
                    # registra o alerta encontrado para a usina sempre no intervalo analisado
                    ts_first = a.get("ts_primeiro", a["ts_leitura"])
                    ts_last  = a.get("ts_ultimo",  a["ts_leitura"])
                    intervalo_txt = self.formatar_intervalo_alerta(ts_first, ts_last)

                    alerta_fmt = {
                        "usina": nome,
                        "capacidade": cap,
                        "rele": a["rele_id"],
                        "horario": a["ts_leitura"].strftime("%d/%m/%Y %H:%M:%S"),
                        "tipo": a["tipo_alerta"],
                        "parametros": f"{a['parametros']} | {intervalo_txt}" if intervalo_txt else a["parametros"],
                        "ts": a["ts_leitura"]
                    }
                    self.alertas_ativos[chave] = alerta_fmt
                    novos_alertas_rele[chave] = alerta_fmt


        # Atualiza UI relé
        self._ui(self._atualizar_tabela_reles, novos_alertas_rele)

        # --- INVERSORES (pular usinas com alerta de relé) ---
        for p in plantas:
            usina_id = str(p.get("id"))
            if usina_id in usinas_com_alerta_rele:
                logger.info(f"Pulando inversores de {p.get('nome')} devido a alerta de relé nesta varredura.")
                # Zera sequências daquela usina nesta varredura (estado é por inversor; limpamos flags que pertençam à usina)
                for k in list(self.falhas_ativas_por_inv.keys()):
                    if k.startswith(f"{usina_id}:"):
                        del self.falhas_ativas_por_inv[k]
                continue

            nome = p.get("nome")
            cap = p.get("capacidade")
            self.atualizar_status(f"Inversores: analisando {nome}...")

            falhas, tem_dados_inv, falhas_ativas_atual = detectar_falhas_inversores(
                self.api, usina_id, inicio_janela, agora, self.falhas_ativas_por_inv
            )
            self.falhas_ativas_por_inv.update(falhas_ativas_atual)

            if not tem_dados_inv:
                # registrar "Sem Dados" apenas para INVERSOR
                chave_sem = f"{usina_id}_{agora.date()}_INV"
                self.sem_dados_ativos[chave_sem] = {
                    "usina": nome, "tipo": "INVERSOR",
                    "data": agora.date().strftime("%d/%m/%Y"),
                    "ultima": agora
                }

            for f in falhas:
                chave_inv = f"{usina_id}_{f['inversor_id']}"
                if chave_inv not in self.inversores_ativos:
                    alert = {
                        "usina": nome,
                        "capacidade": cap,
                        "inversor": f['inversor_id'],
                        "horario": f['ts_leitura'].strftime("%d/%m/%Y %H:%M:%S"),
                        "status": f['status'],
                        "indicadores": f.get('indicadores', {})
                    }
                    self.inversores_ativos[chave_inv] = alert
                    novos_inversores[chave_inv] = alert

        # Atualiza UI inversor + “Sem Dados”
        self._ui(self._atualizar_tabela_inversores, novos_inversores)
        self._ui(self._atualizar_tabela_sem_dados)

        # Finalizações
        self.ultima_varredura = agora
        self.ultima_varredura_rele = agora
        self.ultima_varredura_inversor = agora

        self._ui(self.atualizar_status, "Varredura concluída.")
        self._ui(self.status_icon.config, fg=STYLE_CONFIG["success"])

        # Atualiza gráfico se a aba estiver aberta
        if self.notebook.index("current") == 2:
            self._ui(self._update_graph)

        # incrementa o número de varreduras e atualiza o contador na barra de status
        self.num_varreduras += 1
        # atualiza o texto da UI de forma thread-safe
        self._ui(self.varreduras_var.set, f"Varreduras: {self.num_varreduras}")

        # Agenda próxima varredura
        self._iniciar_contagem_regressiva()


    # ---------- Atualizadores de Tabela ----------
    def _atualizar_tabela_reles(self, novos_alertas):
        def _key(a):
            return a.get("ts") or datetime.min
        for alerta in sorted(novos_alertas.values(), key=_key, reverse=True):
            chave_notif = f"{alerta['usina']}_{alerta['rele']}_{alerta['horario']}"
            if chave_notif not in self.alertas_notificados:
                self.alertas_notificados.add(chave_notif)
                msg = (f"Usina: {alerta['usina']}\n"
                    f"Relé: {alerta['rele']}\n"
                    f"Tipo: {alerta['tipo']}\n"
                    f"Horário: {alerta['horario']}\n"
                    f"Parâmetros: {alerta['parametros']}")
                AlertPopup(self, msg, alerta["tipo"])

                # Notificação Teams
                try:
                    _teams_post_card(
                        title=f"⚠ Alerta de Relé ({alerta['tipo']})",
                        text=(
                            f"**Usina:** {alerta['usina']}  \n"
                            f"**Relé:** {alerta['rele']}  \n"
                            f"**Horário:** {alerta['horario']}  \n"
                            f"**Parâmetros:** {alerta['parametros']}"
                        ),
                        severity="danger" if alerta["tipo"] in ("SOBRETENSÃO", "TÉRMICO", "BLOQUEIO") else "warning",
                        facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
                    )
                except Exception:
                    pass

            # Inserção na tree
            self.tree.insert("", "end", values=(
                alerta["usina"],
                f"{alerta['capacidade']} kWp",
                alerta["rele"],
                alerta["horario"],
                alerta["tipo"],
                alerta["parametros"]
            ), tags=(alerta["tipo"],))

        # contadores para barra de status
        counts = {"SOBRETENSÃO": 0, "SUBTENSÃO": 0, "FREQUÊNCIA": 0, "TÉRMICO": 0, "BLOQUEIO": 0, "OUTROS": 0}
        for a in self.alertas_ativos.values():
            if a["tipo"] in counts:
                counts[a["tipo"]] += 1
        total = sum(counts.values())
        self.alert_count_var.set(f"Relés: {total}")


    def _atualizar_tabela_inversores(self, novos):
        for inv in sorted(novos.values(), key=lambda x: x["horario"], reverse=True):
            chave_notif = f"{inv['usina']}_{inv['inversor']}_{inv['horario']}"
            if chave_notif not in self.alertas_inversores_notificados:
                self.alertas_inversores_notificados.add(chave_notif)
                inds = inv.get('indicadores', {})
                msg = (f"Usina: {inv['usina']}\n"
                    f"Inversor: {inv['inversor']}\n"
                    f"Status: {inv['status']}\n"
                    f"Horário: {inv['horario']}\n"
                    f"Pac: {inds.get('pac', 'N/A')}")
                AlertPopup(self, msg, "INVERSOR")

                # Notificação Teams
                try:
                    detalhes_txt = f"Pac: {inds.get('pac','N/A')}"
                    _teams_post_card(
                        title="⚠ Falha de Inversor (Pac=0; 3 leituras consecutivas; 06:30–17:30)",
                        text=(
                            f"**Usina:** {inv['usina']}  \n"
                            f"**Inversor:** {inv['inversor']}  \n"
                            f"**Horário:** {inv['horario']}  \n"
                            f"**Detalhes:** {detalhes_txt}"
                        ),
                        severity="danger",
                        facts=[("Capacidade", f"{inv['capacidade']} kWp")],
                    )
                except Exception:
                    pass

            detalhes = []
            inds = inv.get('indicadores', {})
            if 'pac' in inds:
                detalhes.append(f"Pac: {inds['pac']}")
            texto_detalhes = " | ".join(detalhes) if detalhes else "Sem detalhes"

            self.inverter_tree.insert("", "end", values=(
                inv["usina"],
                f"{inv['capacidade']} kWp",
                inv["inversor"],
                inv["horario"],
                "FALHA (Pac == 0)",
                texto_detalhes
            ), tags=("FALHA",))

        total_falhas = sum(1 for inv in self.inversores_ativos.values() if inv["status"] == "FALHA")
        self.inv_status_var.set(f"Inversores: {total_falhas}")



    def _atualizar_tabela_sem_dados(self):
        # mostra apenas itens marcados para INVERSOR
        self.no_data_tree.delete(*self.no_data_tree.get_children())
        for _, evento in sorted(self.sem_dados_ativos.items(),
                                key=lambda kv: kv[1]['ultima'], reverse=True):
            self.no_data_tree.insert("", "end", values=(
                evento["usina"],
                evento["tipo"],   # "INVERSOR"
                evento["data"],
                evento["ultima"].strftime("%d/%m/%Y %H:%M:%S")
            ))

    @staticmethod
    def formatar_intervalo_alerta(ts_first, ts_last) -> str:
        if not ts_first or not ts_last:
            return ""
        if ts_first == ts_last:
            return f"Alerta às {ts_first.strftime('%H:%M')}"
        return (f"Primeiro alerta às {ts_first.strftime('%H:%M')} "
                f"e último às {ts_last.strftime('%H:%M')}")


# ========== MAIN ==========
def main():
    root = tk.Tk()
    app = RelayMonitor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
