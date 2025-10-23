import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from requests import Session
import logging
import os
from PIL import Image, ImageTk
from ttkthemes import ThemedStyle
import threading
import time
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import winsound
from threading import Thread
from queue import Queue
from requests.exceptions import Timeout, ConnectionError, RequestException
import re  # Importação adicionada

# Configurações
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

class AlertPopup:
    """Popup de alerta com fila para evitar múltiplos simultâneos"""
    popup_queue = Queue()
    popup_active = False

    def __init__(self, parent, message, alert_type):
        self.parent = parent
        self.message = message
        self.alert_type = alert_type

        # Enfileira o popup e tenta exibir se possível
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
        self.popup.geometry("400x200")
        self.popup.resizable(False, False)
        self.popup.attributes('-topmost', True)

        colors = {
            "SOBRETENSÃO": ("#ffebee", "#b71c1c"),
            "SUBTENSÃO": ("#e3f2fd", "#0d47a1"),
            "FREQUÊNCIA": ("#fff8e1", "#ff6f00"),
            "TÉRMICO": ("#ffebee", "#e53935"),
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
            wraplength=380
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
                winsound.Beep(1000, 500)
                time.sleep(1)
                winsound.Beep(1500, 500)
                time.sleep(1)
        except:
            pass

    def close(self):
        self.playing_sound = False
        self.popup.destroy()
        AlertPopup.popup_active = False
        # Tenta mostrar o próximo popup na fila
        self.try_show_next()

class RelayMonitor:
    def __init__(self, root):
        self.root = root
        self.alertas_ativos = {}
        self.inversores_ativos = {}
        self.ultima_varredura = None
        # Novos marcadores para controlar intervalos independentes de varredura
        self.ultima_varredura_rele = None
        self.ultima_varredura_inversor = None
        self.varredura_ativa = False
        self.contador_varreduras = 0
        self.alertas_notificados = set()
        self.alertas_inversores_notificados = set()
        self.thread_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.cache_plantas = None
        self.cache_plantas_timestamp = None
        self.cache_timeout = 3600  # 1 hora em segundos
        self.ultima_limpeza = None


        # Registro de ocorrências sem dados para relés/inversores
        self.sem_dados_ativos = {}
        self.sem_dados_notificados = set()

        self._create_main_frames()
        self._setup_api()
        self._setup_ui()
        self.iniciar_monitoramento()

        # Periodicamente limpa sets de alertas notificados para evitar crescimento
        self.root.after(3600000, self._limpar_alertas_notificados)

    def _limpar_alertas_notificados(self):
        self.alertas_notificados.clear()
        self.alertas_inversores_notificados.clear()
        self.root.after(3600000, self._limpar_alertas_notificados)

    def _create_main_frames(self):
        self.status_frame = tk.Frame(self.root, bg="#f0f0f0", height=24)
        self.status_frame.pack(fill="x", side="bottom", pady=(0, 0))

        self.notification_frame = tk.Frame(self.root, bg="#f0f0f0", height=30)
        self.notification_frame.pack(fill="x", before=self.status_frame)
        self.notification_frame.pack_forget()

    def _login(self):
        json_data = {"username": self.email, "password": self.password}
        try:
            response = self.session.post(f"{self.base_url}/authenticate", json=json_data, timeout=15)
            if response.status_code == 200:
                return response.json().get("token")
            else:
                logging.error(f"Falha na autenticação. Status: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Erro durante login: {str(e)}")
            return None

    def _setup_api(self):
        self.email = "monitoramento@settaenergia.com.br"
        self.password = "$$Setta123"
        self.session = Session()
        self.base_url = "https://apipv.pvoperation.com.br/api/v1"
        self.token = self._login()
        if not self.token:
            messagebox.showerror("Erro", "Falha na autenticação")
            self.root.destroy()
            return
        self.headers = {"x-access-token": self.token}

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
            logo_label = tk.Label(self.root, image=self.logo_img, bg="#f5f5f5")
            logo_label.pack(pady=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)

        # Frame alertas relés
        self.table_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.table_frame, text="Lista de Alertas")

        colunas = [("Usina", 200), ("Capacidade", 80), ("Relé", 100),
                   ("Horário", 120), ("Tipo Alerta", 150), ("Parâmetros", 200)]

        self.tree = ttk.Treeview(self.table_frame, columns=[col[0] for col in colunas],
                                 show="headings", style="Custom.Treeview")

        for col, width in colunas:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_column(c, False))
            self.tree.column(col, width=width, anchor="center")

        scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")

        # Tags de alertas
        self.tree.tag_configure("SOBRETENSÃO",
                                background='#ffebee',
                                foreground='#b71c1c',
                                font=('Segoe UI', 9, 'bold'))

        self.tree.tag_configure("SUBTENSÃO",
                                background='#e3f2fd',
                                foreground='#0d47a1',
                                font=('Segoe UI', 9, 'bold'))

        self.tree.tag_configure("FREQUÊNCIA",
                                background='#fff8e1',
                                foreground='#ff6f00',
                                font=('Segoe UI', 9, 'italic'))

        self.tree.tag_configure("TÉRMICO",
                                background='#ffebee',
                                foreground='#e53935',
                                font=('Segoe UI', 9))
        
        self.tree.tag_configure("BLOQUEIO",
                        background='#e8f5e9',
                        foreground='#2e7d32',
                        font=('Segoe UI', 9, 'italic'))

        self.tree.tag_configure("OUTROS",
                                background='#f5f5f5',
                                foreground='#424242',
                                font=('Segoe UI', 9))

        self.tree.tag_configure("verificado",
                                background='#e8f5e9',
                                font=('Segoe UI', 9))

        self.tree.tag_configure("hidden", background='', foreground='')

        # Aba status inversores
        self.inverter_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.inverter_frame, text="Status Inversores")

        # COLUNA ADICIONAL PARA DETALHES
        colunas_inversores = [("Usina", 200), ("Capacidade", 80), ("Inversor", 100),
                              ("Horário", 120), ("Status", 100), ("Detalhes", 150)]

        self.inverter_tree = ttk.Treeview(self.inverter_frame, columns=[col[0] for col in colunas_inversores],
                                          show="headings", style="Custom.Treeview")

        for col, width in colunas_inversores:
            self.inverter_tree.heading(col, text=col)
            self.inverter_tree.column(col, width=width, anchor="center")

        scrollbar_inv = ttk.Scrollbar(self.inverter_frame, orient="vertical", command=self.inverter_tree.yview)
        self.inverter_tree.configure(yscrollcommand=scrollbar_inv.set)

        self.inverter_tree.pack(side="left", expand=True, fill="both")
        scrollbar_inv.pack(side="right", fill="y")

        # Tags status inversores
        self.inverter_tree.tag_configure("FALHA",
                                        background='#ffebee',
                                        foreground='#c62828',
                                        font=('Segoe UI', 9, 'bold'))

        # Aba estatísticas
        self.graph_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.graph_frame, text="Estatísticas")

        self.figure = Figure(figsize=(8, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill="both")

        self.notebook.bind("<<NotebookTabChanged>>", self._update_graph)

        # Aba "Sem Dados" para registrar usinas que não retornaram dados na
        # consulta (tanto para relés quanto para inversores).  A ideia é
        # permitir que o operador visualize facilmente quais usinas não
        # forneceram medições no período analisado, sem inundar as outras
        # tabelas.
        self.no_data_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.no_data_frame, text="Sem Dados")

        colunas_sem = [
            ("Usina", 200),
            ("Tipo", 80),  # "RELÉ" ou "INVERSOR"
            ("Data", 80),  # Data da falta de dados
            ("Última Verificação", 150)
        ]
        self.no_data_tree = ttk.Treeview(
            self.no_data_frame,
            columns=[col[0] for col in colunas_sem],
            show="headings",
            style="Custom.Treeview"
        )
        for col, width in colunas_sem:
            self.no_data_tree.heading(col, text=col)
            self.no_data_tree.column(col, width=width, anchor="center")
        scrollbar_sem = ttk.Scrollbar(self.no_data_frame, orient="vertical", command=self.no_data_tree.yview)
        self.no_data_tree.configure(yscrollcommand=scrollbar_sem.set)
        self.no_data_tree.pack(side="left", expand=True, fill="both")
        scrollbar_sem.pack(side="right", fill="y")

        # Filtros
        self.filter_frame = tk.Frame(self.root, bg=STYLE_CONFIG["bg"])
        self.filter_frame.pack(fill="x", padx=10, pady=(0, 5))

        tk.Label(self.filter_frame, text="Filtrar:", bg=STYLE_CONFIG["bg"]).pack(side="left")

        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(self.filter_frame, textvariable=self.filter_var)
        self.filter_entry.pack(side="left", expand=True, fill="x", padx=5)
        self.filter_entry.bind("<KeyRelease>", self._apply_filter)

        ttk.Button(self.filter_frame, text="Limpar",
                   command=self._clear_filter).pack(side="left", padx=5)

        self.filter_type_var = tk.StringVar(value="TODOS")
        types = ["TODOS", "SOBRETENSÃO", "SUBTENSÃO", "FREQUÊNCIA", "TÉRMICO", "OUTROS"]
        self.type_menu = ttk.OptionMenu(self.filter_frame, self.filter_type_var, *types,
                                       command=self._apply_filter)
        self.type_menu.pack(side="left", padx=5)

        self.notification_var = tk.StringVar()
        self.notification_label = tk.Label(
            self.notification_frame,
            textvariable=self.notification_var,
            bg="#fff3e0",
            fg="#e65100",
            font=("Segoe UI", 9, "bold")
        )
        self.notification_label.pack(fill="x", padx=2, pady=2)

        self.status_icon = tk.Label(self.status_frame, text="●", font=("Segoe UI", 12),
                                    bg="#f0f0f0", fg="#4CAF50")
        self.status_icon.pack(side="left", padx=(10, 5))

        self.status_var = tk.StringVar(value="Pronto para iniciar monitoramento")
        tk.Label(self.status_frame, textvariable=self.status_var,
                 font=("Segoe UI", 9), bg="#f0f0f0", fg="#333333",
                 anchor="w").pack(side="left", fill="x", expand=True)

        self.alert_count_var = tk.StringVar(value="Alertas: 0")
        tk.Label(self.status_frame, textvariable=self.alert_count_var,
                 font=("Segoe UI", 9), bg="#f0f0f0").pack(side="left", padx=10)

        self.inv_status_var = tk.StringVar(value="Inversores Falha: 0")
        tk.Label(self.status_frame, textvariable=self.inv_status_var,
                 font=("Segoe UI", 9), bg="#f0f0f0").pack(side="left", padx=10)

        self.varreduras_var = tk.StringVar(value="Varreduras: 0")
        tk.Label(self.status_frame, textvariable=self.varreduras_var,
                 font=("Segoe UI", 9), bg="#f0f0f0").pack(side="left", padx=10)

        self.contador_var = tk.StringVar(value="Próxima varredura em: --:--")
        tk.Label(self.status_frame, textvariable=self.contador_var,
                 font=("Segoe UI", 9), bg="#f0f0f0", fg="#666666").pack(side="right", padx=10)

        self.progress = ttk.Progressbar(self.status_frame, orient="horizontal",
                                        mode="determinate", length=100)
        self.progress.pack(side="right", padx=10)

        button_frame = tk.Frame(self.root, bg=STYLE_CONFIG["bg"])
        button_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(button_frame, text="Forçar Varredura",
                   command=self.executar_varredura_thread).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Exportar CSV",
                   command=self.exportar_csv).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Exportar Inversores",
                   command=self.exportar_inversores_csv).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Limpar",
                   command=self.limpar_alertas).pack(side="left", padx=5)

        # Informativo de critério fixo para detecção de falhas em inversores
        self.config_frame = ttk.Frame(self.root)
        self.config_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(self.config_frame, text="Critério de falha (inversor): Pac ≤ 0 e Status ≠ 1").pack(side="left")
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copiar Dados", command=self._copy_data)
        self.context_menu.add_command(label="Marcar como Verificado", command=self._mark_as_verified)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Exportar Seleção", command=self._export_selection)

        self.tree.bind("<Button-3>", self._show_context_menu)

        # Menu de contexto para inversores
        self.inv_context_menu = tk.Menu(self.root, tearoff=0)
        self.inv_context_menu.add_command(label="Copiar Dados", command=self._copy_inverter_data)
        self.inv_context_menu.add_separator()
        self.inv_context_menu.add_command(label="Exportar Seleção", command=self._export_inverter_selection)

        self.inverter_tree.bind("<Button-3>", self._show_inv_context_menu)

        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.withdraw()
        self.tooltip.overrideredirect(True)
        self.tooltip_label = tk.Label(self.tooltip, bg="#ffffe0", relief="solid", borderwidth=1)
        self.tooltip_label.pack()

        self.tree.bind("<Motion>", self._show_tooltip)
        self.tree.bind("<Leave>", lambda e: self.tooltip.withdraw())

    def _sort_column(self, col, reverse):
        data = [(self.tree.set(child, col), child)
                for child in self.tree.get_children('')]

        try:
            data.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            data.sort(reverse=reverse)

        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)

        self.tree.heading(col, command=lambda: self._sort_column(col, not reverse))

    def _aplicar_configuracao(self):
        # Critério fixo; não há configuração aplicável.
        self.show_notification("Critério de falha é fixo: Pac ≤ 0 e Status ≠ 1", "info")

    def _apply_filter(self, event=None):
        filter_text = self.filter_var.get().lower()
        filter_type = self.filter_type_var.get()

        for child in self.tree.get_children():
            item = self.tree.item(child)
            values = [str(v).lower() for v in item['values']]
            tags = item['tags']

            type_match = (filter_type == "TODOS") or (filter_type in tags)
            text_match = (not filter_text) or any(filter_text in v for v in values)

            # Usar tags para ocultar linhas: adiciona tag "hidden" para ocultar
            if type_match and text_match:
                new_tags = tuple(tag for tag in tags if tag != "hidden")
            else:
                new_tags = tuple(set(tags) | {"hidden"})

            self.tree.item(child, tags=new_tags)

        # Configuração visual: linhas com tag hidden ficam invisíveis
        self._update_tree_visibility(self.tree)

    def _update_tree_visibility(self, treeview):
        # Oculta linhas que tem tag 'hidden'
        for child in treeview.get_children():
            tags = treeview.item(child, "tags")
            if "hidden" in tags:
                treeview.detach(child)
            else:
                treeview.reattach(child, "", "end")

    def _clear_filter(self):
        """Limpa filtros aplicados na lista de alertas.

        Como não há filtragem específica para os inversores ou para a aba de
        sem dados, apenas restaura o filtro de texto e o tipo de alerta.
        """
        self.filter_var.set("")
        self.filter_type_var.set("TODOS")
        self._apply_filter()

    def _update_graph(self, event=None):
        if self.notebook.index("current") != 2:  # Aba estatísticas é a 3ª aba (0-based)
            return

        alert_counts = {"SOBRETENSÃO": 0, "SUBTENSÃO": 0, "FREQUÊNCIA": 0,
                        "TÉRMICO": 0, "OUTROS": 0}

        for alerta in self.alertas_ativos.values():
            alert_counts[alerta["tipo"]] += 1

        inv_counts = {"FALHA": 0}
        for inversor in self.inversores_ativos.values():
            if inversor["status"] == "FALHA":
                inv_counts["FALHA"] += 1

        self.figure.clear()

        ax1 = self.figure.add_subplot(121)
        types = list(alert_counts.keys())
        counts = list(alert_counts.values())
        bars1 = ax1.bar(types, counts, color=['#ef5350', '#42a5f5', '#ffee58', '#ffa726', '#9e9e9e'])
        ax1.set_title('Alertas de Relés por Tipo')
        ax1.set_ylabel('Quantidade')
        ax1.tick_params(axis='x', rotation=45)
        for bar in bars1:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{int(height)}', ha='center', va='bottom')

        ax2 = self.figure.add_subplot(122)
        inv_types = list(inv_counts.keys())
        inv_counts_vals = list(inv_counts.values())
        bars2 = ax2.bar(inv_types, inv_counts_vals, color=['#66bb6a', '#ef5350'])
        ax2.set_title('Status dos Inversores')
        ax2.set_ylabel('Quantidade')
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{int(height)}', ha='center', va='bottom')

        self.figure.tight_layout()
        self.canvas.draw()

    def show_notification(self, message, level="info"):
        colors = {
            "info": ("#e3f2fd", "#0d47a1"),
            "warning": ("#fff8e1", "#ff6f00"),
            "error": ("#ffebee", "#b71c1c")
        }

        bg, fg = colors.get(level, ("#f5f5f5", "#212529"))

        self.notification_label.config(bg=bg, fg=fg)
        self.notification_var.set(message)
        self.notification_frame.pack(fill="x", before=self.status_frame)

        self.root.after(5000, self.hide_notification)

    def hide_notification(self):
        self.notification_frame.pack_forget()

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _show_inv_context_menu(self, event):
        item = self.inverter_tree.identify_row(event.y)
        if item:
            self.inverter_tree.selection_set(item)
            self.inv_context_menu.post(event.x_root, event.y_root)

    def _copy_data(self):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        self.root.clipboard_clear()
        self.root.clipboard_append("\t".join(str(v) for v in item['values']))
        self.show_notification("Dados copiados para a área de transferência", "info")

    def _copy_inverter_data(self):
        selected = self.inverter_tree.selection()
        if not selected:
            return

        item = self.inverter_tree.item(selected[0])
        self.root.clipboard_clear()
        self.root.clipboard_append("\t".join(str(v) for v in item['values']))
        self.show_notification("Dados copiados para a área de transferência", "info")

    def _mark_as_verified(self):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        current_tags = item['tags']
        if "verificado" not in current_tags:
            self.tree.item(selected[0], tags=current_tags + ('verificado',))
            self.show_notification("Alerta marcado como verificado", "info")

    def _export_selection(self):
        selected = self.tree.selection()
        if not selected:
            return

        from tkinter import filedialog
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Salvar seleção como CSV"
        )

        if caminho:
            import csv
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Usina", "Capacidade (kWp)", "Relé", "Horário", "Tipo Alerta", "Parâmetros"])
                for item_id in selected:
                    item = self.tree.item(item_id)
                    writer.writerow(item['values'])

            messagebox.showinfo("Exportar", f"Seleção exportada para:\n{caminho}")
            self.show_notification(f"Seleção exportada para {caminho}", "info")

    def _export_inverter_selection(self):
        selected = self.inverter_tree.selection()
        if not selected:
            return

        from tkinter import filedialog
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Salvar seleção de inversores como CSV"
        )

        if caminho:
            import csv
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Usina", "Capacidade (kWp)", "Inversor", "Horário", "Status"])
                for item_id in selected:
                    item = self.inverter_tree.item(item_id)
                    writer.writerow(item['values'])

            messagebox.showinfo("Exportar", f"Seleção de inversores exportada para:\n{caminho}")
            self.show_notification(f"Seleção de inversores exportada para {caminho}", "info")

    def _show_tooltip(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            self.tooltip.withdraw()
            return

        col = self.tree.identify_column(event.x)
        if col == '#5':
            values = self.tree.item(item, 'values')
            text = f"Tipo: {values[4]}\nParâmetros: {values[5]}"
            self.tooltip_label.config(text=text)
            self.tooltip.update_idletasks()
            self.tooltip.geometry(f"+{event.x_root + 20}+{event.y_root + 10}")
            self.tooltip.deiconify()

    def atualizar_status(self, texto):
        def update():
            timestamp = datetime.now().strftime("[%H:%M:%S]")
            self.status_var.set(f"{timestamp} {texto}")
        self.root.after(0, update)

    # Atualizações seguras da UI:
    def safe_ui_update(self, func, *args):
        self.root.after(0, lambda: func(*args))

    def buscar_plantas(self):
        agora = time.time()
        
        # Verifica se o cache é válido
        if (self.cache_plantas is not None and 
            self.cache_plantas_timestamp is not None and
            (agora - self.cache_plantas_timestamp) < self.cache_timeout):
            return self.cache_plantas
        
        try:
            response = self.session.get(f"{self.base_url}/plants", headers=self.headers, timeout=15)
            if response.status_code == 200:
                self.cache_plantas = response.json()
                self.cache_plantas_timestamp = agora
                return self.cache_plantas
            else:
                logging.error(f"Erro ao buscar plantas. Status: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Exceção ao buscar plantas: {str(e)}")
            return []

    def buscar_alertas_reles(self, usina_id, inicio_periodo, fim_periodo):
        PARAMETROS_RELE = [
            "r27A", "r27B", "r27C", "r27_0", "r32A", "r32A_2",
            "r32B", "r32B_2", "r32C", "r32C_2", "r46Q", "r47",
            "r59A", "r59B", "r59C", "r59N", "r67A", "r67A_2",
            "r67B", "r67B_2", "r67C", "r67C_2", "r67N_1", "r67N_2",
            "r78", "r81O", "r81U", "r86", "rAR", "rBA", "rDO",
            "rEPwd", "rERLS", "rEl2t", "rFR", "rGS", "rHLT",
            "rRL1", "rRL2", "rRL3", "rRL4", "rRL5", "rRR"
        ]
        alertas = []
        data_atual = inicio_periodo.date()
        while data_atual <= fim_periodo.date():
            try:
                response = self.session.post(
                    f"{self.base_url}/day_relay",
                    json={"id": int(usina_id), "date": data_atual.strftime("%Y-%m-%d")},
                    headers=self.headers,
                    timeout=15
                )
                
                if response.status_code == 401:
                    logging.warning("Token expirado. Tentando renovar...")
                    if not self.verificar_token():
                        break
                    continue
                        
                if response.status_code != 200:
                    logging.warning(f"Status não OK para alertas de relé: {response.status_code}")
                    data_atual += timedelta(days=1)
                    continue
                dados = response.json()
                for registro in dados:
                    conteudo = registro.get("conteudojson", {})
                    dispositivo_id = registro.get("idrele")
                    if not dispositivo_id:
                        continue
                    try:
                        ts_leitura = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
                        if inicio_periodo <= ts_leitura <= fim_periodo:
                            parametros_ativados = [p for p in PARAMETROS_RELE if conteudo.get(p, False) is True]
                            if parametros_ativados:
                                classificacao = {
                                    "SOBRETENSÃO": ["r59A", "r59B", "r59C", "r59N"],
                                    "SUBTENSÃO": ["r27A", "r27B", "r27C", "r27_0"],
                                    "FREQUÊNCIA": ["r81O", "r81U"],
                                    "TÉRMICO": ["r49", "r49_2"],
                                    "BLOQUEIO": ["rAR", "rBA", "rDO"],
                                    "OUTROS": []  # Todos os outros parâmetros
                                }
                                tipo_alerta = "OUTROS"
                                for tipo, params in classificacao.items():
                                    if any(p in parametros_ativados for p in params):
                                        tipo_alerta = tipo
                                        break
                                alertas.append({
                                    "ts_leitura": ts_leitura,
                                    "rele_id": dispositivo_id,
                                    "parametros": ", ".join(parametros_ativados),
                                    "tipo_alerta": tipo_alerta
                                })
                    except (ValueError, TypeError, KeyError):
                        continue
            except Timeout:  # CORRIGIDO: requests.exceptions.Timeout -> Timeout
                logging.warning(f"Timeout ao buscar alertas para usina {usina_id}")
            except Exception as e:
                logging.error(f"Erro ao buscar alertas: {str(e)}")
            finally:
                data_atual += timedelta(days=1)
        return alertas
    
    def buscar_status_inversores(self, usina_id, inicio_periodo, fim_periodo):
        """
        Busca status dos inversores e detecta falhas usando regra binária:
        registra FALHA quando (Pac ≤ 0) e (Status ≠ 1).
        
        Retorna (falhas, tem_dados).
        """
        falhas = []
        tem_dados = False
        data_atual = inicio_periodo.date()
        
        # Obter capacidade da usina para calcular percentual de potência
        capacidade_usina = self._obter_capacidade_usina(usina_id)
        
        while data_atual <= fim_periodo.date():
            try:
                response = self.session.post(
                    f"{self.base_url}/day_inverter",
                    json={"id": int(usina_id), "date": data_atual.strftime("%Y-%m-%d")},
                    headers=self.headers,
                    timeout=15
                )
                
                if response.status_code != 200 or not response.json():
                    data_atual += timedelta(days=1)
                    continue

                dados = response.json()
                leituras_por_inversor = {}
                
                for registro in dados:
                    conteudo = registro.get("conteudojson", {})
                    dispositivo_id = registro.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
                    if not dispositivo_id:
                        continue
                        
                    try:
                        ts_leitura = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
                        if inicio_periodo <= ts_leitura <= fim_periodo:
                            leitura_time = ts_leitura.time()
                            if not (leitura_time >= datetime.strptime("06:30", "%H:%M").time() and
                                    leitura_time <= datetime.strptime("17:30", "%H:%M").time()):
                                continue
                                
                            tem_dados = True
                            
                            if dispositivo_id not in leituras_por_inversor:
                                leituras_por_inversor[dispositivo_id] = []
                                
                            # *** Nova lógica de falha de inversor ***
                            # Regras:
                            # - Falha somente quando (Pac <= 0) E (Status != 1)
                            # - Ignora qualquer outro parâmetro (tensão, temperatura, códigos, etc.)
                            
                            indicadores = {}
                            
                            # Status (esperado 1 = normal/operando)
                            raw_status = conteudo.get("Status", 0)
                            try:
                                status_code = float(raw_status)
                            except:
                                status_code = 0.0
                            
                            # Potência ativa (Pac) — tenta múltiplas chaves comuns do payload
                            # Ordem de preferência: 'Pac', 'Potencia_Saida', 'Pout', 'Potencia'
                            pac_raw = None
                            for k in ("Pac", "PAC", "Potencia_Saida", "Pout", "Potencia"):
                                if k in conteudo:
                                    pac_raw = conteudo.get(k)
                                    break
                            pac = self._extrair_valor_numerico(pac_raw if pac_raw is not None else 0)
                            
                            falha_condicional = (pac <= 0) and (status_code != 1)
                            if falha_condicional:
                                indicadores["status"] = status_code
                                indicadores["pac"] = pac
                                pontuacao = 1  # marcador binário de falha
                            else:
                                pontuacao = 0
                            
                            leituras_por_inversor[dispositivo_id].append({
                                "timestamp": ts_leitura,
                                "pontuacao": pontuacao,
                                "indicadores": indicadores,
                                "dados_completos": conteudo
                            })
                            
                    except Exception as e:
                        continue

                # Processar leituras para cada inversor
                for inversor_id, leituras in leituras_por_inversor.items():
                    if not leituras:
                        continue
                        
                    leituras.sort(key=lambda x: x["timestamp"])
                    
                    # Verificar se a pontuação acumulada atinge o mínimo
                    # Verificar se houve ao menos uma leitura em falha (Pac <= 0 e Status != 1)
                    houve_falha = any(leitura["pontuacao"] == 1 for leitura in leituras)
                    if houve_falha:
                        # Escolher a leitura de falha mais recente
                        leitura_critica = max((l for l in leituras if l["pontuacao"] == 1), key=lambda x: x["timestamp"])
                        
                        falhas.append({
                            "ts_leitura": leitura_critica["timestamp"],
                            "inversor_id": inversor_id,
                            "status": "FALHA",
                            "pontuacao": 1,
                            "indicadores": leitura_critica["indicadores"]
                        })
                        
            except Exception as e:
                logging.error(f"Erro ao buscar status inversores (usina {usina_id}, data {data_atual}): {str(e)}")
                data_atual += timedelta(days=1)
                continue
                
            data_atual += timedelta(days=1)
            
        return falhas, tem_dados

    def _obter_capacidade_usina(self, usina_id):
        """Obtém a capacidade da usina para cálculos de percentual"""
        if not hasattr(self, '_cache_capacidades'):
            self._cache_capacidades = {}
            
        if usina_id in self._cache_capacidades:
            return self._cache_capacidades[usina_id]
            
        try:
            plantas = self.buscar_plantas()
            for planta in plantas:
                if str(planta["id"]) == usina_id:
                    self._cache_capacidades[usina_id] = planta["capacidade"]
                    return planta["capacidade"]
        except:
            pass
            
        return 100  # Valor padrão se não conseguir obter a capacidade

    def _extrair_valor_numerico(self, valor):
        """Extrai valor numérico de strings que podem conter unidades"""
        if isinstance(valor, (int, float)):
            return float(valor)
            
        if isinstance(valor, str):
            # Remover unidades (ex: " kW", " V", " °C")
            import re
            match = re.search(r'([-+]?\d*\.\d+|\d+)', valor)
            if match:
                return float(match.group(1))
                
        return 0

    def _verificar_tensoes(self, conteudo):
        """
        Verifica se as tensões de entrada estão dentro dos limites normais
        Retorna dict com status e valores
        """
        # Limites normais de tensão (ajustar conforme necessário)
        LIMITE_MINIMO = 100  # V
        LIMITE_MAXIMO = 1000  # V
        
        tensoes = {
            "fora_limites": False,
            "valores": {}
        }
        
        # Verificar tensões por fase (se disponíveis)
        for fase in ["A", "B", "C"]:
            chave_tensao = f"Tensao_Entrada_{fase}"
            valor_tensao = self._extrair_valor_numerico(conteudo.get(chave_tensao, 0))
            
            tensoes["valores"][fase] = valor_tensao
            
            if valor_tensao > 0 and (valor_tensao < LIMITE_MINIMO or valor_tensao > LIMITE_MAXIMO):
                tensoes["fora_limites"] = True
                
        return tensoes

    def _atualizar_tabela(self):
        self.tree.delete(*self.tree.get_children())
        alert_counts = {"SOBRETENSÃO": 0, "SUBTENSÃO": 0, "FREQUÊNCIA": 0, "TÉRMICO": 0, "OUTROS": 0}
        novos_alertas = []

        for alerta in sorted(self.alertas_ativos.values(), key=lambda x: x["horario"], reverse=True):
            chave = f"{alerta['usina']}_{alerta['rele']}_{alerta['horario']}"
            if chave not in self.alertas_notificados:
                novos_alertas.append(alerta)
                self.alertas_notificados.add(chave)

            alert_counts[alerta["tipo"]] += 1
            tags = (alerta["tipo"],)

            self.tree.insert("", "end", values=(
                alerta["usina"],
                f"{alerta['capacidade']} kWp",
                alerta["rele"],
                alerta["horario"],
                alerta["tipo"],
                alerta["parametros"]
            ), tags=tags)

        for alerta in novos_alertas:
            message = (
                f"Usina: {alerta['usina']}\n"
                f"Relé: {alerta['rele']}\n"
                f"Tipo: {alerta['tipo']}\n"
                f"Horário: {alerta['horario']}"
            )
            AlertPopup(self, message, alerta["tipo"])

        total = sum(alert_counts.values())
        count_text = f"Alertas: {total} (Sobre: {alert_counts['SOBRETENSÃO']}, Sub: {alert_counts['SUBTENSÃO']})"
        self.alert_count_var.set(count_text)

    def _atualizar_tabela_inversores(self):
        self.inverter_tree.delete(*self.inverter_tree.get_children())
        novos_alertas = []
        falhas = 0

        for inversor in sorted(self.inversores_ativos.values(), key=lambda x: x["horario"], reverse=True):
            if inversor["status"] != "FALHA":
                continue

            chave = f"{inversor['usina']}_{inversor['inversor']}_{inversor['horario']}"
            if chave not in self.alertas_inversores_notificados:
                novos_alertas.append(inversor)
                self.alertas_inversores_notificados.add(chave)

            tags = ("FALHA",)
            # Monta detalhes a partir dos indicadores (Status e Pac, se disponíveis)
            detalhes = []
            inds = inversor.get('indicadores', {}) if 'indicadores' in inversor else {}
            if isinstance(inds, dict):
                if 'status' in inds:
                    detalhes.append(f"Status: {inds['status']}")
                if 'pac' in inds:
                    detalhes.append(f"Pac: {inds['pac']}")
            texto_detalhes = " | ".join(detalhes) if detalhes else "Sem detalhes"


            self.inverter_tree.insert("", "end", values=(
                inversor["usina"],
                f"{inversor['capacidade']} kWp",
                inversor["inversor"],
                inversor["horario"],
                f"FALHA (Pac≤0 & Status≠1)",
                texto_detalhes
            ), tags=tags)

        self.inv_status_var.set(f"Inversores Falha: {falhas}")

        for inversor in novos_alertas:
            # Criar mensagem detalhada para popup
            # Mensagem detalhada baseada nos indicadores capturados (Status e Pac)
            mensagem_detalhes = []
            inds = inversor.get('indicadores', {})
            if isinstance(inds, dict):
                if 'status' in inds:
                    mensagem_detalhes.append(f"Status: {inds['status']}")
                if 'pac' in inds:
                    mensagem_detalhes.append(f"Pac: {inds['pac']}")

            mensagem = (
                f"Usina: {inversor['usina']}\n"
                f"Inversor: {inversor['inversor']}\n"
                f"Status: {inversor['status']}\n"
                f"Horário: {inversor['horario']}\n"
                + (f"Status (indicador): {inversor.get('indicadores', {}).get('status', 'N/A')}\n")
                + (f"Pac: {inversor.get('indicadores', {}).get('pac', 'N/A')}\n")
                + ("Indicadores:\n" + "\n".join(f"  • {d}" for d in mensagem_detalhes))
            )
            AlertPopup(self, mensagem, "INVERSOR")

    def _atualizar_tabela_sem_dados(self):
        """Atualiza a tabela da aba 'Sem Dados' com eventos de falta de dados.

        Cada registro em `self.sem_dados_ativos` possui as chaves:
            - usina: nome da usina
            - tipo: string indicando 'RELÉ' ou 'INVERSOR'
            - data: string de data formatada (DD/MM/YYYY)
            - ultima: datetime da última verificação sem dados
        A tabela mostra a última verificação para que o operador saiba quando
        ocorreu a última falha de comunicação.
        """
        self.no_data_tree.delete(*self.no_data_tree.get_children())
        # Ordena por última verificação (mais recente primeiro)
        for key, evento in sorted(self.sem_dados_ativos.items(), key=lambda kv: kv[1]['ultima'], reverse=True):
            self.no_data_tree.insert(
                "",
                "end",
                values=(
                    evento["usina"],
                    evento["tipo"],
                    evento["data"],
                    evento["ultima"].strftime("%d/%m/%Y %H:%M:%S")
                )
            )

    # Adicione estes métodos para organizar o código:
    def processar_alertas_reles(self, usina_id, nome_usina, capacidade, inicio_rele, agora):
        alertas = self.buscar_alertas_reles(usina_id, inicio_rele, agora)
        novos_alertas = {}
        
        for alerta in alertas:
            chave = f"{usina_id}_{alerta['rele_id']}_{alerta['tipo_alerta']}"
            if chave not in self.alertas_ativos:
                novos_alertas[chave] = {
                    "usina": nome_usina,
                    "capacidade": capacidade,
                    "rele": alerta['rele_id'],
                    "horario": alerta['ts_leitura'].strftime("%d/%m/%Y %H:%M:%S"),
                    "tipo": alerta['tipo_alerta'],
                    "parametros": alerta['parametros']
                }
        
        return novos_alertas

    def processar_inversores(self, usina_id, nome_usina, capacidade, inicio_inversor, agora):
        # Usa a nova lógica binária (Pac ≤ 0 e Status ≠ 1)
        falhas, tem_dados_inv = self.buscar_status_inversores(
            usina_id, inicio_inversor, agora
        )
        novos_inversores = {}
        
        if not tem_dados_inv:
            data_chave = agora.date().strftime("%Y-%m-%d")
            chave_sem = f"{usina_id}_{data_chave}_INV"
            if chave_sem in self.sem_dados_ativos:
                self.sem_dados_ativos[chave_sem]['ultima'] = agora
            else:
                self.sem_dados_ativos[chave_sem] = {
                    "usina": nome_usina,
                    "tipo": "INVERSOR",
                    "data": agora.date().strftime("%d/%m/%Y"),
                    "ultima": agora
                }
        
        for status in falhas:
            # Usa chave de inversor e usina (sem timestamp) para evitar registros repetidos
            chave = f"{usina_id}_{status['inversor_id']}"
            if chave not in self.inversores_ativos:
                novos_inversores[chave] = {
                    "usina": nome_usina,
                    "capacidade": capacidade,
                    "inversor": status['inversor_id'],
                    "horario": status['ts_leitura'].strftime("%d/%m/%Y %H:%M:%S"),
                    "status": status['status'],
                    "pontuacao": status.get('pontuacao', 0),
                    "indicadores": status.get('indicadores', {})
                }
        
        return novos_inversores

    def limpar_dados_antigos(self):
        agora = datetime.now()
        
        # Executa a limpeza no máximo uma vez por hora
        if self.ultima_limpeza and (agora - self.ultima_limpeza).total_seconds() < 3600:
            return
        
        logging.info("Executando limpeza de dados antigos...")
        
        # Remove alertas com mais de 24 horas
        chaves_para_remover = []
        for chave, alerta in self.alertas_ativos.items():
            try:
                horario_alerta = datetime.strptime(alerta["horario"], "%d/%m/%Y %H:%M:%S")
                if (agora - horario_alerta).total_seconds() > 86400:  # 24 horas
                    chaves_para_remover.append(chave)
            except ValueError:
                chaves_para_remover.append(chave)
        
        for chave in chaves_para_remover:
            del self.alertas_ativos[chave]
        
        # Remove inversores com mais de 24 horas
        chaves_para_remover = []
        for chave, inversor in self.inversores_ativos.items():
            try:
                horario_inversor = datetime.strptime(inversor["horario"], "%d/%m/%Y %H:%M:%S")
                if (agora - horario_inversor).total_seconds() > 86400:  # 24 horas
                    chaves_para_remover.append(chave)
            except ValueError:
                chaves_para_remover.append(chave)
        
        for chave in chaves_para_remover:
            del self.inversores_ativos[chave]
        
        # Remove registros sem dados com mais de 7 dias
        chaves_para_remover = []
        for chave, sem_dados in self.sem_dados_ativos.items():
            if (agora - sem_dados["ultima"]).total_seconds() > 604800:  # 7 dias
                chaves_para_remover.append(chave)
        
        for chave in chaves_para_remover:
            del self.sem_dados_ativos[chave]
        
        self.ultima_limpeza = agora
        logging.info(f"Limpeza concluída. {len(chaves_para_remover)} itens removidos.")

    def executar_varredura(self):
        self.limpar_dados_antigos()
        agora = datetime.now()

        # === VARREDURA DE RELÉS ===
        if self.ultima_varredura_rele is None or agora.date() != (self.ultima_varredura_rele.date() if self.ultima_varredura_rele else agora.date()):
            inicio_rele = agora.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            inicio_rele = self.ultima_varredura_rele

        msg_rele = f"Relés: {('00:00' if inicio_rele.hour == 0 and inicio_rele.minute == 0 else inicio_rele.strftime('%H:%M'))} até {agora.strftime('%H:%M')}"

        # === VARREDURA DE INVERSORES ===
        fazer_varredura_inversor = False
        if self.ultima_varredura_inversor is None or agora.date() != (self.ultima_varredura_inversor.date() if self.ultima_varredura_inversor else agora.date()):
            inicio_inversor = agora.replace(hour=0, minute=0, second=0, microsecond=0)
            fazer_varredura_inversor = True
        else:
            tempo_desde_ultima_inversor = agora - self.ultima_varredura_inversor
            if tempo_desde_ultima_inversor >= timedelta(minutes=35):
                inicio_inversor = self.ultima_varredura_inversor
                fazer_varredura_inversor = True
            else:
                inicio_inversor = self.ultima_varredura_inversor

        if fazer_varredura_inversor:
            inv_inicio_str = '06:30' if (self.ultima_varredura_inversor is None or agora.date() != (self.ultima_varredura_inversor.date() if self.ultima_varredura_inversor else agora.date())) else inicio_inversor.strftime('%H:%M')
            # Mensagem para varredura de inversores com critério binário
            msg_inv = f"Inversores: {inv_inicio_str} até {agora.strftime('%H:%M')} (critério: Pac ≤ 0 e Status ≠ 1)"
        else:
            proximo_inversor_em = timedelta(minutes=35) - (agora - self.ultima_varredura_inversor)
            minutos_restantes = int(proximo_inversor_em.total_seconds() // 60)
            segundos_restantes = int(proximo_inversor_em.total_seconds() % 60)
            msg_inv = f"Inversores: aguardando {minutos_restantes:02d}:{segundos_restantes:02d} para próxima varredura"

        mensagem = f"{msg_rele} | {msg_inv}"

        self.atualizar_status(f"Iniciando {mensagem}...")
        self.status_icon.config(fg="#FF9800")

        plantas = self.buscar_plantas()
        if not plantas:
            self.atualizar_status("Nenhuma planta encontrada")
            self.status_icon.config(fg="#dc3545")
            return

        total_alertas = 0
        total_falhas_inversores = 0
        novos_alertas_locais = {}
        novos_inversores_locais = {}

        for planta in plantas:
            usina_id = str(planta["id"])
            nome_usina = planta["nome"]
            capacidade = planta["capacidade"]

            self.atualizar_status(f"{mensagem} - Analisando {nome_usina}...")

            # Processa alertas de relés
            alertas_usina = self.processar_alertas_reles(usina_id, nome_usina, capacidade, inicio_rele, agora)
            novos_alertas_locais.update(alertas_usina)
            total_alertas += len(alertas_usina)

            # Processa inversores (se necessário)
            if fazer_varredura_inversor:
                # Usa a nova lógica de pontuação em vez de sequência consecutiva
                # Usa a nova lógica binária
                inversores_usina = self.processar_inversores(
                    usina_id, nome_usina, capacidade, inicio_inversor, agora
                )

                for inversor in inversores_usina.values():
                    if inversor["status"] == "FALHA":
                        total_falhas_inversores += 1

        # Atualiza dicionários e UI após coleta
        self.alertas_ativos.update(novos_alertas_locais)
        self.inversores_ativos.update(novos_inversores_locais)

        self._atualizar_tabela()
        self._atualizar_tabela_inversores()

        # Atualiza tabela de sem dados ao final de cada varredura
        self._atualizar_tabela_sem_dados()

        # Atualiza marcadores de última varredura
        self.ultima_varredura_rele = agora
        self.ultima_varredura = agora
        if fazer_varredura_inversor:
            self.ultima_varredura_inversor = agora

        status_msg = f"{mensagem} concluída. {total_alertas} alertas, {total_falhas_inversores} falhas em inversores"
        self.atualizar_status(status_msg)
        self.status_icon.config(fg="#4CAF50")

        # Atualiza o gráfico apenas quando a aba de estatísticas estiver selecionada
        if self.notebook.index("current") == 2:
            self._update_graph()

        self._iniciar_contagem_regressiva()

    # Adicione este novo método:
    def _executar_varredura_segura(self):
        try:
            self.executar_varredura()
        except Exception as e:
            logging.error(f"Erro durante varredura: {str(e)}")
            self.atualizar_status(f"Erro durante varredura: {str(e)}")
            self.status_icon.config(fg="#dc3545")

    def executar_varredura_thread(self):
        with self.thread_lock:
            if getattr(self, "_thread_varredura", None) and self._thread_varredura.is_alive():
                self.show_notification("Varredura já está em andamento", "warning")
                return

            self._thread_varredura = threading.Thread(target=self._executar_varredura_segura, daemon=True)
            self._thread_varredura.start()

    def _iniciar_contagem_regressiva(self):
        def contagem():
            # Intervalo de contagem regressiva de 10 minutos (600 segundos) entre varreduras para relés.
            for segundos_restantes in range(600, 0, -1):
                if not self.varredura_ativa:
                    break
                mins, segs = divmod(segundos_restantes, 60)
                self.contador_var.set(f"Próxima varredura em: {mins:02d}:{segs:02d}")
                time.sleep(1)

            if self.varredura_ativa:
                self.executar_varredura_thread()

        threading.Thread(target=contagem, daemon=True).start()

    def limpar_alertas(self):
        self.alertas_ativos.clear()
        self.inversores_ativos.clear()
        self.alertas_notificados.clear()
        self.alertas_inversores_notificados.clear()
        self.sem_dados_ativos.clear()
        self.tree.delete(*self.tree.get_children())
        self.inverter_tree.delete(*self.inverter_tree.get_children())
        self.no_data_tree.delete(*self.no_data_tree.get_children())
        self.alert_count_var.set("Alertas: 0")
        self.inv_status_var.set("Inversores Falha: 0")
        self.atualizar_status("Alertas e status de inversores limpos")

    def exportar_csv(self):
        if not self.alertas_ativos:
            messagebox.showinfo("Exportar", "Nenhum alerta para exportar")
            return

        from tkinter import filedialog
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Salvar relatório de relés"
        )

        if caminho:
            import csv
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Usina", "Capacidade (kWp)", "Relé", "Horário", "Tipo Alerta", "Parâmetros"])

                for alerta in sorted(self.alertas_ativos.values(),
                                    key=lambda x: x["horario"], reverse=True):
                    writer.writerow([
                        alerta["usina"],
                        alerta["capacidade"],
                        alerta["rele"],
                        alerta["horario"],
                        alerta["tipo"],
                        alerta["parametros"]
                    ])

            messagebox.showinfo("Exportar", f"Relatório salvo em:\n{caminho}")
            self.show_notification(f"Relatório exportado para {caminho}", "info")

    def exportar_inversores_csv(self):
        if not self.inversores_ativos:
            messagebox.showinfo("Exportar", "Nenhum dado de inversor para exportar")
            return

        from tkinter import filedialog
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Salvar relatório de inversores"
        )

        if caminho:
            import csv
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Usina", "Capacidade (kWp)", "Inversor", "Horário", "Status"])

                for inversor in sorted(self.inversores_ativos.values(),
                                      key=lambda x: x["horario"], reverse=True):
                    writer.writerow([
                        inversor["usina"],
                        inversor["capacidade"],
                        inversor["inversor"],
                        inversor["horario"],
                        inversor["status"]
                    ])

            messagebox.showinfo("Exportar", f"Relatório de inversores salvo em:\n{caminho}")
            self.show_notification(f"Relatório de inversores exportado para {caminho}", "info")

    def iniciar_monitoramento(self):
        self.varredura_ativa = True
        self.executar_varredura_thread()

    def parar_monitoramento(self):
        self.varredura_ativa = False
        self.atualizar_status("Monitoramento pausado")

if __name__ == "__main__":
    root = tk.Tk()
    app = RelayMonitor(root)
    root.mainloop()