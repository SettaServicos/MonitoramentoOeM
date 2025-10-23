import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import csv
from datetime import datetime, timedelta
from threading import Event, Thread
from services.pv_operation import PVOperation
from win10toast import ToastNotifier
import os
import time
from ttkthemes import ThemedStyle
from tkinter import ttk
import tkinter as tk

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

class AlertaMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Alertas - Setta Serviços")
        self.root.geometry("1200x600")
        self.root.configure(bg=STYLE_CONFIG["bg"])
        self.alertas_ativos = {}
        self.monitoramento_ativo = Event()  # Adicione esta linha
        self.monitoramento_ativo.set()      # Inicia como ativo
        self.primeira_varredura_dia = True  # Adicionar esta linha para controlar a primeira varredura
        style = ThemedStyle(root)
        style.set_theme("arc")

        # Logotipo
        if os.path.exists(LOGO_PATH):
            img = Image.open(LOGO_PATH)
            img = img.resize((220, 80))
            self.logo_img = ImageTk.PhotoImage(img)
            logo_label = tk.Label(root, image=self.logo_img, bg="#f5f5f5")
            logo_label.pack(pady=10)

        # Frame principal
        main_frame = tk.Frame(root, bg=STYLE_CONFIG["bg"])
        main_frame.pack(expand=True, fill="both", padx=10, pady=5)

        # Tabela de alertas com estilo melhorado
        self.tree = ttk.Treeview(main_frame, columns=("Usina", "Capacidade", "Serial", "Horário", "Status", "Tipo"), 
                                show="headings", style="Custom.Treeview")
        
        # Configurar estilo
        style = ttk.Style()
        style.configure("Custom.Treeview", 
                       font=STYLE_CONFIG["font"],
                       rowheight=25,
                       bordercolor="#dee2e6",
                       lightcolor="#ffffff",
                       fieldbackground=STYLE_CONFIG["bg"])
        style.map("Custom.Treeview", 
                 background=[("selected", STYLE_CONFIG["highlight"])])

        # Configurar colunas
        col_widths = {
            "Usina": 250,    # Mais espaço para nomes longos
            "Capacidade": 80,  # Apenas números
            "Serial": 180,    # Espaço para serial completo
            "Horário": 120,   # Formato fixo
            "Status": 350     # Mensagens completas
        }
        for col, width in col_widths.items():
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")

        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Layout
        self.tree.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")

        # Frame de botões
        button_frame = tk.Frame(root, bg=STYLE_CONFIG["bg"])
        button_frame.pack(fill="x", padx=10, pady=5)

        # Botões com estilo consistente
        buttons = [
            ("Exportar Relatório", self.exportar_csv),
            ("Limpar Alertas", self.limpar_alertas),
            ("Verificar Seleção", self.marcar_verificado)
        ]
        for text, command in buttons:
            btn = ttk.Button(button_frame, text=text, command=command)
            btn.pack(side="left", padx=5, pady=2)

        # Frame da barra de status
        self.status_frame = tk.Frame(root, bg="#f0f0f0", height=24)
        self.status_frame.pack(fill="x", side="bottom", pady=(0,0))

        # Ícone de status (verde/vermelho/laranja)
        self.status_icon = tk.Label(self.status_frame, text="●", font=("Segoe UI", 12), bg="#f0f0f0", fg="#4CAF50")
        self.status_icon.pack(side="left", padx=(10,5))

        # Mensagem de status
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var,
                                    font=("Segoe UI", 9), bg="#f0f0f0", fg="#333333", anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)

        # Horário da última atualização
        self.last_update_var = tk.StringVar()
        tk.Label(self.status_frame, textvariable=self.last_update_var,
                font=("Segoe UI", 9), bg="#f0f0f0", fg="#666666").pack(side="right", padx=10)
        self.atualizar_status("Aplicacão iniciada. Aguardando primeira varredura...")

        self.toaster = ToastNotifier()
        self.iniciar_monitoramento()
        # Configurar tags para cores
        self.tree.tag_configure("POTÊNCIA ZERADA", background='#ffeeee')  # Vermelho suave
        self.tree.tag_configure("verificado", background='#f5fff5')       # Verde suave   

    
    def verificar_reset_diario(self):
        """Verifica se precisa resetar para nova varredura diária após as 6h"""
        agora = datetime.now()
        hoje = agora.date()
        
        # Só considera novo dia após as 6h da manhã
        if agora.hour >= 6:
            if not hasattr(self, '_ultimo_dia_verificado') or self._ultimo_dia_verificado != hoje:
                self.primeira_varredura_dia = True
                self._ultimo_dia_verificado = hoje
                print(f"Reset diário realizado às {agora.strftime('%H:%M')} - Nova varredura completa será feita")

    def marcar_verificado(self):
        selecionado = self.tree.focus()
        if not selecionado:
            messagebox.showwarning("Aviso", "Nenhum alerta selecionado.")
            return

        item = self.tree.item(selecionado)
        serial = item['values'][2]
        tipo = item['values'][5]  # Pega o tipo do alerta (coluna 5)
        chave = f"{serial}_{tipo}"

        if chave in self.alertas_ativos:
            del self.alertas_ativos[chave]
            self._atualizar_interface()  # Linha existente

            # ===== NOVO: Feedback visual =====
            self.tree.selection_set(selecionado)  # Mantém o item selecionado
            self.tree.item(selecionado, tags=('verificado',))  # Aplica tag
            self.tree.tag_configure('verificado', background='#e8f5e9')  # Cor verde claro
            self.root.after(2000, lambda: self.tree.selection_remove(selecionado))  # Remove destaque após 2s
            # ===== Fim do trecho novo =====

            self.atualizar_status(f"Alerta verificado: {serial} ({tipo})")
        else:
            messagebox.showerror("Erro", "Alerta não encontrado.")
           
    def atualizar_status(self, texto):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.status_var.set(f"{timestamp} {texto}")

    def atualizar_alerta(self, usina, capacidade, serial, tipo="POTÊNCIA ZERADA", horario_falha=None):
        agora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        chave = f"{serial}_{tipo}"
        
        horario = horario_falha if horario_falha else agora
        
        if chave not in self.alertas_ativos:
            self.alertas_ativos[chave] = {
                "usina": usina,
                "capacidade": capacidade,
                "serial": serial,
                "horario": horario,
                "status": "Primeira ocorrência detectada",
                "tipo": tipo
            }
            self.notificar(usina, capacidade, serial, tipo)
        else:
            self.alertas_ativos[chave]["status"] = f"Problema persistente desde {self.alertas_ativos[chave]['horario']}"
        self._atualizar_interface()

    def remover_alerta(self, serial):
        if serial in self.alertas_ativos:
            del self.alertas_ativos[serial]
            self._atualizar_interface()

    def _atualizar_interface(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Ordena por tipo (potência zerada primeiro)
        alertas_ordenados = sorted(self.alertas_ativos.values(), 
                                key=lambda x: x["tipo"] == "POTÊNCIA ZERADA", reverse=True)
        
        for alerta in alertas_ordenados:
            # Aplica a tag correspondente ao tipo de alerta
            self.tree.insert("", "end", 
                            values=(
                                alerta["usina"],
                                alerta["capacidade"],
                                alerta["serial"],
                                alerta["horario"],
                                alerta["status"]  # Remova alerta["tipo"]
                            ),
                            tags=(alerta["tipo"],))  # Esta linha é crucial para aplicar a cor

    def limpar_alertas(self):
        self.alertas_ativos.clear()
        self._atualizar_interface()
        self.atualizar_status("Todos os alertas foram removidos da tela.")

    def exportar_csv(self):
        if not self.alertas_ativos:
            messagebox.showinfo("Exportar", "Nenhum alerta para exportar.")
            return
        caminho = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if caminho:
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for alerta in self.alertas_ativos.values():
                    writer.writerow([
                        alerta["usina"],
                        alerta["capacidade"],
                        alerta["serial"],
                        alerta["horario"],
                        alerta["status"],
                        alerta["tipo"]
                    ])
            messagebox.showinfo("Exportar", f"Arquivo exportado para: {caminho}")
            self.atualizar_status("Arquivo exportado com sucesso.")

    def notificar(self, usina, capacidade, serial, tipo):
        # Mostra notificação APENAS para potência zerada
        if tipo == "POTÊNCIA ZERADA":
            self.toaster.show_toast(
                title="ALERTA - Potência Zerada",
                msg=f"""\
            Usina: {usina[:30]} ({capacidade} kWp)
            Inversor: {serial}
            Horário: {datetime.now().strftime('%H:%M:%S')}""",
                duration=8,
                threaded=True
            )
        # Offline não gera pop-up
    
    def executar_monitoramento(self, max_retries=3):
        # Mostrar estado de carregamento
        self.status_icon.config(fg="#FF9800")  # Laranja
        self.status_var.set("Varredura em andamento...")
        self.last_update_var.set(datetime.now().strftime("%H:%M:%S"))
        self.root.update()  # Forçar atualização da UI
        for attempt in range(max_retries):
            try:
                # Controle do tipo de varredura
                if self.primeira_varredura_dia:
                    self.atualizar_status("Iniciando PRIMEIRA varredura do dia (desde 6h)...")
                    full_day_check = True
                    self.primeira_varredura_dia = False
                else:
                    self.atualizar_status("Iniciando varredura rotineira (últimos 15 minutos)...")
                    full_day_check = False

                novos_alertas = 0
                
                with PVOperation() as pvo:
                    # Obtém lista de usinas
                    usinas = pvo.session.get(
                        f"{pvo.base_url}/plants", 
                        headers=pvo.headers
                    ).json()

                    alertas_atuais = set()

                    for usina in usinas:
                        usina_id = usina["id"]
                        potencias_zeradas, inversores_offline = pvo.buscar_potencia_instantanea(
                            usina_id, 
                            full_day_check
                        )

                        # Processa potências zeradas
                        for horario, serial in potencias_zeradas:
                            chave = f"{serial}_POTÊNCIA ZERADA"
                            alertas_atuais.add(chave)
                            
                            if chave not in self.alertas_ativos:
                                novos_alertas += 1
                                self.atualizar_alerta(
                                    usina["nome"],
                                    usina["capacidade"],
                                    serial,
                                    "POTÊNCIA ZERADA",
                                    horario.strftime("%d/%m/%Y %H:%M:%S")
                                )

                    # Remove alertas resolvidos
                    for chave in list(self.alertas_ativos.keys()):
                        if chave not in alertas_atuais:
                            del self.alertas_ativos[chave]

                    # Atualiza status
                    status_msg = (
                        f"Varredura {'completa' if full_day_check else 'parcial'} concluída. "
                        f"Novos alertas: {novos_alertas}. "
                        f"Total ativos: {len(self.alertas_ativos)}"
                    )
                    self.atualizar_status(status_msg)
                    self.status_icon.config(fg="#4CAF50")  # Verde
                    break

            except Exception as e:
                self.status_icon.config(fg="#F44336")  # Vermelho
                logging.error(f"Erro na varredura: {str(e)}")
                if attempt == max_retries - 1:
                    self.atualizar_status(f"Falha após {max_retries} tentativas")
                time.sleep(10)

    def reiniciar_varredura_diaria(self):
        """Reseta o flag de primeira varredura diariamente"""
        agora = datetime.now()
        if not hasattr(self, '_data_ultima_verificacao') or self._data_ultima_verificacao.date() < agora.date():
            self.primeira_varredura_dia = True
            self._data_ultima_verificacao = agora
            print("✅ Reset realizado para nova varredura diária")

    def iniciar_monitoramento(self):
        def ciclo():
            while self.monitoramento_ativo.is_set():
                self.verificar_reset_diario()  # Verifica reset diário
                self.executar_monitoramento()
                time.sleep(900)  # 15 minutos
        
        Thread(target=ciclo, daemon=True).start()

    def parar_monitoramento(self):
        self.monitoramento_ativo.clear()
        self.atualizar_status("Monitoramento pausado.")
        
if __name__ == "__main__":
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.geometry("400x220+600+300")
    splash.configure(bg="white")
    if os.path.exists(LOGO_PATH):
        img = Image.open(LOGO_PATH)
        img = img.resize((220, 80))
        logo_img = ImageTk.PhotoImage(img)
        tk.Label(splash, image=logo_img, bg="white").pack(pady=(40, 10))
    tk.Label(splash, text="Carregando sistema de monitoramento...", bg="white", font=("Segoe UI", 10)).pack()
    splash.after(2000, splash.destroy)
    splash.mainloop()
    root = tk.Tk()
    app = AlertaMonitor(root)
    root.mainloop()