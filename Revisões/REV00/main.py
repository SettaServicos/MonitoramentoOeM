import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import csv
from datetime import datetime, timedelta
from threading import Event, Thread
from services import PVOperation
from win10toast import ToastNotifier
import os
import time
from ttkthemes import ThemedStyle
from tkinter import ttk
import tkinter as tk

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        # Implementação do tooltip
        pass

    def hide_tip(self, event=None):
        # Implementação para esconder
        pass

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
        col_widths = {"Usina": 200, "Capacidade": 100, "Serial": 150, "Horário": 150, "Status": 300, "Tipo": 120}
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
            ("Exportar CSV", self.exportar_csv),
            ("Limpar Alertas", self.limpar_alertas),
            ("Marcar como Verificado", self.marcar_verificado),
            ("Mostrar Todos", lambda: self._aplicar_filtro("TODOS")),
            ("Apenas Pac = 0", lambda: self._aplicar_filtro("POTÊNCIA ZERADA")),
            ("Apenas Offline", lambda: self._aplicar_filtro("OFFLINE"))
        ]

        for text, command in buttons:
            btn = ttk.Button(button_frame, text=text, command=command)
            btn.pack(side="left", padx=5, pady=2)

        # Barra de status melhorada
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(root, textvariable=self.status_var, 
                                 bg="#e9ecef", fg="#495057", 
                                 font=STYLE_CONFIG["font"], anchor="w", 
                                 padx=10, pady=5)
        self.status_bar.pack(fill="x", side="bottom")
        self.atualizar_status("Aplicacão iniciada. Aguardando primeira varredura...")

        self.toaster = ToastNotifier()
        self.iniciar_monitoramento()
        # Configurar tags para cores
        self.tree.tag_configure("POTÊNCIA ZERADA", background='#ffcccc')  # Vermelho claro
        self.tree.tag_configure("OFFLINE", background='#ccccff')          # Azul claro
        self.tree.tag_configure('verificado', background='#e8f5e9')       # Verde claro        

    def _aplicar_filtro(self, tipo):
        """Filtra os alertas exibidos na tabela conforme o tipo selecionado"""
        for row in self.tree.get_children():
            self.tree.delete(row)
            
        for alerta in self.alertas_ativos.values():
            if tipo == "TODOS" or alerta["tipo"] == tipo:
                self.tree.insert("", "end", values=(
                    alerta["usina"],
                    alerta["capacidade"],
                    alerta["serial"],
                    alerta["horario"],
                    alerta["status"],
                    alerta["tipo"]
                ))
        self.atualizar_status(f"Filtro aplicado: {tipo}")    

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

    def atualizar_alerta(self, usina, capacidade, serial, tipo="POTÊNCIA ZERADA"):
        agora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        chave = f"{serial}_{tipo}"  # Chave única por serial e tipo
        
        if chave not in self.alertas_ativos:
            self.alertas_ativos[chave] = {
                "usina": usina,
                "capacidade": capacidade,
                "serial": serial,
                "horario": agora,
                "status": "Primeira ocorrência detectada",
                "tipo": tipo
            }
            self.notificar(usina, capacidade, serial, tipo)
        else:
            horario_inicial = self.alertas_ativos[chave]["horario"]
            self.alertas_ativos[chave]["status"] = f"Problema persistente desde {horario_inicial}"
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
                                alerta["status"],
                                alerta["tipo"]
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
                writer.writerow(["Usina", "Capacidade (kWp)", "Serial", "Horário", "Status", "Tipo"])
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
                title=f"ALERTA CRÍTICO - Potência Zerada",
                msg=f"{usina} ({capacidade} kWp)\nInversor: {serial}",
                duration=10,
                threaded=True
            )
        # Offline não gera pop-up

    def tempo_offline(self, serial: str) -> timedelta:
        """Calcula há quanto tempo o inversor está offline"""
        # Implementar lógica de tracking de tempo
        return timedelta(minutes=0)  # Placeholder
    
    def executar_monitoramento(self, max_retries=3):
        for attempt in range(max_retries):
            try:
                self.atualizar_status(f"Iniciando varredura (tentativa {attempt + 1}/{max_retries})...")
                novos_alertas = 0
                
                with PVOperation() as pvo:
                    endpoint = f"{pvo.base_url}/plants"
                    resp = pvo.session.get(endpoint, headers=pvo.headers)
                    usinas = resp.json()
                    todos_os_alertas_atuais = set()

                    for usina in usinas:
                        usina_id = usina["id"]
                        usina_nome = usina["nome"]
                        capacidade = usina["capacidade"]
                        potencias_zeradas, inversores_offline = pvo.buscar_potencia_instantanea(usina_id)
                        
                        # 1. Processa TODAS as potências zeradas primeiro (prioridade máxima)
                        for horario, serial in potencias_zeradas:
                            chave = f"{serial}_POTÊNCIA ZERADA"
                            todos_os_alertas_atuais.add(chave)
                            if chave not in self.alertas_ativos:
                                novos_alertas += 1
                                print(f"⚠️ ALERTA PRIORITÁRIO: {serial} (Potência Zerada)")
                            self.atualizar_alerta(usina_nome, capacidade, serial, "POTÊNCIA ZERADA")

                        # 2. Processa offline APENAS se não tiver alerta de potência zerada
                        for serial in inversores_offline:
                            chave_offline = f"{serial}_OFFLINE"
                            chave_zerada = f"{serial}_POTÊNCIA ZERADA"
                            
                            if chave_zerada not in todos_os_alertas_atuais:
                                todos_os_alertas_atuais.add(chave_offline)
                                if chave_offline not in self.alertas_ativos:
                                    novos_alertas += 1
                                    print(f"⚠️ ALERTA SECUNDÁRIO: {serial} (Offline)")
                                self.atualizar_alerta(usina_nome, capacidade, serial, "OFFLINE")

                    # Remove alertas que não estão mais ativos
                    alertas_para_remover = [s for s in self.alertas_ativos if s not in todos_os_alertas_atuais]
                    for chave in alertas_para_remover:
                        if chave in self.alertas_ativos:
                            del self.alertas_ativos[chave]

                    total_potencia_zerada = sum(1 for a in self.alertas_ativos.values() if a["tipo"] == "POTÊNCIA ZERADA")
                    total_offline = sum(1 for a in self.alertas_ativos.values() if a["tipo"] == "OFFLINE")

                    mensagem = (f"Varredura de {len(usinas)} usinas concluída. "
                                f"{novos_alertas} novo(s) alerta(s), "
                                f"sendo {total_offline} Offline e {total_potencia_zerada} Potência zerada. "
                                f"Próxima em 15 minutos.")

                    print(mensagem)  # Para o terminal
                    self.atualizar_status(mensagem)  # Para a barra de status
                    break

            except Exception as e:
                if attempt == max_retries - 1:
                    self.atualizar_status(f"Falha após {max_retries} tentativas: {e}")
                else:
                    time.sleep(10)

    def iniciar_monitoramento(self):
        def ciclo():
            while self.monitoramento_ativo.is_set():  # Loop controlado
                self.executar_monitoramento()
                time.sleep(900)  # Intervalo de 15 minutos
        
        # Inicia a thread
        t = Thread(target=ciclo, daemon=True)
        t.start()

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