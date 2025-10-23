import logging
from datetime import datetime, timedelta
from requests import Session
import time
from functools import wraps

def retry(max_retries=3, delay=5):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result is not None:
                        return result
                except Exception as e:
                    logging.warning(f"Tentativa {attempt + 1} falhou: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(delay)
            return None
        return wrapper
    return decorator

class PVOperation:
    def __init__(self):
        logging.info("Iniciando conexão com PVOperation...")
        self.email, self.password = self.buscar_credenciais()
        self.session = Session()
        self.base_url = "https://apipv.pvoperation.com.br/api/v1"
        self.token = self._login_with_retry()
        if not self.token:
            raise Exception("Falha na autenticação após retentativas")
        self.headers = {"x-access-token": self.token}

    @retry(max_retries=3, delay=5)
    def _login_with_retry(self):
        return self.login(self.email, self.password)

    def _login_with_retry(self, max_retries=3, delay=5):
        for attempt in range(max_retries):
            try:
                token = self.login(self.email, self.password)
                if token:
                    return token
            except Exception as e:
                print(f"⚠️ Tentativa {attempt + 1} falhou: {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
        return None
    print("✅ Conexão autenticada com sucesso.\n")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.session.close()

    @staticmethod
    def buscar_credenciais():
        return "monitoramento@settaenergia.com.br", "$$Setta123"

    def login(self, email: str, password: str) -> str | None:
        print(f"➡️ Login com: {email}")
        json_data = {"username": email, "password": password}
        response = self.session.post(f"{self.base_url}/authenticate", json=json_data)

        if response.status_code != 200:
            logging.error("❌ Erro ao fazer login no PV Operation!")
            return None

        print("🔓 Login bem-sucedido.\n")
        return response.json().get("token")

    def buscar_inversor_id(self, usina_id: str, serial: str) -> str | None:
        print(f"🔎 Buscando ID do inversor {serial} na usina {usina_id}")
        endpoint = f"{self.base_url}/plant_devices"
        resp = self.session.get(endpoint, headers=self.headers, json={"id": int(usina_id)})

        if resp.status_code != 200:
            print("❌ Erro ao consultar dispositivos da usina.\n")
            return None

        inversores = resp.json()[0].get("plant_devices", [])
        for inv in inversores:
            if inv.get("device_esn") == serial:
                device_id = inv.get("device_id")
                print(f"✅ Inversor encontrado: ID {device_id}\n")
                return f"{usina_id}_{device_id}"

        print("❌ Inversor não encontrado.\n")
        return None

    def _make_request_with_retry(self, method, endpoint, max_retries=3, delay=2, **kwargs):
        kwargs['timeout'] = 10  # Segundos
        for attempt in range(max_retries):
            try:
                response = method(endpoint, headers=self.headers, **kwargs)
                if response.status_code == 200:
                    return response
                print(f"⚠️ Tentativa {attempt + 1} falhou. Status: {response.status_code}")
            except Exception as e:
                print(f"⚠️ Tentativa {attempt + 1} falhou: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
        return None
        
    def buscar_potencia_instantanea(self, usina_id: str, full_day_check=False) -> tuple[list, list]:
        """Retorna:
        - Lista de tuplas (horario, serial) para inversores com potência zerada
        - Lista de serials para inversores offline
        
        Parâmetros:
            full_day_check: Se True, verifica desde 6h da manhã até agora
        """
        print(f"⚡ Buscando potência para usina {usina_id} ({'desde 6h' if full_day_check else 'últimos 15 min'})")
        
        # 1. Define o período de análise
        agora = datetime.now()
        if full_day_check:
            # Começa às 6h do dia atual (ou do dia anterior se for antes das 6h)
            inicio_periodo = agora.replace(hour=6, minute=0, second=0, microsecond=0)
            if agora.hour < 6:
                inicio_periodo -= timedelta(days=1)
        else:
            inicio_periodo = agora - timedelta(minutes=15)
        
        # 2. Faz a requisição com retry
        endpoint = f"{self.base_url}/day_inverter"
        response = self._make_request_with_retry(
            self.session.post, 
            endpoint, 
            json={"id": usina_id},
            timeout=15
        )
        
        if not response:
            return [], []

        # 3. Processa os dados
        try:
            dados = response.json()
            potencia_zerada = []
            seriais_vistos = set()
            seriais_com_dados = set()

            for registro in dados:
                conteudo = registro.get("conteudojson", {})
                serial = conteudo.get("Inversor")
                if not serial:
                    continue

                seriais_vistos.add(serial)
                
                try:
                    ts_leitura = datetime.strptime(conteudo.get("tsleitura"), "%Y-%m-%d %H:%M:%S")
                    pac = float(conteudo.get("Pac", 1))
                except (ValueError, TypeError):
                    continue

                # Verifica se está no período de interesse
                if inicio_periodo <= ts_leitura <= agora:
                    seriais_com_dados.add(serial)
                    if pac <= 0:  # Potência zerada
                        potencia_zerada.append((ts_leitura, serial))

            # Inversores offline são os que não tiveram dados no período
            inversores_offline = list(seriais_vistos - seriais_com_dados)
            
            return potencia_zerada, inversores_offline

        except Exception as e:
            logging.error(f"Erro ao processar dados: {str(e)}")
            return [], []
        
    def verificar_status_inversor(self, api_key: str) -> str:
        """Retorna 'online', 'offline' ou 'erro' com base nos dados do endpoint /day_inverter
        Parâmetros:
            api_key: string no formato "usina_id_inversor_id"
        
        Lógica:
            - Online: Inversor com dados recentes (últimos 20 minutos) e Pac > 0
            - Offline: Inversor sem dados recentes ou Pac consistentemente zerado
            - Erro: Quando ocorre falha na requisição ou processamento
        """
        usina_id, inversor_id = api_key.split("_")
        potencias_zeradas, _ = self.buscar_potencia_instantanea(usina_id)
        for _, serial in potencias_zeradas:
            if serial == self._obter_serial_por_id(usina_id, inversor_id):
                return "potencia_zerada"  # ⚠️ Status dedicado        
        try:
            # Primeiro obtemos o serial do inversor
            serial = self._obter_serial_por_id(usina_id, inversor_id)
            if not serial:
                return "erro"
            
            # Obtém os dados de potência instantânea
            potencias_zeradas, inversores_offline = self.buscar_potencia_instantanea(usina_id)
            
            # Verifica se o inversor está na lista de offline
            if serial in inversores_offline:
                return "offline"
                
            # Verifica se há potência zerada para este inversor
            for horario, serial_pot in potencias_zeradas:
                if serial_pot == serial:
                    # Se há registro de potência zerada recente
                    return "offline"
                    
            # Se passou por todas as verificações
            return "online"
            
        except Exception as e:
            logging.error(f"Erro ao verificar status do inversor {api_key}: {str(e)}")
            return "erro"

    def _obter_serial_por_id(self, usina_id: str, inversor_id: str) -> str | None:
        """Obtém o número de série do inversor com base no ID"""
        endpoint = f"{self.base_url}/plant_devices"
        resp = self.session.get(endpoint, headers=self.headers, json={"id": int(usina_id)})
        
        if resp.status_code != 200:
            return None
            
        inversores = resp.json()[0].get("plant_devices", [])
        for inv in inversores:
            if str(inv.get("device_id")) == inversor_id:
                return inv.get("device_esn")
        return None
    
    def buscar_geracao(self, api_key: str, dia_pesq: datetime) -> float:
        usina_id, inversor_id = api_key.split("_")
        print(f"📊 Buscando geração do dia {dia_pesq.date()} para usina {usina_id}, inversor {inversor_id}")
        endpoint = f"{self.base_url}/month_energy"
        resp = self.session.post(endpoint, headers=self.headers, json={"id": int(usina_id)})

        if resp.status_code != 200:
            print("❌ Erro ao consultar geração mensal.")
            return -1

        for d in resp.json():
            if d.get("idinversor") != int(inversor_id):
                continue
            if d.get("dataleitura_new") != dia_pesq.strftime("%Y-%m-%d %H:%M:%S"):
                continue
            print(f"✅ Geração encontrada: {d.get('eday')} kWh\n")
            return float(d.get("eday"))

        print("⚠️ Nenhum dado correspondente encontrado.\n")
        return -1

    def buscar_potencia(self, api_key: str, dia_pesq: datetime) -> dict:
        usina_id, inversor_id = api_key.split("_")
        print(f"⚡ Buscando potência por minuto para usina {usina_id}, inversor {inversor_id}, dia {dia_pesq.date()}")
        endpoint = f"{self.base_url}/usinas/getgraficodia"
        params = {
            "idinversor": int(inversor_id),
            "idusina": int(usina_id),
            "date": dia_pesq.strftime("%d/%m/%Y")
        }

        resp = self.session.get(endpoint, headers=self.headers, params=params)
        horarios = {}

        if not resp.ok:
            print("❌ Erro ao consultar potência por minuto.")
            return horarios

        dados = resp.json().get("graficodia", [])
        inicio = False

        for d in dados:
            if float(d.get("energiapormin")) <= 0 and not inicio:
                continue
            inicio = True
            horario = datetime(
                int(d.get("ano")), int(d.get("mes")), int(d.get("dia")),
                int(d.get("hora")), int(d.get("minuto"))
            )
            horarios[horario] = round(float(d.get("energiapormin")), 2)

        print(f"✅ Total de registros: {len(horarios)}\n")
        return horarios

    def buscar_irradiacao(self, api_key: str, dia_pesq: datetime) -> float:
        usina_id, inversor_id = api_key.split("_")
        print(f"🔆 Buscando irradiância para usina {usina_id}, inversor {inversor_id}, dia {dia_pesq.date()}")
        endpoint = f"{self.base_url}/usinas/getgraficodia"
        params = {
            "idinversor": int(inversor_id),
            "idusina": int(usina_id),
            "date": dia_pesq.strftime("%d/%m/%Y")
        }

        resp = self.session.get(endpoint, headers=self.headers, params=params)
        if not resp.ok:
            print("❌ Erro ao consultar irradiância.")
            return -1

        dados = resp.json().get("graficoIrradiancia", [])
        horario_anterior = 0
        irrad_total = 0

        for d in dados:
            if float(d.get("irradianciapormin")) <= 0:
                continue
            hora = int(d.get("hora"))
            minuto = int(d.get("minuto"))
            horario_atual = hora + round(minuto/60, 8)
            irrad_total += (horario_atual - horario_anterior) * float(d.get("irradianciapormin"))
            horario_anterior = horario_atual

        print(f"✅ Irradiação total estimada: {irrad_total:.2f} Wh/m²\n")
        return round(irrad_total, 2)

        print("✅ Verificação finalizada.\n")