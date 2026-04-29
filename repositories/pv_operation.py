import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from time import sleep

from requests import Session
from requests.exceptions import ConnectionError, RequestException, Timeout

logger = logging.getLogger("RelayMonitorHeadless")


class PVOperation:
    """Cliente da API PVOperation com retry e verificação SSL configurável."""

    def __init__(self, email, password, base_url, verify=True):
        self.email = email
        self.password = password
        self.base_url = base_url
        self._verify = verify
        self.session = Session()
        self.session.verify = self._verify
        self.token = None
        self.headers = {}
        self.last_get_plants_timeout = False
        self.last_get_plants_error = False
        self._login()

    def _reset_session(self):
        try:
            self.session.close()
        except Exception:
            pass
        self.session = Session()
        self.session.verify = self._verify

    def _retry_after_seconds(self, response):
        retry_after = response.headers.get("Retry-After")
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
                sleep(backoff_base * tentativa)
                continue
            except (ConnectionError, RequestException) as e:
                logger.warning(
                    f"Erro de conexão em {contexto}: {e}. {conn_error_suffix}"
                )
                self._reset_session()
                if not self._login():
                    if tentativa == max_tentativas:
                        return None, False
                    sleep(backoff_base * tentativa)
                    continue
                if tentativa == max_tentativas:
                    return None, False
                sleep(backoff_base * tentativa)
                continue
            except Exception as e:
                logger.error(f"Erro em {contexto}: {e}")
                return None, False

            if resp.status_code == 401 and reauth_on_401:
                if not self.verificar_token():
                    return None, False
                sleep(1)
                continue

            if _should_retry(resp.status_code):
                if log_status:
                    logger.warning(
                        f"Status {resp.status_code} em {contexto} - tentativa {tentativa}/{max_tentativas}."
                    )
                if tentativa == max_tentativas:
                    return resp, False
                if resp.status_code == 429:
                    espera = self._retry_after_seconds(resp)
                    if espera is None:
                        espera = min(backoff_base ** tentativa, 10)
                else:
                    espera = backoff_base * tentativa
                sleep(espera)
                continue

            return resp, False

        return None, False

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

    def verificar_token(self) -> bool:
        logger.warning("Tentando renovar token...")
        ok = self._login()
        if not ok:
            logger.error("Não foi possível renovar o token.")
        return ok

    def get_plants(self):
        url = f"{self.base_url}/plants"
        self.last_get_plants_timeout = False
        self.last_get_plants_error = False
        response, timeout_flag = self._request_with_retry(
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

        if response is None:
            self.last_get_plants_timeout = bool(timeout_flag)
            self.last_get_plants_error = True
            return []

        if response.status_code == 200:
            return response.json() or []

        logger.error(f"Erro ao buscar plantas. Status: {response.status_code}")
        self.last_get_plants_error = True
        return []

    def post_day(self, endpoint: str, plant_id: int, date: datetime):
        payload = {"id": int(plant_id), "date": date.strftime("%Y-%m-%d")}
        url = f"{self.base_url}/{endpoint}"
        contexto = f"{endpoint} (usina {plant_id}, {date.date()})"
        response, timeout_flag = self._request_with_retry(
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
        if response is None:
            return None, timeout_flag
        if response.status_code == 200:
            return response.json(), False
        return None, False
