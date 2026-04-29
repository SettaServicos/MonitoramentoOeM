from datetime import datetime
from email.utils import parsedate_to_datetime
from json import dumps
from logging import Logger
from time import sleep

from requests import post


class MSTeams:
    def __init__(self, webhook_url: str, enabled: bool = True, logger: Logger = None) -> None:
        self.webhook_url = webhook_url
        self.enabled = enabled
        self.logger = logger

    @property
    def is_enabled(self) -> bool:
        return self.enabled

    def post_card(self, title, text, severity="info", facts=None):
        if not self.enabled:
            return False

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": self._theme_color(severity),
            "title": title,
            "text": text,
        }
        if facts:
            payload["sections"] = [{"facts": [{"name": k, "value": v} for k, v in facts]}]

        max_tentativas = 3
        backoff_base = 2
        for tentativa in range(1, max_tentativas + 1):
            try:
                response = post(
                    self.webhook_url,
                    data=dumps(payload),
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if response.status_code == 429:
                    espera = self._retry_after_seconds(response)
                    if espera is not None:
                        espera = min(max(0, espera), 60)
                        if tentativa == max_tentativas:
                            self._log_warning("[TEAMS] Rate limit (429) excedeu tentativas.")
                            return False
                        sleep(espera)
                        continue
                response.raise_for_status()
                return True
            except Exception as exc:
                if tentativa == max_tentativas:
                    self._log_warning(f"[TEAMS] Falha ao enviar webhook: {exc}")
                    return False
                sleep(backoff_base * tentativa)
        return False

    @staticmethod
    def _theme_color(severity: str) -> str:
        colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
        return colors.get(severity, "0078D4")

    @staticmethod
    def _retry_after_seconds(response) -> int | None:
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

    def _log_warning(self, message: str) -> None:
        if self.logger:
            self.logger.warning(message)
