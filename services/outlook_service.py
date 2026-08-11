import logging
import os
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from requests.exceptions import ReadTimeout


WEEKLY_REPORT_RECIPIENT = "arturguedes@settaenergia.com.br"


class MsalAuthError(Exception):
    pass


class OutlookSendError(Exception):
    pass


def _env_required(*names: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip().strip('"').strip("'")
    raise MsalAuthError(f"Variavel de ambiente obrigatoria ausente: {' ou '.join(names)}")


def _parse_scopes(raw_scopes: str) -> list[str]:
    if "," in raw_scopes:
        scopes = [scope.strip() for scope in raw_scopes.split(",")]
    else:
        scopes = [scope.strip() for scope in raw_scopes.split()]
    scopes = [scope for scope in scopes if scope]
    if not scopes:
        raise MsalAuthError("Variavel de ambiente de scopes esta vazia.")
    return scopes


@dataclass(frozen=True)
class EmailAttachment:
    name: str
    content_bytes: bytes

    @classmethod
    def from_path(cls, path: Path) -> "EmailAttachment":
        return cls(name=path.name, content_bytes=path.read_bytes())

    def to_graph_payload(self) -> dict:
        return {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": self.name,
            "contentBytes": b64encode(self.content_bytes).decode("ascii"),
        }


@dataclass(frozen=True)
class EmailMessage:
    subject: str
    html_content: str
    to_recipients: Iterable[str]
    attachments: Iterable[EmailAttachment]

    def to_graph_payload(self) -> dict:
        return {
            "message": {
                "subject": self.subject,
                "body": {
                    "contentType": "HTML",
                    "content": self.html_content,
                },
                "toRecipients": [
                    {"emailAddress": {"address": recipient}}
                    for recipient in self.to_recipients
                ],
                "attachments": [
                    attachment.to_graph_payload()
                    for attachment in self.attachments
                ],
            },
            "saveToSentItems": True,
        }


class OutlookService:
    WEEKLY_REPORT_RECIPIENT = WEEKLY_REPORT_RECIPIENT

    def __init__(self):
        from msal import ConfidentialClientApplication

        self.client_id = _env_required("client_id", "MSAL_CLIENT_ID", "AZURE_CLIENT_ID")
        self.client_secret = _env_required("client_secret", "MSAL_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
        self.authority = _env_required("authority", "MSAL_AUTHORITY", "AZURE_AUTHORITY")
        self.scopes = _parse_scopes(_env_required("scopes", "MSAL_SCOPES", "GRAPH_SCOPES"))
        self.sender_id = _env_required("outlook_sender_id", "OUTLOOK_SENDER_ID")
        self.graph_base_url = "https://graph.microsoft.com/v1.0/users"
        self._app = ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority,
        )
        self._headers = {}
        self._acquire_token()

    def _acquire_token(self):
        result = self._app.acquire_token_silent(self.scopes, account=None)
        if not result:
            result = self._app.acquire_token_for_client(scopes=self.scopes)
        token = result.get("access_token")
        if not token:
            raise MsalAuthError(
                f"Falha ao obter token de autenticacao - {result.get('error')}: "
                f"{result.get('error_description')}"
            )
        self._headers = {"Authorization": f"Bearer {token}"}

    def send_email(self, email: EmailMessage) -> int:
        endpoint = f"{self.graph_base_url}/{self.sender_id}/sendMail"
        payload = email.to_graph_payload()

        for _ in range(3):
            try:
                response = requests.post(endpoint, headers=self._headers, json=payload, timeout=30)
                if response.status_code == 401:
                    self._acquire_token()
                    response = requests.post(endpoint, headers=self._headers, json=payload, timeout=30)
                if response.ok:
                    return response.status_code

                logging.error("[OUTLOOK] Falha Graph sendMail: %s", response.text)
                raise OutlookSendError(f"Falha ao enviar email [{response.status_code}]: {response.text}")
            except ReadTimeout:
                continue

        raise OutlookSendError("Falha ao enviar email apos 3 tentativas por timeout.")

    def send_weekly_report(self, report_path: Path, period_label: str) -> int:
        report_path = Path(report_path)
        if not report_path.is_file():
            raise OutlookSendError(f"Arquivo de relatorio nao encontrado: {report_path}")

        email = EmailMessage(
            subject=f"Relatorio semanal OeM - {period_label}",
            html_content=(
                "<p>Artur,</p>"
                f"<p>Segue em anexo o relatorio semanal de OeM referente ao periodo {period_label}.</p>"
                "<p>(e-mail gerado automaticamente, nao responda)</p>"
            ),
            to_recipients=[self.WEEKLY_REPORT_RECIPIENT],
            attachments=[EmailAttachment.from_path(report_path)],
        )
        return self.send_email(email)
