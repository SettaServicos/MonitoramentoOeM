from os import environ
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path

from msal import ConfidentialClientApplication
from requests import Response, post


class OutlookMailError(Exception):
    pass


@dataclass(frozen=True)
class EmailAttachment:
    name: str
    content_bytes: bytes

    def to_dict(self) -> dict:
        return {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": self.name,
            "contentBytes": b64encode(self.content_bytes).decode("ascii"),
        }


@dataclass(frozen=True)
class EmailMessage:
    subject: str
    content: str
    to_recipient: str
    attachment: EmailAttachment

    def to_dict(self) -> dict:
        return {
            "Message": {
                "Subject": self.subject,
                "Body": {"ContentType": "html", "Content": self.content},
                "ToRecipients": [{"EmailAddress": {"Address": self.to_recipient}}],
                "Attachments": [self.attachment.to_dict()]
            }
        }


class MsalClient:
    def __init__(self) -> None:
        self._app = ConfidentialClientApplication(
            client_id=environ.get("client_id"),
            client_credential=environ.get("client_secret"),
            authority=environ.get("authority"),
        )
        self._scopes = [environ.get("scopes")]
        self._header = self._acquire_token_header()

    def _acquire_token_header(self) -> dict:
        result = self._app.acquire_token_silent(self._scopes, account=None)
        if not result:
            result = self._app.acquire_token_for_client(scopes=self._scopes)
        token = result.get("access_token")
        if not token:
            raise OutlookMailError(
                f"Falha ao obter token de autenticacao: {result.get('error')}"
            )
        return {"Authorization": f"Bearer {token}"}

    @property
    def header(self) -> dict:
        return self._header

    def refresh_header(self) -> dict:
        self._header = self._acquire_token_header()
        return self._header


class OutlookMailService:
    GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users"
    WEEKLY_REPORT_RECIPIENT = "arturguedes@settaenergia.com.br"

    def __init__(self) -> None:
        self._sender_id = environ.get("outlook_sender_id")
        self._msal_client = MsalClient()

    def send_weekly_report(self, report_path: Path, semana_txt: str) -> None:
        attachment = EmailAttachment(
            name=report_path.name,
            content_bytes=report_path.read_bytes(),
        )
        message = EmailMessage(
            subject=f"RELATÓRIO SEMANAL O&M - {semana_txt}",
            content=(
                "<html><body>"
                "<p>Segue em anexo o relatório semanal de monitoramento OeM.</p>"
                f"<p>Periodo: <strong>{semana_txt}</strong></p>"
                "</body></html>"
            ),
            to_recipient=self.WEEKLY_REPORT_RECIPIENT,
            attachment=attachment,
        )
        self._send_email(message)

    def _send_email(self, message: EmailMessage) -> None:
        endpoint = f"{self.GRAPH_USERS_URL}/{self._sender_id}/sendMail"
        response = post(
            endpoint,
            headers=self._msal_client.header,
            json=message.to_dict(),
            timeout=30,
        )
        if response.status_code == 401:
            response = post(
                endpoint,
                headers=self._msal_client.refresh_header(),
                json=message.to_dict(),
                timeout=30,
            )
        if response.ok:
            return
        self._raise_send_error(response)

    @staticmethod
    def _raise_send_error(response: Response) -> None:
        try:
            details = response.json()
        except ValueError:
            details = response.text
        raise OutlookMailError(
            f"Falha ao enviar email [{response.status_code}]: {details}"
        )
