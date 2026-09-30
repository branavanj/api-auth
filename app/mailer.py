import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

from app.config import get_settings

log = logging.getLogger(__name__)


class EmailSender(Protocol):
    def send(self, to: str, subject: str, body: str) -> None: ...


class SmtpEmailSender:
    def send(self, to: str, subject: str, body: str) -> None:
        settings = get_settings()
        msg = EmailMessage()
        msg["From"] = settings.email_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)

        smtp_cls = smtplib.SMTP_SSL if settings.smtp_security == "ssl" else smtplib.SMTP
        with smtp_cls(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_security == "starttls":
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password or "")
            smtp.send_message(msg)


def get_email_sender() -> EmailSender:
    return SmtpEmailSender()


def deliver(sender: EmailSender, to: str, subject: str, body: str) -> None:
    """Exécuté en tâche de fond : une panne SMTP est journalisée, jamais renvoyée au client."""
    try:
        sender.send(to, subject, body)
    except Exception:
        log.exception("Échec d'envoi d'email à %s", to)
