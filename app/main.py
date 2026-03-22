import asyncio
import datetime as dt
import hashlib
import hmac
import io
import logging
import os
import secrets
import smtplib
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TypedDict, cast
from urllib.parse import urlencode, urlparse

import qrcode
import tornado.escape
import tornado.httpclient
import tornado.ioloop
import tornado.web
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)
from pymongo.errors import DuplicateKeyError
from tornado.concurrent import Future

from .in_memory_db import Document, InMemoryClient, InMemoryCollection, InMemoryDatabase

Database = AsyncIOMotorDatabase[Document] | InMemoryDatabase
Collection = AsyncIOMotorCollection[Document] | InMemoryCollection
logger = logging.getLogger("unseen")


def utcnow() -> dt.datetime:
    """Timezone-aware UTC now."""
    return dt.datetime.now(dt.timezone.utc)


def compact_string(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


class SessionData(TypedDict, total=False):
    role: str
    user_id: str
    email: str


class Settings(BaseSettings):
    """Application configuration loaded from env/.env with optional YAML fallback."""

    app_base_url: str = "http://localhost:8888"
    port: int = 8888
    use_in_memory_db: bool = False
    mongo_url: Optional[str] = None
    users_collection: str = "unseen_users"
    admin_email: EmailStr
    admin_password: str
    cookie_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[EmailStr] = None
    smtp_use_tls: bool = True
    log_level: str = "INFO"
    recaptcha_site_key: Optional[str] = Field(
        default=None,
    )
    recaptcha_secret_key: Optional[str] = Field(
        default=None,
    )
    recaptcha_expected_action: str = "registration_submit"
    recaptcha_min_score: float = 0.5
    recaptcha_timeout_sec: int = 5

    model_config = SettingsConfigDict(
        env_prefix="UNSEEN_",
        env_file=".env",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_source = YamlConfigSettingsSource(settings_cls, yaml_file=Path(os.environ.get("UNSEEN_CONFIG", "config.yaml")))
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            yaml_source,
            file_secret_settings,
        )

    @field_validator("smtp_from", mode="before")
    @classmethod
    def normalize_optional_smtp_from(cls, value: Any) -> Any:
        return compact_string(value)

    @model_validator(mode="after")
    def validate_database_choice(self) -> "Settings":
        if not self.use_in_memory_db and not self.mongo_url:
            raise ValueError("mongo_url is required unless use_in_memory_db is true.")
        self.log_level = str(self.log_level).strip().upper()
        if self.log_level not in logging.getLevelNamesMapping():
            raise ValueError(f"Unsupported log_level: {self.log_level}")
        self.recaptcha_site_key = compact_string(self.recaptcha_site_key)
        self.recaptcha_secret_key = compact_string(self.recaptcha_secret_key)
        self.recaptcha_expected_action = compact_string(self.recaptcha_expected_action) or "registration_submit"
        if not (0 <= self.recaptcha_min_score <= 1):
            raise ValueError("recaptcha_min_score must be between 0 and 1.")
        if self.recaptcha_timeout_sec <= 0 or self.recaptcha_timeout_sec > 30:
            raise ValueError("recaptcha_timeout_sec must be between 1 and 30.")
        return self

    @property
    def recaptcha_enabled(self) -> bool:
        return bool(self.recaptcha_site_key and self.recaptcha_secret_key)

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_from)

    @property
    def smtp_uses_defaults(self) -> bool:
        return (
            self.smtp_configured
            and self.smtp_host == "localhost"
            and self.smtp_port == 587
            and not self.smtp_user
            and not self.smtp_password
        )


def load_settings() -> Settings:
    return Settings.model_validate({})


if TYPE_CHECKING:
    _settings_example = Settings(
        mongo_url="mongodb://example",
        admin_email="admin@example.com",
        admin_password="changeme",
    )


class RegistrationForm(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    confirm_email: EmailStr
    phone: str
    password: str
    password_confirm: str
    role: str
    level: str
    want_partner: bool = False
    partner_name: Optional[str] = None
    partner_contact: Optional[str] = None
    special_conditions: Optional[str] = None
    accept_rules: bool
    consent_data: bool
    verification_code: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if self.email.lower() != self.confirm_email.lower():
            raise ValueError("Emails must match.")
        if self.password != self.password_confirm:
            raise ValueError("Passwords must match.")
        if self.role not in {"leader", "follower"}:
            raise ValueError("Role must be leader or follower.")
        if self.level not in {"beginner", "improver", "intermediate", "advanced"}:
            raise ValueError("Invalid level.")
        if self.want_partner and not (self.partner_name and self.partner_contact):
            raise ValueError("Partner name and contact are required when opting to register with a partner.")
        if not self.accept_rules or not self.consent_data:
            raise ValueError("Consent and rules must be accepted.")


class RegistrationRecord(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    email_lower: str
    phone: str
    password_hash: str
    role: str
    level: str
    want_partner: bool = False
    partner_name: Optional[str] = None
    partner_contact: Optional[str] = None
    special_conditions: Optional[str] = None
    accept_rules: bool = True
    consent_data: bool = True
    email_proof_sent_at: Optional[dt.datetime] = None
    email_verification_code: Optional[str] = None
    email_verification_expires_at: Optional[dt.datetime] = None
    email_verification_attempts: int = 0
    email_verification_last_sent_at: Optional[dt.datetime] = None
    email_verified_at: Optional[dt.datetime] = None
    application_pending_email_sent_at: Optional[dt.datetime] = None
    application_confirmed_at: Optional[dt.datetime] = None
    application_confirmed_by: Optional[str] = None
    application_confirmation_email_sent_at: Optional[dt.datetime] = None
    payment_confirmed_at: Optional[dt.datetime] = None
    payment_confirmed_by: Optional[str] = None
    admin_comment: Optional[str] = None
    assigned_price: Optional[str] = None
    payment_link: Optional[str] = None
    cancelled_at: Optional[dt.datetime] = None
    cancelled_by: Optional[str] = None
    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, salt, stored = encoded.split("$", 2)
    except ValueError:
        return False
    if prefix != "pbkdf2":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return hmac.compare_digest(stored, digest.hex())


def check_admin_password(settings: Settings, password: str) -> bool:
    if settings.admin_password.startswith("pbkdf2$"):
        return verify_password(password, settings.admin_password)
    return hmac.compare_digest(settings.admin_password, password)


@dataclass
class EmailAttachment:
    filename: str
    data: bytes
    maintype: str
    subtype: str
    content_id: Optional[str] = None
    inline: bool = False


def send_email(
    settings: Settings,
    to_email: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    attachments: Optional[list[EmailAttachment]] = None,
) -> bool:
    smtp_from = compact_string(settings.smtp_from)
    if not smtp_from:
        attachment_names = [attachment.filename for attachment in attachments or []]
        logger.info(
            "smtp_from is unset. Logging email instead of sending. to=%s subject=%s attachments=%s\n%s",
            to_email,
            subject,
            attachment_names,
            body,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"UNSEEN <{smtp_from}>"
    msg["To"] = to_email
    msg.set_content(body)
    html_part: Optional[EmailMessage] = None
    if html_body:
        msg.add_alternative(html_body, subtype="html")
        html_part = cast(Optional[EmailMessage], msg.get_body(preferencelist=("html",)))
    for attachment in attachments or []:
        if attachment.inline and attachment.content_id and html_part is not None:
            html_part.add_related(
                attachment.data,
                maintype=attachment.maintype,
                subtype=attachment.subtype,
                cid=f"<{attachment.content_id}>",
                filename=attachment.filename,
                disposition="inline",
            )
        else:
            msg.add_attachment(
                attachment.data,
                maintype=attachment.maintype,
                subtype=attachment.subtype,
                filename=attachment.filename,
            )

    smtp_host = compact_string(settings.smtp_host)
    if not smtp_host:
        logger.warning(
            "smtp_from is set but smtp_host is empty. Skipping email to %s with subject %s.",
            to_email,
            subject,
        )
        return False

    try:
        if settings.smtp_use_tls:
            with smtplib.SMTP(smtp_host, settings.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                if settings.smtp_user and settings.smtp_password:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, settings.smtp_port, timeout=10) as smtp:
                if settings.smtp_user and settings.smtp_password:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
        logger.info("Sent email to %s with subject %s.", to_email, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s with subject %s.", to_email, subject)
        return False


def generate_verification_code() -> str:
    return secrets.token_urlsafe(6).replace("-", "")[:8].upper()


def make_payment_qr_png(url: str) -> bytes:
    qr = qrcode.QRCode(border=4, box_size=8)
    qr.add_data(url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


EMAIL_VERIFICATION_EXPIRY = dt.timedelta(hours=6)
VERIFICATION_ATTEMPT_LIMIT = 5
VERIFICATION_RESEND_COOLDOWN = dt.timedelta(minutes=5)


def verification_link(settings: Settings, email: str, code: str) -> str:
    return f"{settings.app_base_url.rstrip('/')}/verify?code={code}&email={email}"


def send_verification_email(settings: Settings, email: str, code: str) -> None:
    send_email(
        settings,
        to_email=email,
        subject="Verify your email for UNSEEN",
        body=(
            "Hi,\n\n"
            "Please verify your email to complete your application for UNSEEN.\n\n"
            f"Verification code: {code}\n"
            f"Or click: {verification_link(settings, email, code)}\n\n"
            "This code expires in 6 hours.\n\n"
            "If you did not register, you can ignore this email."
        ),
    )


def send_pending_review_email(settings: Settings, email: str, first_name: str) -> None:
    portal_link = f"{settings.app_base_url.rstrip('/')}/portal"
    send_email(
        settings,
        to_email=email,
        subject="Your UNSEEN application is under review",
        body=(
            f"Hi {first_name or 'there'},\n\n"
            "Your email is verified and we have received your application for UNSEEN.\n"
            "Your application is not confirmed yet.\n\n"
            "We background-check applications for safety and balance. We will try to maximize openness and inclusivity, "
            "but we may still reject an application for any reason, with or without explanation.\n\n"
            "You can review your status in the portal:\n"
            f"{portal_link}\n"
        ),
    )


def send_admin_registration_email(settings: Settings, record: RegistrationRecord) -> None:
    admin_link = f"{settings.app_base_url.rstrip('/')}/admin"
    partner_line = "Yes" if record.want_partner else "No"
    send_email(
        settings,
        to_email=str(settings.admin_email),
        subject="New UNSEEN application",
        body=(
            "Hello,\n\n"
            "A new application was submitted for UNSEEN.\n\n"
            f"Name: {record.first_name} {record.last_name}\n"
            f"Email: {record.email}\n"
            f"Phone: {record.phone}\n"
            f"Role/Level: {record.role.title()} / {record.level.title()}\n"
            f"Registering with partner: {partner_line}\n"
            f"Partner name: {record.partner_name or '-'}\n"
            f"Partner contact: {record.partner_contact or '-'}\n"
            f"Special conditions: {record.special_conditions or '-'}\n\n"
            f"View in admin: {admin_link}"
        ),
    )


def send_confirmation_email(
    settings: Settings,
    email: str,
    first_name: str,
    assigned_price: Optional[str],
    payment_link: Optional[str],
) -> bool:
    portal_link = f"{settings.app_base_url.rstrip('/')}/portal"
    payment_line = (
        f"Payment link: {payment_link}\n"
        "A QR code for this payment link is attached to this email.\n\n"
        if payment_link
        else "We will send your payment link separately.\n\n"
    )
    price_line = f"Assigned price: {assigned_price}\n" if assigned_price else ""
    attachments: list[EmailAttachment] = []
    html_payment_line = "<p>We will send your payment link separately.</p>"
    if payment_link:
        attachments.append(
            EmailAttachment(
                filename="payment-link-qr.png",
                data=make_payment_qr_png(payment_link),
                maintype="image",
                subtype="png",
                content_id="payment-link-qr",
                inline=True,
            )
        )
        html_payment_line = (
            f'<p><strong>Payment link:</strong> <a href="{tornado.escape.xhtml_escape(payment_link)}">'
            f'{tornado.escape.xhtml_escape(payment_link)}</a></p>'
            '<p>A QR code for this payment link is included below.</p>'
            '<p><img src="cid:payment-link-qr" alt="QR code for the payment link" style="max-width:320px; height:auto;"></p>'
        )
    return send_email(
        settings,
        to_email=email,
        subject="Your UNSEEN application was accepted",
        body=(
            f"Hi {first_name or 'there'},\n\n"
            "Your application for UNSEEN was accepted.\n"
            "Your place is awaiting payment confirmation.\n"
            "Please complete the payment using the instructions below.\n\n"
            f"{price_line}"
            f"{payment_line}"
            "Portal:\n"
            f"{portal_link}\n\n"
            "If you have questions, reply to this email."
        ),
        html_body=(
            f"<p>Hi {tornado.escape.xhtml_escape(first_name or 'there')},</p>"
            "<p>Your application for UNSEEN was accepted.</p>"
            "<p>Your place is awaiting payment confirmation.</p>"
            "<p>Please complete the payment using the instructions below.</p>"
            f"{f'<p><strong>Assigned price:</strong> {tornado.escape.xhtml_escape(assigned_price)}</p>' if assigned_price else ''}"
            f"{html_payment_line}"
            f'<p><strong>Portal:</strong> <a href="{tornado.escape.xhtml_escape(portal_link)}">{tornado.escape.xhtml_escape(portal_link)}</a></p>'
            "<p>If you have questions, reply to this email.</p>"
        ),
        attachments=attachments,
    )


async def verify_recaptcha_token(settings: Settings, token: Optional[str], remote_ip: str) -> bool:
    if not settings.recaptcha_enabled:
        return True

    recaptcha_token = compact_string(token)
    if not recaptcha_token or not settings.recaptcha_secret_key:
        logger.warning("reCAPTCHA token missing or secret unset for ip=%s.", remote_ip)
        return False

    request = tornado.httpclient.HTTPRequest(
        url="https://www.google.com/recaptcha/api/siteverify",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urlencode(
            {
                "secret": settings.recaptcha_secret_key,
                "response": recaptcha_token,
                "remoteip": remote_ip,
            }
        ),
        request_timeout=float(settings.recaptcha_timeout_sec),
    )
    try:
        response = await tornado.httpclient.AsyncHTTPClient().fetch(request, raise_error=False)
    except Exception:
        logger.exception("reCAPTCHA verification request failed for ip=%s.", remote_ip)
        return False

    if response.code != 200:
        logger.warning("reCAPTCHA verification returned status %s for ip=%s.", response.code, remote_ip)
        return False

    try:
        payload = tornado.escape.json_decode(response.body or b"{}")
    except Exception:
        logger.warning("reCAPTCHA verification returned invalid JSON for ip=%s.", remote_ip)
        return False
    if not isinstance(payload, dict):
        logger.warning("reCAPTCHA verification returned non-object payload for ip=%s.", remote_ip)
        return False
    if not bool(payload.get("success")):
        logger.info("reCAPTCHA rejected request for ip=%s.", remote_ip)
        return False

    action = str(payload.get("action") or "")
    if action != settings.recaptcha_expected_action:
        logger.warning(
            "reCAPTCHA action mismatch for ip=%s: got=%s expected=%s.",
            remote_ip,
            action,
            settings.recaptcha_expected_action,
        )
        return False

    try:
        score = float(payload.get("score"))
    except (TypeError, ValueError):
        score = 0.0
    if score < settings.recaptcha_min_score:
        logger.info(
            "reCAPTCHA score too low for ip=%s: score=%.3f threshold=%.3f.",
            remote_ip,
            score,
            settings.recaptcha_min_score,
        )
        return False
    logger.debug("reCAPTCHA accepted for ip=%s with score=%.3f.", remote_ip, score)
    return True


class BaseHandler(tornado.web.RequestHandler):
    @property
    def local_tz(self) -> dt.tzinfo:
        tz = dt.datetime.now().astimezone().tzinfo
        return tz or dt.timezone.utc

    @property
    def cfg(self) -> Settings:
        return cast(Settings, self.settings["app_settings"])

    @property
    def db(self) -> Database:
        return cast(Database, self.settings["db"])

    def get_current_user(self) -> Optional[SessionData]:
        raw = self.get_secure_cookie("session")
        if not raw:
            return None
        try:
            return cast(SessionData, tornado.escape.json_decode(raw))
        except Exception:
            logger.warning("Invalid session cookie encountered from ip=%s.", self.request.remote_ip)
            return None

    @property
    def base_path(self) -> str:
        base = cast(str, self.settings.get("base_path", ""))
        return "" if base == "/" else base

    def _with_base(self, url: str) -> str:
        base = self.base_path
        if not base:
            return url
        if url.startswith(("http://", "https://")):
            return url
        if url.startswith(base + "/") or url == base:
            return url
        if url.startswith("/"):
            return f"{base}{url}"
        return f"{base}/{url}"

    def redirect(self, url: str, permanent: bool = False, status: Optional[int] = None) -> None:
        super().redirect(self._with_base(url), permanent=permanent, status=status)

    def reverse_url(self, name: str, *args: Any) -> str:
        raw = super().reverse_url(name, *args)
        return self._with_base(raw)

    def render(self, template_name: str, **kwargs: Any) -> Future[None]:
        kwargs.setdefault("fmt_ts", self.format_ts)
        kwargs.setdefault("base_path", self.base_path)
        return super().render(template_name, **kwargs)

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        if status_code == 404:
            self.render("templates/error.html", title="Not found", message="Page not found.")
            return
        if status_code >= 500:
            logger.exception("Unhandled error %s on %s %s.", status_code, self.request.method, self.request.uri)
        elif status_code >= 400:
            logger.warning("HTTP %s on %s %s.", status_code, self.request.method, self.request.uri)
        super().write_error(status_code, **kwargs)

    def format_ts(self, value: Any) -> str:
        """Format a datetime in the server's local timezone without fractional seconds."""
        if not isinstance(value, dt.datetime):
            return ""
        dt_obj = value
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
        local_dt = dt_obj.astimezone(self.local_tz).replace(microsecond=0)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")


class LandingHandler(BaseHandler):
    async def get(self) -> None:
        self.render(
            "unseen.html",
            login_url=self.reverse_url("login"),
            register_url=self.reverse_url("register"),
        )


class HowToGetThereHandler(BaseHandler):
    async def get(self) -> None:
        self.render("templates/how_to_get_there.html")


class LoginHandler(BaseHandler):
    def get(self) -> None:
        self.render("templates/login.html", error=None)

    async def post(self) -> None:
        email = self.get_body_argument("email", "").strip().lower()
        password = self.get_body_argument("password", "")

        if not email or not password:
            logger.info("Login rejected: missing credentials from ip=%s.", self.request.remote_ip)
            self.render("templates/login.html", error="Email and password are required.")
            return

        # Admin login
        if email == self.cfg.admin_email.lower() and check_admin_password(self.cfg, password):
            self.set_secure_cookie("session", tornado.escape.json_encode({"role": "admin", "email": email}), httponly=True)
            logger.info("Admin login successful for %s from ip=%s.", email, self.request.remote_ip)
            self.redirect("/admin")
            return

        # Participant login
        users: Collection = self.db[self.cfg.users_collection]
        user = await users.find_one({"email_lower": email})
        if user:
            password_hash = user.get("password_hash")
            if isinstance(password_hash, str) and verify_password(password, password_hash):
                if not user.get("email_verified_at"):
                    logger.info("Participant login blocked for unverified email=%s.", email)
                    self.render("templates/login.html", error="Please verify your email before logging in.")
                    return
                user_id_val = user.get("_id")
                user_id_str = str(user_id_val) if user_id_val is not None else ""
                self.set_secure_cookie(
                    "session",
                    tornado.escape.json_encode({"role": "user", "user_id": user_id_str, "email": email}),
                    httponly=True,
                )
                logger.info("Participant login successful for email=%s.", email)
                self.redirect("/portal")
                return

        logger.info("Login failed for email=%s from ip=%s.", email or "<empty>", self.request.remote_ip)
        self.render("templates/login.html", error="Invalid credentials.")


class LogoutHandler(BaseHandler):
    def post(self) -> None:
        logger.info("Logout requested from ip=%s.", self.request.remote_ip)
        self.clear_cookie("session")
        self.redirect(self.get_argument("next", "/"))


class LegacyRegisterRedirectHandler(BaseHandler):
    async def get(self, _code: str) -> None:
        logger.info("Redirecting legacy invite registration URL from ip=%s.", self.request.remote_ip)
        self.redirect("/register")


class RegisterHandler(BaseHandler):
    def render_form(self, errors: Any, values: Dict[str, Any]) -> None:
        self.render(
            "templates/register.html",
            errors=errors,
            values=values,
            recaptcha_enabled=self.cfg.recaptcha_enabled,
            recaptcha_site_key=self.cfg.recaptcha_site_key or "",
            recaptcha_action=self.cfg.recaptcha_expected_action,
        )

    async def get(self) -> None:
        logger.debug("Rendering registration form for ip=%s.", self.request.remote_ip)
        self.render_form(None, {})

    async def post(self) -> None:
        body: Dict[str, Any] = {k: self.get_body_argument(k, "") for k in self.request.body_arguments.keys()}

        recaptcha_token = self.get_body_argument("recaptcha_token", "")
        email_candidate = str(body.get("email") or "").strip().lower()

        def _flag(name: str) -> bool:
            return self.get_body_argument(name, "false").lower() in {"true", "on", "1", "yes"}

        body["want_partner"] = _flag("want_partner")
        body["accept_rules"] = _flag("accept_rules")
        body["consent_data"] = _flag("consent_data")
        if self.cfg.recaptcha_enabled:
            recaptcha_ok = await verify_recaptcha_token(self.cfg, recaptcha_token, self.request.remote_ip)
            if not recaptcha_ok:
                logger.info("Registration rejected by reCAPTCHA for email=%s ip=%s.", email_candidate or "<empty>", self.request.remote_ip)
                self.render_form(
                    [{"loc": ("recaptcha",), "msg": "Security check failed. Please try again.", "type": "value_error"}],
                    body,
                )
                return
        try:
            form = RegistrationForm(**body)
        except ValidationError as exc:
            logger.info("Registration validation failed for email=%s with %s error(s).", email_candidate or "<empty>", len(exc.errors()))
            self.render_form(exc.errors(), body)
            return

        now = utcnow()
        verification_code = generate_verification_code()
        record = RegistrationRecord(
            first_name=form.first_name.strip(),
            last_name=form.last_name.strip(),
            email=form.email,
            email_lower=form.email.lower(),
            phone=form.phone.strip(),
            password_hash=hash_password(form.password),
            role=form.role,
            level=form.level,
            want_partner=form.want_partner,
            partner_name=form.partner_name.strip() if form.partner_name else None,
            partner_contact=form.partner_contact.strip() if form.partner_contact else None,
            special_conditions=form.special_conditions.strip() if form.special_conditions else None,
            accept_rules=form.accept_rules,
            consent_data=form.consent_data,
            email_proof_sent_at=now,
            email_verification_code=verification_code,
            email_verification_expires_at=now + EMAIL_VERIFICATION_EXPIRY,
            email_verification_last_sent_at=now,
        )

        users: Collection = self.db[self.cfg.users_collection]
        try:
            res = await users.insert_one(record.model_dump())
        except DuplicateKeyError:
            logger.info("Registration rejected: duplicate email=%s.", record.email_lower)
            self.render_form(
                [{"loc": ("email",), "msg": "Email already registered.", "type": "value_error"}],
                body,
            )
            return

        inserted_id = res.inserted_id
        if not isinstance(inserted_id, ObjectId):
            raise RuntimeError("Unexpected insert id type.")
        logger.info(
            "Registration created for email=%s role=%s level=%s partner=%s.",
            record.email_lower,
            record.role,
            record.level,
            record.want_partner,
        )

        try:
            send_verification_email(self.cfg, str(record.email), verification_code)
        except Exception:
            pass

        self.set_secure_cookie(
            "session",
            tornado.escape.json_encode(
                {"role": "user", "user_id": str(inserted_id), "email": form.email.lower()}
            ),
            httponly=True,
        )
        self.redirect("/portal")


class PortalHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        session = cast(Optional[SessionData], self.current_user)
        if not session or session.get("role") != "user":
            logger.warning("Portal access redirected to admin due to invalid user session from ip=%s.", self.request.remote_ip)
            self.redirect("/admin")
            return

        user_id = session.get("user_id")
        if not user_id:
            logger.warning("Portal access without user_id in session for email=%s.", session.get("email"))
            self.redirect("/login")
            return

        users: Collection = self.db[self.cfg.users_collection]
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            logger.warning("Portal access with invalid ObjectId user_id=%s.", user_id)
            self.clear_cookie("session")
            self.redirect("/login")
            return

        user_doc = await users.find_one({"_id": user_oid})
        if not user_doc:
            logger.warning("Portal access for missing user_id=%s.", user_id)
            self.clear_cookie("session")
            self.redirect("/login")
            return

        user: Document = {**user_doc, "_id": str(user_doc["_id"])}
        if not user.get("email_verified_at"):
            logger.info("Portal access blocked pending verification for email=%s.", session.get("email"))
            self.clear_cookie("session")
            self.redirect("/verify")
            return

        logger.debug("Portal rendered for email=%s confirmed=%s cancelled=%s.", user.get("email"), bool(user.get("application_confirmed_at")), bool(user.get("cancelled_at")))
        review_confirmed = bool(user.get("application_confirmed_at")) and not bool(user.get("cancelled_at"))
        payment_confirmed = review_confirmed and bool(user.get("payment_confirmed_at"))

        self.render(
            "templates/portal.html",
            user=user,
            application_confirmed=review_confirmed,
            payment_confirmed=payment_confirmed,
            payment_link=compact_string(user.get("payment_link")),
        )

    @tornado.web.authenticated
    async def post(self) -> None:
        self.redirect("/portal")


class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            logger.warning("Forbidden admin access attempt from ip=%s.", self.request.remote_ip)
            raise tornado.web.HTTPError(403)

        users_coll: Collection = self.db[self.cfg.users_collection]

        users_cursor = users_coll.find().sort("created_at", -1)
        registrations: List[Document] = []
        reg_stats: Dict[str, Dict[str, int]] = {
            "pending_email": {"leader": 0, "follower": 0},
            "pending_review": {"leader": 0, "follower": 0},
            "awaiting_payment": {"leader": 0, "follower": 0},
            "confirmed": {"leader": 0, "follower": 0},
        }
        async for doc in users_cursor:
            doc_typed = cast(Document, doc)

            role = str(doc_typed.get("role") or "").lower()
            verified = bool(doc_typed.get("email_verified_at"))
            review_confirmed = bool(doc_typed.get("application_confirmed_at"))
            payment_confirmed = review_confirmed and bool(doc_typed.get("payment_confirmed_at"))
            is_cancelled = bool(doc_typed.get("cancelled_at"))
            if role in reg_stats["pending_email"] and not is_cancelled:
                if not verified:
                    reg_stats["pending_email"][role] += 1
                elif not review_confirmed:
                    reg_stats["pending_review"][role] += 1
                elif payment_confirmed:
                    reg_stats["confirmed"][role] += 1
                else:
                    reg_stats["awaiting_payment"][role] += 1

            reg_dict: Document = {
                **doc_typed,
                "_id": str(doc_typed["_id"]),
                "order": len(registrations),
                "cancelled": is_cancelled,
                "review_confirmed": review_confirmed,
                "payment_confirmed": payment_confirmed,
                "verified": verified,
            }
            registrations.append(reg_dict)

        logger.info("Admin dashboard rendered with %s registrations.", len(registrations))
        self.render(
            "templates/admin.html",
            registrations=registrations,
            reg_stats=reg_stats,
        )


class ApplicationStatusHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        action = self.get_body_argument("action", "reject").strip().lower()
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        now = utcnow()
        if action == "reject":
            logger.info("Application rejected by admin=%s for email=%s.", self.current_user.get("email"), user_doc.get("email"))
            await users_coll.update_one(
                {"_id": user_oid},
                {
                    "$set": {
                        "cancelled_at": now,
                        "cancelled_by": self.current_user.get("email"),
                        "application_confirmed_at": None,
                        "application_confirmed_by": None,
                        "application_confirmation_email_sent_at": None,
                        "payment_confirmed_at": None,
                        "payment_confirmed_by": None,
                        "updated_at": now,
                    }
                },
            )
        elif action == "restore":
            logger.info("Application restored by admin=%s for email=%s.", self.current_user.get("email"), user_doc.get("email"))
            await users_coll.update_one(
                {"_id": user_oid},
                {
                    "$set": {
                        "cancelled_at": None,
                        "cancelled_by": None,
                        "updated_at": now,
                    }
                },
            )
        else:
            raise tornado.web.HTTPError(400)
        self.redirect("/admin")


class ConfirmApplicationHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        action = self.get_body_argument("action", "").strip().lower()
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        now = utcnow()
        if action == "confirm_paid":
            if user_doc.get("cancelled_at") or not user_doc.get("application_confirmed_at"):
                logger.warning(
                    "Invalid payment confirmation request by admin=%s for email=%s.",
                    self.current_user.get("email"),
                    user_doc.get("email"),
                )
                raise tornado.web.HTTPError(400)
            logger.info(
                "Payment confirmed by admin=%s for email=%s.",
                self.current_user.get("email"),
                user_doc.get("email"),
            )
            await users_coll.update_one(
                {"_id": user_oid},
                {
                    "$set": {
                        "payment_confirmed_at": now,
                        "payment_confirmed_by": self.current_user.get("email"),
                        "cancelled_at": None,
                        "cancelled_by": None,
                        "updated_at": now,
                    }
                },
                )
        elif action == "revoke":
            if not user_doc.get("application_confirmed_at") and not user_doc.get("payment_confirmed_at"):
                logger.warning(
                    "Invalid revoke request by admin=%s for email=%s.",
                    self.current_user.get("email"),
                    user_doc.get("email"),
                )
                raise tornado.web.HTTPError(400)
            if user_doc.get("payment_confirmed_at"):
                logger.info(
                    "Payment confirmation revoked by admin=%s for email=%s.",
                    self.current_user.get("email"),
                    user_doc.get("email"),
                )
                await users_coll.update_one(
                    {"_id": user_oid},
                    {
                        "$set": {
                            "payment_confirmed_at": None,
                            "payment_confirmed_by": None,
                            "updated_at": now,
                        }
                    },
                )
            else:
                logger.info(
                    "Application review confirmation revoked by admin=%s for email=%s.",
                    self.current_user.get("email"),
                    user_doc.get("email"),
                )
                await users_coll.update_one(
                    {"_id": user_oid},
                    {
                        "$set": {
                            "application_confirmed_at": None,
                            "application_confirmed_by": None,
                            "application_confirmation_email_sent_at": None,
                            "payment_confirmed_at": None,
                            "payment_confirmed_by": None,
                            "updated_at": now,
                        }
                    },
                )
        else:
            raise tornado.web.HTTPError(400)

        self.redirect("/admin")


class RegistrationMetaHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        action = self.get_body_argument("action", "save").strip().lower()
        comment = self.get_body_argument("admin_comment", "").strip()
        assigned_price = self.get_body_argument("assigned_price", "").strip()
        payment_link = self.get_body_argument("payment_link", "").strip()
        logger.info(
            "Registration meta updated by admin=%s for user_id=%s action=%s assigned_price=%s payment_link=%s comment=%s.",
            self.current_user.get("email"),
            user_id,
            action,
            bool(assigned_price),
            bool(payment_link),
            bool(comment),
        )

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        now = utcnow()
        update_set: Dict[str, Any] = {
            "admin_comment": comment or None,
            "assigned_price": assigned_price or None,
            "payment_link": payment_link or None,
            "updated_at": now,
        }

        if action == "confirm_and_send":
            if user_doc.get("cancelled_at") or not user_doc.get("email_verified_at"):
                logger.warning(
                    "Invalid review confirmation request by admin=%s for email=%s.",
                    self.current_user.get("email"),
                    user_doc.get("email"),
                )
                raise tornado.web.HTTPError(400)
            email = user_doc.get("email")
            first_name = str(user_doc.get("first_name") or "").strip()
            email_sent_at: Optional[dt.datetime] = user_doc.get("application_confirmation_email_sent_at")
            logger.info(
                "Application review confirmed by admin=%s for email=%s price=%s payment_link=%s.",
                self.current_user.get("email"),
                email,
                assigned_price or "-",
                bool(payment_link),
            )
            if isinstance(email, str) and email:
                sent = send_confirmation_email(self.cfg, email, first_name, assigned_price, payment_link)
                if sent:
                    email_sent_at = now
                else:
                    logger.warning(
                        "Application confirmation email was not delivered for email=%s; timestamp not updated.",
                        email,
                    )
            update_set.update(
                {
                    "application_confirmed_at": now,
                    "application_confirmed_by": self.current_user.get("email"),
                    "application_confirmation_email_sent_at": email_sent_at,
                    "payment_confirmed_at": None,
                    "payment_confirmed_by": None,
                    "cancelled_at": None,
                    "cancelled_by": None,
                }
            )
        elif action != "save":
            raise tornado.web.HTTPError(400)

        result = await users_coll.update_one({"_id": user_oid}, {"$set": update_set})

        if result.matched_count == 0:
            raise tornado.web.HTTPError(404)

        self.redirect("/admin")


class VerifyHandler(BaseHandler):
    def _session_payload(self, user: Document, email: str) -> SessionData:
        user_id_val = user.get("_id")
        user_id = str(user_id_val) if user_id_val is not None else ""
        return {"role": "user", "user_id": user_id, "email": email}

    async def _send_post_verification_emails(self, user: Document, email: str) -> None:
        if user.get("application_pending_email_sent_at"):
            logger.debug("Skipping post-verification emails for email=%s; already sent.", email)
            return

        first_name = str(user.get("first_name") or "").strip()
        try:
            send_pending_review_email(self.cfg, email, first_name)
            await self.db[self.cfg.users_collection].update_one(
                {"_id": user.get("_id")},
                {
                    "$set": {
                        "application_pending_email_sent_at": utcnow(),
                        "updated_at": utcnow(),
                    }
                },
            )
            logger.info("Sent pending-review email and marked timestamp for email=%s.", email)
        except Exception:
            pass

        try:
            parsed = RegistrationRecord.model_validate(user)
            send_admin_registration_email(self.cfg, parsed)
            logger.info("Sent admin notification for newly verified email=%s.", email)
        except Exception:
            pass

    async def _process_verification(self, email: str, code: str) -> tuple[Optional[str], Optional[SessionData]]:
        await asyncio.sleep(0.35)

        email_clean = email.strip().lower()
        code_clean = code.strip().upper()

        if not email_clean or not code_clean:
            logger.info("Verification rejected due to missing email/code from ip=%s.", self.request.remote_ip)
            return "Email and code are required.", None

        users: Collection = self.db[self.cfg.users_collection]
        user = await users.find_one({"email_lower": email_clean})
        if not user:
            logger.info("Verification requested for unknown email=%s.", email_clean)
            return "User not found.", None

        if user.get("email_verified_at"):
            user_doc = cast(Document, user)
            logger.info("Verification requested for already verified email=%s.", email_clean)
            await self._send_post_verification_emails(user_doc, email_clean)
            return None, self._session_payload(user_doc, email_clean)

        stored_code = user.get("email_verification_code")
        expires_at = user.get("email_verification_expires_at")
        attempts = int(user.get("email_verification_attempts") or 0)

        if not stored_code:
            logger.info("Verification failed for email=%s: no stored code.", email_clean)
            return "No verification code found. Request a new one.", None

        if attempts >= VERIFICATION_ATTEMPT_LIMIT:
            logger.info("Verification blocked for email=%s: attempt limit reached.", email_clean)
            return "Too many attempts. Request a new code.", None

        now = utcnow()

        def _expires_before_now(val: Any) -> bool:
            if not isinstance(val, dt.datetime):
                return False
            if val.tzinfo is None:
                val = val.replace(tzinfo=dt.timezone.utc)
            return val < now

        if expires_at and _expires_before_now(expires_at):
            attempts += 1
            await users.update_one(
                {"email_lower": email_clean},
                {
                    "$inc": {"email_verification_attempts": 1},
                    "$set": {"updated_at": now},
                },
            )
            if attempts >= VERIFICATION_ATTEMPT_LIMIT:
                logger.info("Verification expired and limit reached for email=%s.", email_clean)
                return "Too many attempts. Request a new code.", None
            logger.info("Verification code expired for email=%s.", email_clean)
            return "Code expired. Request a new code.", None

        if stored_code != code_clean:
            attempts += 1
            await users.update_one(
                {"email_lower": email_clean},
                {
                    "$inc": {"email_verification_attempts": 1},
                    "$set": {"updated_at": now},
                },
            )
            if attempts >= VERIFICATION_ATTEMPT_LIMIT:
                logger.info("Verification invalid and limit reached for email=%s.", email_clean)
                return "Too many attempts. Request a new code.", None
            logger.info("Verification failed due to invalid code for email=%s.", email_clean)
            return "Invalid code.", None

        await users.update_one(
            {"email_lower": email_clean},
            {
                "$set": {
                    "email_verified_at": now,
                    "email_verification_code": None,
                    "email_verification_expires_at": None,
                    "email_verification_attempts": 0,
                    "updated_at": now,
                }
            },
        )

        user_doc = cast(Document, {**user, "email_verified_at": now})
        logger.info("Email verified successfully for email=%s.", email_clean)
        await self._send_post_verification_emails(user_doc, email_clean)
        return None, self._session_payload(user_doc, email_clean)

    async def get(self) -> None:
        email_arg = self.get_argument("email", "").strip()
        code_arg = self.get_argument("code", "").strip()
        if email_arg and code_arg:
            error, session = await self._process_verification(email_arg, code_arg)
            if session:
                self.set_secure_cookie("session", tornado.escape.json_encode(session), httponly=True)
                self.redirect("/portal")
                return
            self.render("templates/verify.html", error=error, success=None, email=email_arg, code=code_arg, resend_cooldown_seconds=0)
            return

        self.render("templates/verify.html", error=None, success=None, email=email_arg, code=code_arg, resend_cooldown_seconds=0)

    async def post(self) -> None:
        email = self.get_body_argument("email", "")
        code = self.get_body_argument("code", "")
        error, session = await self._process_verification(email, code)
        if session:
            self.set_secure_cookie("session", tornado.escape.json_encode(session), httponly=True)
            self.redirect("/portal")
            return
        self.render(
            "templates/verify.html",
            error=error,
            success=None,
            email=email.strip().lower(),
            code=code.strip().upper(),
            resend_cooldown_seconds=0,
        )


class ResendVerificationHandler(BaseHandler):
    async def post(self) -> None:
        email = self.get_body_argument("email", "").strip().lower()
        now = utcnow()
        users: Collection = self.db[self.cfg.users_collection]

        if not email:
            logger.info("Verification resend rejected due to missing email from ip=%s.", self.request.remote_ip)
            self.render(
                "templates/verify.html",
                error="Email is required to resend the verification code.",
                success=None,
                email="",
                code="",
                resend_cooldown_seconds=0,
            )
            return

        user = await users.find_one({"email_lower": email})
        if not user:
            logger.info("Verification resend requested for unknown email=%s.", email)
            self.render(
                "templates/verify.html",
                error="User not found.",
                success=None,
                email=email,
                code="",
                resend_cooldown_seconds=0,
            )
            return

        if user.get("email_verified_at"):
            logger.info("Verification resend skipped for already verified email=%s.", email)
            self.render(
                "templates/verify.html",
                error=None,
                success="Email already verified. You can now log in.",
                email=email,
                code="",
                resend_cooldown_seconds=0,
            )
            return

        last_sent: Optional[dt.datetime] = user.get("email_verification_last_sent_at") or user.get("email_proof_sent_at")
        remaining_seconds = 0
        if isinstance(last_sent, dt.datetime):
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=dt.timezone.utc)
            cooldown_end = last_sent + VERIFICATION_RESEND_COOLDOWN
            remaining_seconds = int((cooldown_end - now).total_seconds())
            if remaining_seconds > 0:
                logger.info("Verification resend cooldown active for email=%s remaining=%ss.", email, remaining_seconds)
                self.render(
                    "templates/verify.html",
                    error="Please wait before requesting another code.",
                    success=None,
                    email=email,
                    code="",
                    resend_cooldown_seconds=remaining_seconds,
                )
                return

        new_code = generate_verification_code()

        await users.update_one(
            {"email_lower": email},
            {
                "$set": {
                    "email_verification_code": new_code,
                    "email_verification_expires_at": now + EMAIL_VERIFICATION_EXPIRY,
                    "email_verification_attempts": 0,
                    "email_verification_last_sent_at": now,
                    "email_proof_sent_at": now,
                    "updated_at": now,
                }
            },
        )

        try:
            send_verification_email(self.cfg, email, new_code)
        except Exception:
            pass
        logger.info("Verification code resent for email=%s.", email)

        self.render(
            "templates/verify.html",
            error=None,
            success="A new verification code was sent to your email.",
            email=email,
            code="",
            resend_cooldown_seconds=int(VERIFICATION_RESEND_COOLDOWN.total_seconds()),
        )


async def create_indexes(db: Database, cfg: Settings) -> None:
    users_coll: Collection = db[cfg.users_collection]
    await users_coll.create_index("email_lower", unique=True)
    logger.info("Ensured unique index on %s.email_lower.", cfg.users_collection)


def make_app(settings: Settings) -> tornado.web.Application:
    db_client: AsyncIOMotorClient[Document] | InMemoryClient
    if settings.use_in_memory_db:
        db_client = InMemoryClient()
        logger.info("Using in-memory database.")
    else:
        if not settings.mongo_url:
            raise RuntimeError("mongo_url is required when not using in-memory database.")
        db_client = AsyncIOMotorClient(settings.mongo_url, tz_aware=True)
        logger.info("Using MongoDB database.")
    db: Database = db_client.get_database()

    parsed = urlparse(settings.app_base_url)
    base_path = parsed.path.rstrip("/")
    if base_path and not base_path.startswith("/"):
        base_path = f"/{base_path}"
    static_prefix = f"{base_path}/static/" if base_path else "/static/"
    login_path = f"{base_path}/login" if base_path else "/login"

    def _prefixed(pattern: str) -> str:
        if not base_path:
            return pattern
        base = base_path.rstrip("/")
        if not base:
            return pattern
        if pattern == "/":
            return f"{base}/?"
        return f"{base}{pattern}"

    route_specs: Sequence[tuple[str, type[BaseHandler], Optional[str]]] = (
        (r"/", LandingHandler, "home"),
        (r"/how-to-get-there", HowToGetThereHandler, "how_to_get_there"),
        (r"/login", LoginHandler, "login"),
        (r"/logout", LogoutHandler, None),
        (r"/register", RegisterHandler, "register"),
        (r"/register/([A-Za-z0-9\\-_]+)", LegacyRegisterRedirectHandler, None),
        (r"/portal", PortalHandler, None),
        (r"/admin", AdminHandler, None),
        (r"/admin/applications/([A-Za-z0-9]+)/confirm", ConfirmApplicationHandler, None),
        (r"/admin/applications/([A-Za-z0-9]+)/status", ApplicationStatusHandler, None),
        (r"/admin/registrations/([A-Za-z0-9]+)/meta", RegistrationMetaHandler, None),
        (r"/verify/resend", ResendVerificationHandler, None),
        (r"/verify", VerifyHandler, None),
    )

    handlers: list[tornado.routing.Rule] = []
    for pattern, handler, name in route_specs:
        handlers.append(tornado.web.url(_prefixed(pattern), handler, name=name))

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    static_path = os.path.join(project_root, "static")
    settings_dict: Dict[str, Any] = {
        "app_settings": settings,
        "db": db,
        "cookie_secret": settings.cookie_secret,
        "login_url": login_path,
        "template_path": project_root,
        "static_path": static_path,
        "static_url_prefix": static_prefix,
        "base_path": base_path,
        "xsrf_cookies": False,
    }
    return tornado.web.Application(handlers, **settings_dict)


def main() -> None:
    settings = load_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("Starting UNSEEN on port %s.", settings.port)
    logger.info("reCAPTCHA enabled: %s.", settings.recaptcha_enabled)
    if not settings.smtp_configured:
        logger.warning("smtp_from is not configured. Outgoing emails will be logged instead of sent.")
    elif settings.smtp_uses_defaults:
        logger.warning(
            "SMTP settings are still using the default localhost configuration. "
            "If no local SMTP server exists, outgoing emails will fail."
        )
    app = make_app(settings)
    db: Database = cast(Database, app.settings["db"])
    loop: tornado.ioloop.IOLoop = tornado.ioloop.IOLoop.current()

    async def _init_indexes() -> None:
        await create_indexes(db, settings)

    loop.run_sync(_init_indexes, None) # type: ignore[unused-ignore]
    app.listen(settings.port)
    logger.info("Running on http://0.0.0.0:%s", settings.port)
    loop.start()


if __name__ == "__main__":
    main()
