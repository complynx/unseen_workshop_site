import asyncio
import datetime as dt
import hashlib
import hmac
import os
import secrets
import smtplib
from collections.abc import Sequence
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TypedDict, cast
from urllib.parse import urlparse

import tornado.escape
import tornado.ioloop
import tornado.web
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel, EmailStr, Field, ValidationError, model_validator
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


def utcnow() -> dt.datetime:
    """Timezone-aware UTC now."""
    return dt.datetime.now(dt.timezone.utc)


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
    invites_collection: str = "unseen_invites"
    users_collection: str = "unseen_users"
    admin_email: EmailStr
    admin_password: str
    cookie_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: EmailStr = "no-reply@example.com"
    smtp_use_tls: bool = True

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

    @model_validator(mode="after")
    def validate_database_choice(self) -> "Settings":
        if not self.use_in_memory_db and not self.mongo_url:
            raise ValueError("mongo_url is required unless use_in_memory_db is true.")
        return self


def load_settings() -> Settings:
    return Settings.model_validate({})


if TYPE_CHECKING:
    _settings_example = Settings(
        mongo_url="mongodb://example",
        admin_email="admin@example.com",
        admin_password="changeme",
    )


class Invite(BaseModel):
    code: str
    label: str
    created_by: str
    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)
    hidden: bool = False
    status: str = "active"
    used_at: Optional[dt.datetime] = None
    used_by: Optional[str] = None
    deleted_at: Optional[dt.datetime] = None
    deleted_by: Optional[str] = None


class RecommendationEntry(BaseModel):
    name: str
    contact: str
    processed: bool = False
    registered: bool = False


def recommendation_list_factory() -> list[RecommendationEntry]:
    return []


class PostApprovalForm(BaseModel):
    opposite_role: list[RecommendationEntry] = Field(default_factory=recommendation_list_factory)
    same_role: Optional[RecommendationEntry] = None
    allergies: Optional[str] = None
    whatsapp_opt_in: bool = False

    @model_validator(mode="after")
    def check_counts(self) -> "PostApprovalForm":
        if len(self.opposite_role) > 3:
            raise ValueError("Up to 3 opposite-role recommendations are allowed.")
        return self


def normalize_recommendation_entry(raw: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"name": "", "contact": "", "processed": False, "registered": False}
    if isinstance(raw, dict):
        entry["name"] = str(raw.get("name") or "").strip() # type: ignore[unused-ignore]
        entry["contact"] = str(raw.get("contact") or "").strip() # type: ignore[unused-ignore]
        entry["processed"] = bool(raw.get("processed")) # type: ignore[unused-ignore]
        entry["registered"] = bool(raw.get("registered")) # type: ignore[unused-ignore]
    return entry


def normalize_post_approval(raw: Any) -> Dict[str, Any]:
    post_data: Dict[str, Any] = {"opposite": [], "same": None, "allergies": "", "whatsapp_opt_in": False}
    if not isinstance(raw, dict):
        return post_data

    opposite_raw: Any = raw.get("opposite_role") # type: ignore[unused-ignore]
    if isinstance(opposite_raw, list):
        for item in opposite_raw: # type: ignore[unused-ignore]
            entry = normalize_recommendation_entry(item)
            if entry["name"] or entry["contact"]:
                post_data["opposite"].append(entry)

    same_raw = raw.get("same_role") # type: ignore[unused-ignore]
    if isinstance(same_raw, dict):
        entry = normalize_recommendation_entry(same_raw)
        if entry["name"] or entry["contact"]:
            post_data["same"] = entry

    post_data["allergies"] = str(raw.get("allergies") or "") # type: ignore[unused-ignore]
    post_data["whatsapp_opt_in"] = bool(raw.get("whatsapp_opt_in")) # type: ignore[unused-ignore]
    return post_data


def build_post_approval_payload(
    opposite: list[Dict[str, Any]],
    same: Optional[Dict[str, Any]],
    allergies: Optional[str],
    whatsapp_opt_in: bool,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "opposite_role": [],
        "allergies": allergies or None,
        "whatsapp_opt_in": bool(whatsapp_opt_in),
        "same_role": None,
    }

    for entry in opposite:
        name = str(entry.get("name") or "").strip()
        contact = str(entry.get("contact") or "").strip()
        if not (name and contact):
            continue
        payload["opposite_role"].append(
            {
                "name": name,
                "contact": contact,
                "processed": bool(entry.get("processed")),
                "registered": bool(entry.get("registered")),
            }
        )

    if same:
        name = str(same.get("name") or "").strip()
        contact = str(same.get("contact") or "").strip()
        if name and contact:
            payload["same_role"] = {
                "name": name,
                "contact": contact,
                "processed": bool(same.get("processed")),
                "registered": bool(same.get("registered")),
            }

    return payload


def build_post_prefill(post_data: Dict[str, Any]) -> Dict[str, Any]:
    opposite = list(post_data.get("opposite") or [])
    while len(opposite) < 3:
        opposite.append({"name": "", "contact": "", "processed": False, "registered": False})
    opposite = opposite[:3]
    same_entry = post_data.get("same") or {"name": "", "contact": "", "processed": False, "registered": False} # type: ignore[unused-ignore]
    return {
        "opposite": opposite,
        "same": same_entry,
        "allergies": post_data.get("allergies") or "",
        "whatsapp_opt_in": bool(post_data.get("whatsapp_opt_in")),
    }


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
    invite_code: str
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
    payment_approved: bool = False
    admin_comment: Optional[str] = None
    assigned_price: Optional[str] = None
    post_approval: PostApprovalForm = Field(default_factory=PostApprovalForm)
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


def send_email(settings: Settings, to_email: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"UNSEEN <{settings.smtp_from}>"
    msg["To"] = to_email
    msg.set_content(body)

    if settings.smtp_use_tls:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls()
            if settings.smtp_user and settings.smtp_password:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_user and settings.smtp_password:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)


def generate_verification_code() -> str:
    return secrets.token_urlsafe(6).replace("-", "")[:8].upper()

EMAIL_VERIFICATION_EXPIRY = dt.timedelta(hours=6)
VERIFICATION_ATTEMPT_LIMIT = 5
VERIFICATION_RESEND_COOLDOWN = dt.timedelta(minutes=5)


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
            self.render("templates/login.html", error="Email and password are required.")
            return

        # Admin login
        if email == self.cfg.admin_email.lower() and check_admin_password(self.cfg, password):
            self.set_secure_cookie("session", tornado.escape.json_encode({"role": "admin", "email": email}), httponly=True)
            self.redirect("/admin")
            return

        # Participant login
        users: Collection = self.db[self.cfg.users_collection]
        user = await users.find_one({"email_lower": email})
        if user:
            password_hash = user.get("password_hash")
            if isinstance(password_hash, str) and verify_password(password, password_hash):
                if not user.get("email_verified_at"):
                    self.render("templates/login.html", error="Please verify your email before logging in.")
                    return
                user_id_val = user.get("_id")
                user_id_str = str(user_id_val) if user_id_val is not None else ""
                self.set_secure_cookie(
                    "session",
                    tornado.escape.json_encode({"role": "user", "user_id": user_id_str, "email": email}),
                    httponly=True,
                )
                self.redirect("/portal")
                return

        self.render("templates/login.html", error="Invalid credentials.")


class LogoutHandler(BaseHandler):
    def post(self) -> None:
        self.clear_cookie("session")
        self.redirect(self.get_argument("next", "/"))


class RegisterHandler(BaseHandler):
    async def get(self, code: str) -> None:
        code = code.lower()
        invite = await self.db[self.cfg.invites_collection].find_one(
            {"code": code, "status": {"$nin": ["deleted", "used"]}}
        )
        if not invite:
            raise tornado.web.HTTPError(404)
        self.render("templates/register.html", code=code, invite=invite, errors=None, values={})

    async def post(self, code: str) -> None:
        code = code.lower()
        invite = await self.db[self.cfg.invites_collection].find_one(
            {"code": code, "status": {"$nin": ["deleted", "used"]}}
        )
        if not invite:
            raise tornado.web.HTTPError(404)

        body: Dict[str, Any] = {k: self.get_body_argument(k, "") for k in self.request.body_arguments.keys()}

        def _flag(name: str) -> bool:
            return self.get_body_argument(name, "false").lower() in {"true", "on", "1", "yes"}

        body["want_partner"] = _flag("want_partner")
        body["accept_rules"] = _flag("accept_rules")
        body["consent_data"] = _flag("consent_data")
        try:
            form = RegistrationForm(**body)
        except ValidationError as exc:
            self.render(
                "templates/register.html",
                code=code,
                invite=invite,
                errors=exc.errors(),
                values=body,
            )
            return

        now = utcnow()
        verification_code = generate_verification_code()
        record = RegistrationRecord(
            invite_code=code,
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
            self.render(
                "templates/register.html",
                code=code,
                invite=invite,
                errors=[{"loc": ("email",), "msg": "Email already registered.", "type": "value_error"}],
                values=body,
            )
            return

        inserted_id = res.inserted_id
        if not isinstance(inserted_id, ObjectId):
            raise RuntimeError("Unexpected insert id type.")

        try:
            await self.db[self.cfg.invites_collection].update_one(
                {"code": code},
                {
                    "$set": {
                        "status": "used",
                        "used_at": utcnow(),
                        "used_by": str(record.email),
                        "updated_at": utcnow(),
                    }
                },
            )
        except Exception:
            pass

        verification_link = f"{self.cfg.app_base_url.rstrip('/')}/verify?code={record.email_verification_code}&email={record.email}"
        try:
            send_email(
                self.cfg,
                to_email=str(record.email),
                subject="Verify your email for UNSEEN",
                body=(
                    "Hi,\n\n"
                    "Please verify your email to complete your registration for UNSEEN.\n\n"
                    f"Verification code: {record.email_verification_code}\n"
                    f"Or click: {verification_link}\n\n"
                    "This code expires in 6 hours.\n\n"
                    "If you did not register, you can ignore this email."
                ),
            )
        except Exception:
            pass

        admin_link = f"{self.cfg.app_base_url.rstrip('/')}/admin"
        partner_line = "Yes" if record.want_partner else "No"
        try:
            send_email(
                self.cfg,
                to_email=str(self.cfg.admin_email),
                subject="New UNSEEN registration",
                body=(
                    "Hello,\n\n"
                    "A new participant just registered for UNSEEN.\n\n"
                    f"Name: {record.first_name} {record.last_name}\n"
                    f"Email: {record.email}\n"
                    f"Phone: {record.phone}\n"
                    f"Role/Level: {record.role.title()} / {record.level.title()}\n"
                    f"Invite code: {record.invite_code}\n"
                    f"Registering with partner: {partner_line}\n"
                    f"Partner name: {record.partner_name or '-'}\n"
                    f"Partner contact: {record.partner_contact or '-'}\n"
                    f"Special conditions: {record.special_conditions or '-'}\n\n"
                    f"View in admin: {admin_link}"
                ),
            )
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
            self.redirect("/admin")
            return

        user_id = session.get("user_id")
        if not user_id:
            self.redirect("/login")
            return

        users: Collection = self.db[self.cfg.users_collection]
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            self.clear_cookie("session")
            self.redirect("/login")
            return

        user_doc = await users.find_one({"_id": user_oid})
        if not user_doc:
            self.clear_cookie("session")
            self.redirect("/login")
            return
        user: Document = {**user_doc, "_id": str(user_doc["_id"])}
        if not user.get("email_verified_at"):
            self.clear_cookie("session")
            self.redirect("/verify")
            return

        participants_cursor = users.find(
            {},
            {"first_name": 1, "last_name": 1},
        ).sort("first_name", 1)
        participants: List[str] = []
        async for item_doc in participants_cursor:
            item: Document = cast(Document, item_doc)
            name = f"{(item.get('first_name') or '').strip()} {(item.get('last_name') or '').strip()}".strip()
            participants.append(name or "Registered participant")

        post_data = normalize_post_approval(user.get("post_approval"))
        post_prefill = build_post_prefill(post_data)

        self.render(
            "templates/portal.html",
            user=user,
            participants=participants,
            post_approval=post_prefill,
            errors=None,
        )

    @tornado.web.authenticated
    async def post(self) -> None:
        session = cast(Optional[SessionData], self.current_user)
        if not session or session.get("role") != "user":
            raise tornado.web.HTTPError(403)
        user_id = session.get("user_id")
        if not user_id:
            raise tornado.web.HTTPError(403)

        users: Collection = self.db[self.cfg.users_collection]
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(403)

        user_doc = await users.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(403)
        if not user_doc.get("email_verified_at"):
            self.redirect("/verify")
            return
        if not bool(user_doc.get("payment_approved")):
            self.redirect("/portal")
            return
        user: Document = {**user_doc, "_id": str(user_doc["_id"])}

        def _flag(name: str) -> bool:
            return self.get_body_argument(name, "false").lower() in {"true", "on", "1", "yes"}

        existing_post = normalize_post_approval(user.get("post_approval"))

        allergies_val = self.get_body_argument("allergies", "").strip() or None
        whatsapp_opt_in = _flag("whatsapp_opt_in")

        opposite_existing = list(existing_post.get("opposite") or [])
        updated_opposite: List[Dict[str, Any]] = []
        for idx in range(1, 4):
            name = self.get_body_argument(f"opp_name_{idx}", "").strip()
            contact = self.get_body_argument(f"opp_contact_{idx}", "").strip()
            existing_entry = (opposite_existing[idx - 1] # type: ignore[unused-ignore]
                              if (idx - 1 < len(opposite_existing))
                              else {"name": "", "contact": "", "processed": False, "registered": False})
            locked = bool(existing_entry.get("processed") or existing_entry.get("registered")) # type: ignore[unused-ignore]
            if locked:
                if existing_entry.get("name") or existing_entry.get("contact"): # type: ignore[unused-ignore]
                    updated_opposite.append(existing_entry) # type: ignore[unused-ignore]
                continue
            if name and contact:
                updated_opposite.append(
                    {
                        "name": name,
                        "contact": contact,
                        "processed": bool(existing_entry.get("processed")), # type: ignore[unused-ignore]
                        "registered": bool(existing_entry.get("registered")), # type: ignore[unused-ignore]
                    }
                )

        same_existing = existing_post.get("same") or {"name": "", "contact": "", "processed": False, "registered": False} # type: ignore[unused-ignore]
        same_locked = bool(same_existing.get("processed") or same_existing.get("registered")) # type: ignore[unused-ignore]
        same_name = self.get_body_argument("same_name", "").strip()
        same_contact = self.get_body_argument("same_contact", "").strip()
        updated_same: Optional[Dict[str, Any]] = None
        if same_locked:
            if same_existing.get("name") or same_existing.get("contact"): # type: ignore[unused-ignore]
                updated_same = same_existing # type: ignore[unused-ignore]
        elif same_name and same_contact:
            updated_same = {
                "name": same_name,
                "contact": same_contact,
                "processed": bool(same_existing.get("processed")), # type: ignore[unused-ignore]
                "registered": bool(same_existing.get("registered")), # type: ignore[unused-ignore]
            }

        form_payload = build_post_approval_payload(updated_opposite, updated_same, allergies_val, whatsapp_opt_in)

        try:
            parsed = PostApprovalForm(**form_payload)
        except ValidationError as exc:
            participants_cursor = users.find(
                {},
                {"first_name": 1, "last_name": 1},
            ).sort("first_name", 1)
            participants: List[str] = []
            async for item_doc in participants_cursor:
                item: Document = cast(Document, item_doc)
                name = f"{(item.get('first_name') or '').strip()} {(item.get('last_name') or '').strip()}".strip()
                participants.append(name or "Registered participant")
            normalized = normalize_post_approval(form_payload)
            post_prefill = build_post_prefill(normalized)

            self.render(
                "templates/portal.html",
                user=user,
                participants=participants,
                post_approval=post_prefill,
                errors=exc.errors(),
            )
            return

        await users.update_one(
            {"_id": user_oid},
            {
                "$set": {
                    "post_approval": parsed.model_dump(),
                    "updated_at": utcnow(),
                }
            },
        )
        self.redirect("/portal")


class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        invites_coll: Collection = self.db[self.cfg.invites_collection]
        users_coll: Collection = self.db[self.cfg.users_collection]

        invites_cursor = invites_coll.find().sort("created_at", -1)
        invites: List[Document] = [cast(Document, i) async for i in invites_cursor]

        users_cursor = users_coll.find().sort("created_at", -1)
        registrations: List[Document] = []
        reg_stats: Dict[str, Dict[str, int]] = {
            "pending_email": {"leader": 0, "follower": 0},
            "registered": {"leader": 0, "follower": 0},
            "paid": {"leader": 0, "follower": 0},
        }
        invite_suggestions: List[Dict[str, Any]] = []
        async for doc in users_cursor:
            doc_typed = cast(Document, doc)
            post_meta = normalize_post_approval(doc_typed.get("post_approval"))

            role = str(doc_typed.get("role") or "").lower()
            verified = bool(doc_typed.get("email_verified_at"))
            paid = bool(doc_typed.get("payment_approved"))
            is_cancelled = bool(doc_typed.get("cancelled_at"))
            if role in reg_stats["pending_email"] and not is_cancelled:
                if not verified:
                    reg_stats["pending_email"][role] += 1
                elif paid:
                    reg_stats["paid"][role] += 1
                else:
                    reg_stats["registered"][role] += 1

            reg_dict: Document = {
                **doc_typed,
                "_id": str(doc_typed["_id"]),
                "post_meta": post_meta,
                "order": len(registrations),
                "cancelled": is_cancelled,
            }
            registrations.append(reg_dict)

            source_name = f"{(doc_typed.get('first_name') or '').strip()} {(doc_typed.get('last_name') or '').strip()}".strip()
            source_email = str(doc_typed.get("email") or "")
            for idx, entry in enumerate(post_meta.get("opposite") or []):
                if not (entry.get("name") or entry.get("contact")):
                    continue
                potential_role = "follower" if role == "leader" else "leader" if role == "follower" else "opposite role"
                invite_suggestions.append(
                    {
                        "source_id": str(doc_typed["_id"]),
                        "source_name": source_name or "Registered participant",
                        "source_email": source_email,
                        "source_role": role,
                        "name": entry.get("name"),
                        "contact": entry.get("contact"),
                        "potential_role": potential_role,
                        "processed": bool(entry.get("processed")),
                        "registered": bool(entry.get("registered")),
                        "kind": "opposite",
                        "index": idx,
                        "order": len(invite_suggestions),
                    }
                )
            same_entry = post_meta.get("same")
            if same_entry and (same_entry.get("name") or same_entry.get("contact")):
                potential_role = role if role in {"leader", "follower"} else "same role"
                invite_suggestions.append(
                    {
                        "source_id": str(doc_typed["_id"]),
                        "source_name": source_name or "Registered participant",
                        "source_email": source_email,
                        "source_role": role,
                        "name": same_entry.get("name"),
                        "contact": same_entry.get("contact"),
                        "potential_role": potential_role,
                        "processed": bool(same_entry.get("processed")),
                        "registered": bool(same_entry.get("registered")),
                        "kind": "same",
                        "index": 0,
                        "order": len(invite_suggestions),
                    }
                )

        self.render(
            "templates/admin.html",
            invites=invites,
            registrations=registrations,
            reg_stats=reg_stats,
            invite_suggestions=invite_suggestions,
            base_url=self.cfg.app_base_url.rstrip("/"),
        )


class CreateInviteHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        label = self.get_body_argument("label", "").strip()
        code = self.get_body_argument("code", "").strip() or secrets.token_urlsafe(8).replace("-", "")[:10]
        invite = Invite(
            code=code.lower(),
            label=label or "Invite",
            created_by=self.current_user.get("email", "admin"),
        )

        invites_coll: Collection = self.db[self.cfg.invites_collection]
        try:
            await invites_coll.insert_one(invite.model_dump())
        except DuplicateKeyError:
            self.redirect("/admin?error=code")
            return

        self.redirect("/admin")


class InviteStatusHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, code: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        code_lower = code.lower()
        action = self.get_body_argument("action", "delete").strip().lower()
        invites_coll: Collection = self.db[self.cfg.invites_collection]
        now = utcnow()
        if action == "hide":
            await invites_coll.update_one(
                {"code": code_lower},
                {
                    "$set": {
                        "hidden": True,
                        "updated_at": now,
                    }
                },
            )
        elif action == "unhide":
            await invites_coll.update_one(
                {"code": code_lower},
                {
                    "$set": {
                        "hidden": False,
                        "updated_at": now,
                    }
                },
            )
        elif action == "delete":
            await invites_coll.update_one(
                {"code": code_lower, "status": {"$ne": "used"}},
                {
                    "$set": {
                        "status": "deleted",
                        "deleted_at": now,
                        "deleted_by": self.current_user.get("email"),
                        "updated_at": now,
                    }
                },
            )
        else:
            raise tornado.web.HTTPError(400)
        self.redirect("/admin")


class CancelRegistrationHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        action = self.get_body_argument("action", "cancel").strip().lower()
        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        now = utcnow()
        if action == "cancel":
            if user_doc.get("payment_approved"):
                raise tornado.web.HTTPError(400)
            await users_coll.update_one(
                {"_id": user_oid},
                {
                    "$set": {
                        "cancelled_at": now,
                        "cancelled_by": self.current_user.get("email"),
                        "payment_approved": False,
                        "updated_at": now,
                    }
                },
            )
        elif action == "restore":
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


class ApprovePaymentHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        action = self.get_body_argument("action", "approve")
        approved = action == "approve"

        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        already_approved = bool(user_doc.get("payment_approved"))
        await users_coll.update_one(
            {"_id": user_oid},
            {"$set": {"payment_approved": approved, "updated_at": utcnow()}},
        )

        if approved and not already_approved:
            email = user_doc.get("email")
            if isinstance(email, str) and email:
                first_name = str(user_doc.get("first_name") or "").strip() or "there"
                portal_link = f"{self.cfg.app_base_url.rstrip('/')}/portal"
                try:
                    send_email(
                        self.cfg,
                        to_email=email,
                        subject="You're approved for UNSEEN",
                        body=(
                            f"Hi {first_name},\n\n"
                            "Great news! Your registration has been approved.\n"
                            "You can now log in to the portal and confirm some last details, invite other participants or see the list of already confirmed ones.\n"
                            "Inviting participants you like is a great way to share the experience, so don't hesitate to do so.\n\n"
                            f"Portal: {portal_link}\n\n"
                            "If you have any questions, just reply to this email."
                        ),
                    )
                except Exception:
                    pass
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

        comment = self.get_body_argument("admin_comment", "").strip()
        assigned_price = self.get_body_argument("assigned_price", "").strip()

        users_coll: Collection = self.db[self.cfg.users_collection]
        result = await users_coll.update_one(
            {"_id": user_oid},
            {
                "$set": {
                    "admin_comment": comment or None,
                    "assigned_price": assigned_price or None,
                    "updated_at": utcnow(),
                }
            },
        )

        if result.matched_count == 0:
            raise tornado.web.HTTPError(404)

        self.redirect("/admin")


class SuggestionStatusHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, user_id: str) -> None:
        if not self.current_user or self.current_user.get("role") != "admin":
            raise tornado.web.HTTPError(403)

        kind = self.get_body_argument("kind", "")
        index_raw = self.get_body_argument("index", "0")
        processed = self.get_body_argument("processed", "false").lower() in {"true", "on", "1", "yes"}
        registered = self.get_body_argument("registered", "false").lower() in {"true", "on", "1", "yes"}

        try:
            idx = int(index_raw)
        except Exception:
            raise tornado.web.HTTPError(400)
        if idx < 0:
            raise tornado.web.HTTPError(400)

        try:
            user_oid = ObjectId(user_id)
        except Exception:
            raise tornado.web.HTTPError(404)

        users_coll: Collection = self.db[self.cfg.users_collection]
        user_doc = await users_coll.find_one({"_id": user_oid})
        if not user_doc:
            raise tornado.web.HTTPError(404)

        post_data = normalize_post_approval(user_doc.get("post_approval"))
        target: Optional[Dict[str, Any]] = None
        if kind == "opposite":
            if idx >= len(post_data.get("opposite") or []):
                raise tornado.web.HTTPError(404)
            target = (post_data.get("opposite") or [])[idx] # type: ignore[unused-ignore]
        elif kind == "same":
            if idx != 0 or not post_data.get("same"):
                raise tornado.web.HTTPError(404)
            target = post_data.get("same")
        else:
            raise tornado.web.HTTPError(400)

        if not target or not (target.get("name") or target.get("contact")): # type: ignore[unused-ignore]
            raise tornado.web.HTTPError(404)

        target["processed"] = processed
        target["registered"] = registered

        payload = build_post_approval_payload(
            list(post_data.get("opposite") or []),
            post_data.get("same"),
            post_data.get("allergies"),
            bool(post_data.get("whatsapp_opt_in")),
        )
        try:
            parsed = PostApprovalForm(**payload)
        except ValidationError:
            raise tornado.web.HTTPError(400)

        await users_coll.update_one(
            {"_id": user_oid},
            {
                "$set": {
                    "post_approval": parsed.model_dump(),
                    "updated_at": utcnow(),
                }
            },
        )
        self.redirect("/admin")


class VerifyHandler(BaseHandler):
    async def _process_verification(self, email: str, code: str) -> tuple[Optional[str], Optional[str]]:
        await asyncio.sleep(0.35)

        email_clean = email.strip().lower()
        code_clean = code.strip().upper()

        if not email_clean or not code_clean:
            return "Email and code are required.", None

        users: Collection = self.db[self.cfg.users_collection]
        user = await users.find_one({"email_lower": email_clean})
        if not user:
            return "User not found.", None

        if user.get("email_verified_at"):
            return None, "Email already verified. You can now log in."

        stored_code = user.get("email_verification_code")
        expires_at = user.get("email_verification_expires_at")
        attempts = int(user.get("email_verification_attempts") or 0)

        if not stored_code:
            return "No verification code found. Request a new one.", None

        if attempts >= VERIFICATION_ATTEMPT_LIMIT:
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
                return "Too many attempts. Request a new code.", None
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
                return "Too many attempts. Request a new code.", None
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

        return None, "Email verified. You can now log in."

    async def get(self) -> None:
        email_arg = self.get_argument("email", "").strip()
        code_arg = self.get_argument("code", "").strip()
        if email_arg and code_arg:
            error, success = await self._process_verification(email_arg, code_arg)
            self.render(
                "templates/verify.html",
                error=error,
                success=success,
                email=email_arg,
                code="" if success else code_arg,
                resend_cooldown_seconds=0,
            )
            return

        self.render("templates/verify.html", error=None, success=None, email=email_arg, code=code_arg, resend_cooldown_seconds=0)

    async def post(self) -> None:
        email = self.get_body_argument("email", "")
        code = self.get_body_argument("code", "")
        error, success = await self._process_verification(email, code)
        self.render(
            "templates/verify.html",
            error=error,
            success=success,
            email=email.strip().lower(),
            code="" if success else code.strip().upper(),
            resend_cooldown_seconds=0,
        )


class ResendVerificationHandler(BaseHandler):
    async def post(self) -> None:
        email = self.get_body_argument("email", "").strip().lower()
        now = utcnow()
        users: Collection = self.db[self.cfg.users_collection]

        if not email:
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
        verification_link = f"{self.cfg.app_base_url.rstrip('/')}/verify?code={new_code}&email={email}"

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
            send_email(
                self.cfg,
                to_email=email,
                subject="Verify your email for UNSEEN",
                body=(
                    "Hi,\n\n"
                    "Please verify your email to complete your registration for UNSEEN.\n\n"
                    f"Verification code: {new_code}\n"
                    f"Or click: {verification_link}\n\n"
                    "This code expires in 6 hours.\n\n"
                    "If you did not register, you can ignore this email."
                ),
            )
        except Exception:
            pass

        self.render(
            "templates/verify.html",
            error=None,
            success="A new verification code was sent to your email.",
            email=email,
            code="",
            resend_cooldown_seconds=int(VERIFICATION_RESEND_COOLDOWN.total_seconds()),
        )


async def create_indexes(db: Database, cfg: Settings) -> None:
    invites_coll: Collection = db[cfg.invites_collection]
    users_coll: Collection = db[cfg.users_collection]
    await invites_coll.create_index("code", unique=True)
    await users_coll.create_index("email_lower", unique=True)
    await users_coll.create_index("invite_code")


def make_app(settings: Settings) -> tornado.web.Application:
    db_client: AsyncIOMotorClient[Document] | InMemoryClient
    if settings.use_in_memory_db:
        db_client = InMemoryClient()
    else:
        if not settings.mongo_url:
            raise RuntimeError("mongo_url is required when not using in-memory database.")
        db_client = AsyncIOMotorClient(settings.mongo_url, tz_aware=True)
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
        (r"/register/([A-Za-z0-9\\-_]+)", RegisterHandler, None),
        (r"/portal", PortalHandler, None),
        (r"/admin", AdminHandler, None),
        (r"/admin/invites", CreateInviteHandler, None),
        (r"/admin/invites/([A-Za-z0-9\\-_]+)/delete", InviteStatusHandler, None),
        (r"/admin/approve/([A-Za-z0-9]+)", ApprovePaymentHandler, None),
        (r"/admin/registrations/([A-Za-z0-9]+)/cancel", CancelRegistrationHandler, None),
        (r"/admin/registrations/([A-Za-z0-9]+)/meta", RegistrationMetaHandler, None),
        (r"/admin/suggestions/([A-Za-z0-9]+)", SuggestionStatusHandler, None),
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
    app = make_app(settings)
    db: Database = cast(Database, app.settings["db"])
    loop: tornado.ioloop.IOLoop = tornado.ioloop.IOLoop.current()

    async def _init_indexes() -> None:
        await create_indexes(db, settings)

    loop.run_sync(_init_indexes, None) # type: ignore[unused-ignore]
    app.listen(settings.port)
    print(f"Running on http://0.0.0.0:{settings.port}")
    loop.start()


if __name__ == "__main__":
    main()
