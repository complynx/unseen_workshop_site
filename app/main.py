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


class RecommendationEntry(BaseModel):
    name: str
    contact: str


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
    email_verified_at: Optional[dt.datetime] = None
    payment_approved: bool = False
    post_approval: PostApprovalForm = Field(default_factory=PostApprovalForm)
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


class BaseHandler(tornado.web.RequestHandler):
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

    def redirect(self, url: str, permanent: bool = False, status: Optional[int] = None) -> None: # type: ignore[override]
        super().redirect(self._with_base(url), permanent=permanent, status=status)

    def reverse_url(self, name: str, *args: Any) -> str: # type: ignore[override]
        raw = super().reverse_url(name, *args)
        return self._with_base(raw)

    def render(self, template_name: str, **kwargs: Any) -> None: # type: ignore[override]
        kwargs.setdefault("base_path", self.base_path)
        super().render(template_name, **kwargs)

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        if status_code == 404:
            self.render("templates/error.html", title="Not found", message="Page not found.")
            return
        super().write_error(status_code, **kwargs)


class LandingHandler(BaseHandler):
    async def get(self) -> None:
        self.render(
            "unseen.html",
            login_url=self.reverse_url("login"),
        )


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
        invite = await self.db[self.cfg.invites_collection].find_one({"code": code})
        if not invite:
            raise tornado.web.HTTPError(404)
        self.render("templates/register.html", code=code, invite=invite, errors=None, values={})

    async def post(self, code: str) -> None:
        code = code.lower()
        invite = await self.db[self.cfg.invites_collection].find_one({"code": code})
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
            email_proof_sent_at=utcnow(),
            email_verification_code=generate_verification_code(),
            email_verification_expires_at=utcnow() + dt.timedelta(hours=6),
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

        post_data_raw = user.get("post_approval")
        post_data: Dict[str, Any] = {}
        if isinstance(post_data_raw, dict):
            typed_post: Dict[str, Any] = {}
            for k, v in post_data_raw.items(): # type: ignore[unused-ignore]
                typed_post[str(k)] = v # type: ignore[unused-ignore]
            post_data = typed_post

        opposite_raw = post_data.get("opposite_role")
        opposite: List[Dict[str, Any]] = []
        if isinstance(opposite_raw, list):
            for raw_item in opposite_raw: # type: ignore[unused-ignore]
                if isinstance(raw_item, dict):
                    raw_item_dict: Dict[str, Any] = cast(Dict[str, Any], raw_item)
                    opposite.append(raw_item_dict)
                else:
                    opposite.append({})
        while len(opposite) < 3:
            opposite.append({})
        opposite = opposite[:3]
        post_prefill: Dict[str, Any] = {
            "opposite": opposite,
            "same": post_data.get("same_role") if isinstance(post_data.get("same_role"), dict) else {},
            "allergies": post_data.get("allergies") or "",
            "whatsapp_opt_in": bool(post_data.get("whatsapp_opt_in")),
        }

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

        form_payload: Dict[str, Any] = {"opposite_role": [], "whatsapp_opt_in": False}
        form_payload["allergies"] = self.get_body_argument("allergies", "").strip() or None
        form_payload["whatsapp_opt_in"] = _flag("whatsapp_opt_in")

        for idx in range(1, 4):
            name = self.get_body_argument(f"opp_name_{idx}", "").strip()
            contact = self.get_body_argument(f"opp_contact_{idx}", "").strip()
            if name and contact:
                form_payload["opposite_role"].append({"name": name, "contact": contact})

        same_name = self.get_body_argument("same_name", "").strip()
        same_contact = self.get_body_argument("same_contact", "").strip()
        if same_name and same_contact:
            form_payload["same_role"] = {"name": same_name, "contact": same_contact}

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
            opposite_raw = form_payload.get("opposite_role")
            opposite: List[Dict[str, Any]] = []
            if isinstance(opposite_raw, list):
                for raw_item in opposite_raw: # type: ignore[unused-ignore]
                    if isinstance(raw_item, dict):
                        raw_item_dict: Dict[str, Any] = cast(Dict[str, Any], raw_item)
                        opposite.append(raw_item_dict)
                    else:
                        opposite.append({})
            while len(opposite) < 3:
                opposite.append({})
            opposite = opposite[:3]
            post_prefill: Dict[str, Any] = {
                "opposite": opposite,
                "same": form_payload.get("same_role") or {},
                "allergies": form_payload.get("allergies") or "",
                "whatsapp_opt_in": bool(form_payload.get("whatsapp_opt_in")),
            }

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
        async for doc in users_cursor:
            doc_typed = cast(Document, doc)
            registrations.append({**doc_typed, "_id": str(doc_typed["_id"])})

        self.render(
            "templates/admin.html",
            invites=invites,
            registrations=registrations,
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
        await users_coll.update_one(
            {"_id": user_oid},
            {"$set": {"payment_approved": approved, "updated_at": utcnow()}},
        )
        self.redirect("/admin")


class VerifyHandler(BaseHandler):
    def get(self) -> None:
        self.render("templates/verify.html", error=None, success=None, email=self.get_argument("email", ""), code=self.get_argument("code", ""))

    async def post(self) -> None:
        email = self.get_body_argument("email", "").strip().lower()
        code = self.get_body_argument("code", "").strip().upper()
        if not email or not code:
            self.render("templates/verify.html", error="Email and code are required.", success=None, email=email, code=code)
            return

        users: Collection = self.db[self.cfg.users_collection]
        user = await users.find_one({"email_lower": email})
        if not user:
            self.render("templates/verify.html", error="User not found.", success=None, email=email, code=code)
            return

        stored_code = user.get("email_verification_code")
        expires_at = user.get("email_verification_expires_at")
        if not stored_code or stored_code != code:
            self.render("templates/verify.html", error="Invalid code.", success=None, email=email, code=code)
            return
        if expires_at and isinstance(expires_at, dt.datetime) and expires_at < utcnow():
            self.render("templates/verify.html", error="Code expired. Request a new invite.", success=None, email=email, code=code)
            return

        await users.update_one(
            {"email_lower": email},
            {
                "$set": {
                    "email_verified_at": utcnow(),
                    "email_verification_code": None,
                    "email_verification_expires_at": None,
                }
            },
        )

        self.render("templates/verify.html", error=None, success="Email verified. You can now log in.", email=email, code="")


async def create_indexes(db: Database, cfg: Settings) -> None:
    invites_coll: Collection = db[cfg.invites_collection]
    users_coll: Collection = db[cfg.users_collection]
    await invites_coll.create_index("code", unique=True)
    await users_coll.create_index("email_lower", unique=True)
    await users_coll.create_index("invite_code")


def make_app(settings: Settings) -> tornado.web.Application:
    if settings.use_in_memory_db:
        db_client = InMemoryClient()
    else:
        if not settings.mongo_url:
            raise RuntimeError("mongo_url is required when not using in-memory database.")
        db_client: AsyncIOMotorClient[Document] | InMemoryClient = AsyncIOMotorClient(settings.mongo_url)
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
        (r"/login", LoginHandler, "login"),
        (r"/logout", LogoutHandler, None),
        (r"/register/([A-Za-z0-9\\-_]+)", RegisterHandler, None),
        (r"/portal", PortalHandler, None),
        (r"/admin", AdminHandler, None),
        (r"/admin/invites", CreateInviteHandler, None),
        (r"/admin/approve/([A-Za-z0-9]+)", ApprovePaymentHandler, None),
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
