import base64
import hashlib
import io
import logging
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse
import zipfile

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx
from jose import jwt
from jose.exceptions import JWTError
from passlib.hash import argon2
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from cpanel_service import CPanelService
from models import AppPassword, DeviceSession, KnownMailbox, User, get_db, init_db


ALLOWED_DOMAINS = {"innogen-pharma.com", "innogen-pharma.ph"}
ALLOWED_RETURN_TO_HOSTS = {"innogen-pharma.com", "innogen-pharma.ph", "innogen.local"}
ALLOWED_RETURN_TO_SUFFIXES = (".innogen-pharma.com", ".innogen-pharma.ph", ".innogen.local")
DEFAULT_CORS_ORIGIN_REGEX = r"^https?://([a-z0-9-]+\.)*(innogen-pharma\.(com|ph)|innogen\.local)(:[0-9]+)?$"

logger = logging.getLogger("sso_auth")


def _configure_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        stream=sys.stdout,
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def _commit_or_503(db: AsyncSession, *, action: str) -> None:
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        logger.exception("db_commit_failed action=%s", action)
        raise HTTPException(status_code=503, detail="Database error")


def _truncate(s: str, max_len: int = 500) -> str:
    s = s or ""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "...(truncated)"


def normalize_email(email: str) -> str:
    return email.strip().lower()


def extract_domain(email: str) -> str:
    email = normalize_email(email)
    if "@" not in email:
        raise ValueError("invalid email")
    return email.split("@", 1)[1]


def ensure_company_domain(email: str) -> str:
    domain = extract_domain(email)
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Non-company domain is not allowed")
    return domain


def validate_return_to(return_to: Optional[str]) -> Optional[str]:
    if not return_to:
        return None
    try:
        parsed = urlparse(return_to)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid return_to")

    if parsed.scheme not in {"https", "http"}:
        raise HTTPException(status_code=400, detail="Invalid return_to")
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid return_to")

    allowed_host = host in ALLOWED_RETURN_TO_HOSTS or any(host.endswith(suffix) for suffix in ALLOWED_RETURN_TO_SUFFIXES)
    if not allowed_host:
        raise HTTPException(status_code=400, detail="Invalid return_to")

    if parsed.scheme == "http" and not (host == "innogen.local" or host.endswith(".innogen.local")):
        raise HTTPException(status_code=400, detail="Invalid return_to")

    return return_to


def host_parent_cookie_domain(host: str) -> Optional[str]:
    host = (host or "").split(":", 1)[0].lower()
    if host.endswith(".innogen-pharma.com") or host == "innogen-pharma.com":
        return ".innogen-pharma.com"
    if host.endswith(".innogen-pharma.ph") or host == "innogen-pharma.ph":
        return ".innogen-pharma.ph"
    return None


def cors_allowed_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def cors_allowed_origin_regex() -> str:
    return os.getenv("CORS_ALLOWED_ORIGIN_REGEX", DEFAULT_CORS_ORIGIN_REGEX)


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def device_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def new_device_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")


def get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "")
    if not secret:
        raise RuntimeError("JWT_SECRET is required")
    return secret


def sign_state(payload: dict) -> str:
    secret = get_jwt_secret()
    now = datetime.now(timezone.utc)
    claims = dict(payload or {})
    claims.setdefault("iat", int(now.timestamp()))
    claims.setdefault("exp", int((now + timedelta(minutes=10)).timestamp()))
    return jwt.encode(claims, secret, algorithm="HS256")


def verify_state(token: str) -> dict:
    secret = get_jwt_secret()
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"require_exp": True, "require_iat": True},
    )


def cookie_settings(request: Request) -> dict:
    cookie_name = os.getenv("SSO_COOKIE_NAME", "device_token")
    secure = os.getenv("SSO_COOKIE_SECURE", "true").lower() in {"1", "true", "yes"}
    raw_samesite = os.getenv("SSO_COOKIE_SAMESITE", "none").lower().strip()
    if raw_samesite not in {"lax", "strict", "none"}:
        raw_samesite = "none"
    samesite: Literal["lax", "strict", "none"] = raw_samesite  # type: ignore

    raw_max_age = os.getenv("SSO_COOKIE_MAX_AGE_SECONDS", str(60 * 60 * 24 * 30))
    try:
        max_age = int(raw_max_age)
    except ValueError:
        max_age = 60 * 60 * 24 * 30
    domain = host_parent_cookie_domain(request.headers.get("host", ""))
    return {
        "cookie_name": cookie_name,
        "secure": secure,
        "samesite": samesite,
        "max_age": max_age,
        "domain": domain,
    }


async def issue_device_session(
    *,
    request: Request,
    response: Response,
    db: AsyncSession,
    user: User,
) -> None:
    raw_token = new_device_token()
    token_hash = device_token_hash(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=cookie_settings(request)["max_age"])
    ua = request.headers.get("user-agent", "")
    ip = get_client_ip(request)
    session = DeviceSession(
        user_id=user.id,
        device_token_hash=token_hash,
        user_agent=ua,
        ip_address=ip,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(session)
    await _commit_or_503(db, action="issue_device_session")

    settings = cookie_settings(request)
    response.set_cookie(
        key=settings["cookie_name"],
        value=raw_token,
        httponly=True,
        secure=settings["secure"],
        samesite=settings["samesite"],
        max_age=settings["max_age"],
        domain=settings["domain"],
        path="/",
    )


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    settings = cookie_settings(request)
    device_token = request.cookies.get(settings["cookie_name"])
    if not device_token:
        return None

    token_hash = device_token_hash(device_token)
    ua = request.headers.get("user-agent", "")
    ip = get_client_ip(request)
    now = datetime.now(timezone.utc)

    stmt = select(DeviceSession).where(
        DeviceSession.device_token_hash == token_hash,
        DeviceSession.revoked.is_(False),
        DeviceSession.expires_at > now,
        DeviceSession.user_agent == ua,
        DeviceSession.ip_address == ip,
    )
    res = await db.execute(stmt)
    device_session = res.scalar_one_or_none()
    if not device_session:
        return None

    user_res = await db.execute(select(User).where(User.id == device_session.user_id))
    return user_res.scalar_one_or_none()


class AuthMethodResponse(BaseModel):
    email: EmailStr
    domain: str
    methods: list[str]


class CreatePasswordRequest(BaseModel):
    email: EmailStr
    password: str


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifySessionResponse(BaseModel):
    authenticated: bool
    user: Optional[dict] = None


async def get_or_create_user(*, db: AsyncSession, email: str, domain: str) -> User:
    res = await db.execute(select(User).where(User.email == email))
    user = res.scalar_one_or_none()
    if user:
        if user.domain != domain:
            user.domain = domain
            await _commit_or_503(db, action="update_user_domain")
        return user
    user = User(email=email, domain=domain)
    db.add(user)
    await _commit_or_503(db, action="create_user")
    await db.refresh(user)
    return user


async def get_known_mailbox(*, db: AsyncSession, email: str) -> Optional[KnownMailbox]:
    res = await db.execute(select(KnownMailbox).where(KnownMailbox.email == email))
    return res.scalar_one_or_none()


async def get_user_password(*, db: AsyncSession, email: str) -> tuple[Optional[User], Optional[AppPassword]]:
    user_res = await db.execute(select(User).where(User.email == email))
    user = user_res.scalar_one_or_none()
    if not user:
        return None, None

    pw_res = await db.execute(select(AppPassword).where(AppPassword.user_id == user.id))
    return user, pw_res.scalar_one_or_none()


async def record_known_mailbox(*, db: AsyncSession, email: str, domain: str, source: str = "cpanel") -> KnownMailbox:
    mailbox = await get_known_mailbox(db=db, email=email)
    if mailbox:
        mailbox.domain = domain
        mailbox.source = source
        mailbox.last_verified_at = datetime.now(timezone.utc)
        await _commit_or_503(db, action="update_known_mailbox")
        await db.refresh(mailbox)
        return mailbox

    mailbox = KnownMailbox(
        email=email,
        domain=domain,
        source=source,
        last_verified_at=datetime.now(timezone.utc),
    )
    db.add(mailbox)
    await _commit_or_503(db, action="create_known_mailbox")
    await db.refresh(mailbox)
    return mailbox


async def ensure_known_ph_mailbox(*, db: AsyncSession, email: str) -> bool:
    email_norm = normalize_email(email)
    domain = ensure_company_domain(email_norm)
    if domain != "innogen-pharma.ph":
        raise HTTPException(status_code=400, detail="Mailbox cache is only for innogen-pharma.ph")

    mailbox = await get_known_mailbox(db=db, email=email_norm)
    if mailbox:
        return True

    svc = CPanelService.from_env()
    try:
        exists = await svc.mailbox_exists(email=email_norm, domain=domain)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if exists:
        await record_known_mailbox(db=db, email=email_norm, domain=domain, source="cpanel")
    return exists


async def exchange_google_code(*, code: str, redirect_uri: str) -> dict:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise RuntimeError("Google OAuth is not configured")

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            logger.warning("google_token_exchange_timeout")
            raise HTTPException(status_code=503, detail="Google token exchange timed out") from exc
        except httpx.HTTPStatusError as exc:
            body = _truncate(exc.response.text)
            logger.warning("google_token_exchange_failed status=%s body=%s", exc.response.status_code, body)
            raise HTTPException(status_code=502, detail="Google token exchange failed") from exc
        except httpx.RequestError as exc:
            logger.warning("google_token_exchange_request_error error=%s", str(exc))
            raise HTTPException(status_code=503, detail="Google token exchange unavailable") from exc


async def validate_google_id_token(*, id_token: str) -> dict:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": id_token})
            resp.raise_for_status()
            claims = resp.json()
        except httpx.TimeoutException as exc:
            logger.warning("google_tokeninfo_timeout")
            raise HTTPException(status_code=503, detail="Google token validation timed out") from exc
        except httpx.HTTPStatusError as exc:
            body = _truncate(exc.response.text)
            logger.warning("google_tokeninfo_failed status=%s body=%s", exc.response.status_code, body)
            raise HTTPException(status_code=401, detail="Invalid Google token") from exc
        except httpx.RequestError as exc:
            logger.warning("google_tokeninfo_request_error error=%s", str(exc))
            raise HTTPException(status_code=503, detail="Google token validation unavailable") from exc
    if claims.get("aud") != client_id:
        raise HTTPException(status_code=401, detail="Invalid Google token audience")
    if claims.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}:
        raise HTTPException(status_code=401, detail="Invalid Google token issuer")
    if claims.get("email_verified") not in {True, "true", "True", "1"}:
        raise HTTPException(status_code=401, detail="Google email is not verified")
    return claims


_apple_jwks_cache: dict = {"fetched_at": None, "keys": None}


async def get_apple_jwks() -> dict:
    now = datetime.now(timezone.utc)
    fetched_at = _apple_jwks_cache.get("fetched_at")
    keys = _apple_jwks_cache.get("keys")
    if fetched_at and keys and (now - fetched_at) < timedelta(hours=6):
        return keys
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get("https://appleid.apple.com/auth/keys")
        resp.raise_for_status()
        keys = resp.json()
    _apple_jwks_cache["fetched_at"] = now
    _apple_jwks_cache["keys"] = keys
    return keys


async def validate_apple_id_token(*, id_token: str) -> dict:
    client_id = os.getenv("APPLE_CLIENT_ID", "")
    if not client_id:
        raise RuntimeError("Apple OAuth is not configured")

    try:
        header = jwt.get_unverified_header(id_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Apple token")

    kid = header.get("kid")
    jwks = await get_apple_jwks()
    keys = jwks.get("keys") or []
    key = next((k for k in keys if k.get("kid") == kid), None)
    if not key:
        raise HTTPException(status_code=401, detail="Apple signing key not found")

    try:
        return jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=client_id,
            issuer="https://appleid.apple.com",
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Apple token")


def apple_client_secret() -> str:
    team_id = os.getenv("APPLE_TEAM_ID", "")
    client_id = os.getenv("APPLE_CLIENT_ID", "")
    key_id = os.getenv("APPLE_KEY_ID", "")
    private_key = os.getenv("APPLE_PRIVATE_KEY", "")
    if not team_id or not client_id or not key_id or not private_key:
        raise RuntimeError("Apple OAuth is not configured")
    private_key = private_key.replace("\\n", "\n")
    now = datetime.now(timezone.utc)
    claims = {
        "iss": team_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    }
    return jwt.encode(claims, private_key, algorithm="ES256", headers={"kid": key_id})


async def exchange_apple_code(*, code: str, redirect_uri: str) -> dict:
    client_id = os.getenv("APPLE_CLIENT_ID", "")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            "https://appleid.apple.com/auth/token",
            data={
                "client_id": client_id,
                "client_secret": apple_client_secret(),
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()


app = FastAPI(title="Innogen Pharma Universal SSO Provider", version="1.0.0")

_STATIC_SITE_DIR = Path(__file__).resolve().parent / "static_site"
if _STATIC_SITE_DIR.exists():
    app.mount("/demo-assets/static", StaticFiles(directory=str(_STATIC_SITE_DIR)), name="demo-assets-static")

_STATIC_DIR = Path(__file__).resolve().parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/demo.html", include_in_schema=False)
async def demo_html() -> Response:
    path = _STATIC_SITE_DIR / "demo.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path)


@app.get("/login", include_in_schema=False)
async def login_html() -> Response:
    path = _STATIC_SITE_DIR / "login.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path)


@app.get("/callback", include_in_schema=False)
async def callback_html() -> Response:
    path = _STATIC_SITE_DIR / "callback.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path)


@app.get("/demo-login.html", include_in_schema=False)
async def demo_login_html() -> Response:
    return RedirectResponse("/login", status_code=302)


@app.get("/demo-callback.html", include_in_schema=False)
async def demo_callback_html() -> Response:
    return RedirectResponse("/callback", status_code=302)


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=cors_allowed_origin_regex(),
)


@app.on_event("startup")
async def _startup() -> None:
    _configure_logging()
    if os.getenv("SQLALCHEMY_CREATE_TABLES", "true").lower() in {"1", "true", "yes"}:
        await init_db()


@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    try:
        await db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.exception("health_db_check_failed")
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"ok": True, "db": "ok"}


@app.get("/demo-assets/other-app-template.zip", include_in_schema=False)
async def other_app_template_zip() -> Response:
    template_dir = _STATIC_SITE_DIR / "other_app_template"
    if not template_dir.exists() or not template_dir.is_dir():
        raise HTTPException(status_code=404, detail="Not found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in template_dir.rglob("*"):
            if p.is_dir():
                continue
            zf.write(p, arcname=str(p.relative_to(template_dir)))

    buf.seek(0)
    headers = {"content-disposition": "attachment; filename=other-app-template.zip"}
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


@app.get("/api/v1/auth/method", response_model=AuthMethodResponse)
async def auth_method(email: EmailStr) -> AuthMethodResponse:
    domain = ensure_company_domain(str(email))
    if domain == "innogen-pharma.com":
        methods = ["google", "apple"]
    else:
        methods = ["cpanel_password"]
    return AuthMethodResponse(email=email, domain=domain, methods=methods)


@app.get("/api/v1/cpanel/mailbox-exists")
async def cpanel_mailbox_exists(email: EmailStr, db: AsyncSession = Depends(get_db)) -> dict:
    email_norm = normalize_email(str(email))
    domain = ensure_company_domain(email_norm)
    if domain != "innogen-pharma.ph":
        raise HTTPException(status_code=400, detail="cPanel mailbox check is only for innogen-pharma.ph")
    exists = await ensure_known_ph_mailbox(db=db, email=email_norm)
    return {"exists": exists}


@app.get("/api/v1/auth/password/status")
async def password_status(email: EmailStr, db: AsyncSession = Depends(get_db)) -> dict:
    email_norm = normalize_email(str(email))
    domain = ensure_company_domain(email_norm)
    if domain != "innogen-pharma.ph":
        raise HTTPException(status_code=400, detail="Password status is only for innogen-pharma.ph")

    user, pw = await get_user_password(db=db, email=email_norm)
    if pw:
        return {"has_password": True}

    if not user:
        if not await ensure_known_ph_mailbox(db=db, email=email_norm):
            return {"has_password": False}
        return {"has_password": False}

    if not await ensure_known_ph_mailbox(db=db, email=email_norm):
        return {"has_password": False}
    return {"has_password": False}


@app.post("/api/v1/auth/password/create")
async def create_password(payload: CreatePasswordRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    email = normalize_email(str(payload.email))
    domain = ensure_company_domain(email)
    if domain != "innogen-pharma.ph":
        raise HTTPException(status_code=400, detail="App password is only for innogen-pharma.ph")

    existing_user, existing_pw = await get_user_password(db=db, email=email)
    if existing_pw:
        raise HTTPException(status_code=409, detail="Password already exists")

    if not await ensure_known_ph_mailbox(db=db, email=email):
        raise HTTPException(status_code=404, detail="Mailbox does not exist")

    user = existing_user
    if not user:
        user = User(email=email, domain=domain)
        db.add(user)
        await db.flush()

    pw = AppPassword(user_id=user.id, password_hash=argon2.hash(payload.password))
    db.add(pw)
    await _commit_or_503(db, action="create_app_password")

    await issue_device_session(request=request, response=response, db=db, user=user)
    return {"ok": True}


@app.post("/api/v1/auth/password/login")
async def password_login(payload: PasswordLoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    email = normalize_email(str(payload.email))
    domain = ensure_company_domain(email)
    if domain != "innogen-pharma.ph":
        raise HTTPException(status_code=400, detail="Password login is only for innogen-pharma.ph")

    user_res = await db.execute(select(User).where(User.email == email))
    user = user_res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_res = await db.execute(select(AppPassword).where(AppPassword.user_id == user.id))
    pw = pw_res.scalar_one_or_none()
    try:
        ok = bool(pw) and argon2.verify(payload.password, pw.password_hash)
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await issue_device_session(request=request, response=response, db=db, user=user)
    return {"ok": True}


@app.get("/api/v1/verify-session", response_model=VerifySessionResponse)
async def verify_session(user: Optional[User] = Depends(get_current_user)) -> VerifySessionResponse:
    if not user:
        return VerifySessionResponse(authenticated=False, user=None)
    return VerifySessionResponse(authenticated=True, user={"email": user.email, "domain": user.domain})


@app.get("/api/v1/oauth/google/start")
async def google_start(email: EmailStr, request: Request, return_to: Optional[str] = None) -> RedirectResponse:
    email_norm = normalize_email(str(email))
    domain = ensure_company_domain(email_norm)
    if domain != "innogen-pharma.com":
        raise HTTPException(status_code=403, detail="Google OAuth is only for innogen-pharma.com")

    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured")

    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or str(request.url_for("google_callback"))
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp())
    state = sign_state({"provider": "google", "email": email_norm, "return_to": validate_return_to(return_to), "exp": exp})

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "login_hint": email_norm,
        "hd": "innogen-pharma.com",
        "prompt": "select_account",
    }
    url = httpx.URL("https://accounts.google.com/o/oauth2/v2/auth").copy_merge_params(params)
    return RedirectResponse(str(url), status_code=302)


@app.get("/api/v1/oauth/google/callback", name="google_callback")
async def google_callback(
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    try:
        state_payload = verify_state(state)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid OAuth state")

    if state_payload.get("provider") != "google":
        raise HTTPException(status_code=401, detail="Invalid OAuth state")

    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or str(request.url_for("google_callback"))
    token_payload = await exchange_google_code(code=code, redirect_uri=redirect_uri)
    id_token = token_payload.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise HTTPException(status_code=401, detail="Missing Google id_token")

    claims = await validate_google_id_token(id_token=id_token)
    email = normalize_email(claims.get("email") or "")
    if not email:
        raise HTTPException(status_code=401, detail="Missing email claim")
    domain = ensure_company_domain(email)
    if domain != "innogen-pharma.com":
        raise HTTPException(status_code=403, detail="Non-company domain is not allowed")

    expected_email = normalize_email(state_payload.get("email") or "")
    if expected_email and expected_email != email:
        raise HTTPException(status_code=401, detail="OAuth email mismatch")

    user = await get_or_create_user(db=db, email=email, domain=domain)
    return_to = state_payload.get("return_to")
    if isinstance(return_to, str) and return_to:
        resp: Response = RedirectResponse(return_to, status_code=302)
    else:
        resp = JSONResponse({"ok": True, "email": user.email, "domain": user.domain})

    await issue_device_session(request=request, response=resp, db=db, user=user)
    return resp


@app.get("/api/v1/oauth/apple/start")
async def apple_start(request: Request, email: Optional[EmailStr] = None, return_to: Optional[str] = None) -> RedirectResponse:
    email_norm = normalize_email(str(email)) if email else None
    if email_norm:
        ensure_company_domain(email_norm)

    client_id = os.getenv("APPLE_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(status_code=500, detail="Apple OAuth is not configured")

    redirect_uri = os.getenv("APPLE_REDIRECT_URI") or str(request.url_for("apple_callback"))
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp())
    state = sign_state({"provider": "apple", "email": email_norm, "return_to": validate_return_to(return_to), "exp": exp})

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code id_token",
        "scope": "email",
        "response_mode": "form_post",
        "state": state,
    }
    url = httpx.URL("https://appleid.apple.com/auth/authorize").copy_merge_params(params)
    return RedirectResponse(str(url), status_code=302)


@app.api_route("/api/v1/oauth/apple/callback", methods=["GET", "POST"], name="apple_callback")
async def apple_callback(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    if request.method == "POST":
        form = await request.form()
        code = form.get("code")
        state = form.get("state")
        id_token = form.get("id_token")
    else:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        id_token = request.query_params.get("id_token")

    if not isinstance(code, str) or not code:
        raise HTTPException(status_code=400, detail="Missing Apple code")
    if not isinstance(state, str) or not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")

    try:
        state_payload = verify_state(state)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid OAuth state")

    if state_payload.get("provider") != "apple":
        raise HTTPException(status_code=401, detail="Invalid OAuth state")

    redirect_uri = os.getenv("APPLE_REDIRECT_URI") or str(request.url_for("apple_callback"))

    if not isinstance(id_token, str) or not id_token:
        token_payload = await exchange_apple_code(code=code, redirect_uri=redirect_uri)
        id_token = token_payload.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise HTTPException(status_code=401, detail="Missing Apple id_token")

    claims = await validate_apple_id_token(id_token=id_token)
    email = normalize_email(claims.get("email") or "")
    if not email:
        raise HTTPException(status_code=401, detail="Missing email claim")
    domain = ensure_company_domain(email)

    expected_email = normalize_email(state_payload.get("email") or "")
    if expected_email and expected_email != email:
        raise HTTPException(status_code=401, detail="OAuth email mismatch")

    user = await get_or_create_user(db=db, email=email, domain=domain)
    return_to = state_payload.get("return_to")
    if isinstance(return_to, str) and return_to:
        resp: Response = RedirectResponse(return_to, status_code=302)
    else:
        resp = JSONResponse({"ok": True, "email": user.email, "domain": user.domain})

    await issue_device_session(request=request, response=resp, db=db, user=user)
    return resp

