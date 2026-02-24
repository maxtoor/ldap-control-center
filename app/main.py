import os
import re
import secrets
import subprocess
import hmac
import hashlib
import base64
import smtplib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Dict, List, Optional
from urllib.parse import quote_plus
from email.message import EmailMessage

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.ldap_client import LDAPClient

APP_TITLE = os.getenv("APP_TITLE", "LDAP Control Center")
APP_SUBTITLE = os.getenv("APP_SUBTITLE", "Gestione utenti su OpenLDAP").strip() or "Gestione utenti su OpenLDAP"
APP_COMPANY = os.getenv("APP_COMPANY", "Emilio Paolo Castelluccio").strip() or "Emilio Paolo Castelluccio"
APP_LOGO_URL = os.getenv("APP_LOGO_URL", "").strip()
APP_LOGO_LINK = os.getenv("APP_LOGO_LINK", "/").strip() or "/"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_GROUPS_FILTER = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
IMPORT_TIMEOUT_SECONDS = int(os.getenv("LEGACY_IMPORT_TIMEOUT_SECONDS", "600"))

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["app_title"] = APP_TITLE
templates.env.globals["app_subtitle"] = APP_SUBTITLE
templates.env.globals["app_company"] = APP_COMPANY
templates.env.globals["app_logo_url"] = APP_LOGO_URL
templates.env.globals["app_logo_link"] = APP_LOGO_LINK
ldap_client = LDAPClient()
logger = logging.getLogger("ldapcc")
PASSWORD_RESET_TTL_MINUTES = int(os.getenv("PASSWORD_RESET_TTL_MINUTES", "30"))
PASSWORD_RESET_BASE_URL = os.getenv("PASSWORD_RESET_BASE_URL", "").strip()
PASSWORD_RESET_SHOW_LINK = os.getenv("PASSWORD_RESET_SHOW_LINK", "false").lower() in {"1", "true", "yes", "on"}
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes", "on"}
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", APP_TITLE).strip() or APP_TITLE
SMTP_RESET_SUBJECT = os.getenv("SMTP_RESET_SUBJECT", "Reset password account LDAP").strip() or "Reset password account LDAP"
PREFERENCE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365
USERS_PAGE_SIZE_COOKIE = "users_page_size"
GROUPS_PAGE_SIZE_COOKIE = "groups_page_size"
AUTH_SESSION_COOKIE = "ldapcc_session"
AUTH_SESSION_TTL_HOURS = int(os.getenv("APP_SESSION_TTL_HOURS", "12"))
AUTH_USERNAME = os.getenv("APP_ADMIN_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("APP_ADMIN_PASSWORD", "admin")
AUTH_SESSION_SECRET = os.getenv("APP_SESSION_SECRET", "change-this-session-secret")
AUTH_PUBLIC_PATH_PREFIXES = ("/static", "/login", "/password/forgot", "/password/reset")


@dataclass
class PasswordResetToken:
    uid: str
    expires_at: datetime


password_reset_tokens: Dict[str, PasswordResetToken] = {}


@app.on_event("startup")
def startup_event() -> None:
    ldap_client.ensure_users_ou()
    ldap_client.ensure_groups_ou()


def _matches_query(values: List[str], query: str) -> bool:
    normalized_query = query.strip().lower()
    if not normalized_query:
        return True
    return any(normalized_query in (value or "").lower() for value in values)


def _redirect_to(
    path: str,
    message: Optional[str] = None,
    error: Optional[str] = None,
    q: str = "",
    page: int = 1,
    page_size: Optional[int] = None,
):
    params = []
    if message:
        params.append(f"message={quote_plus(message)}")
    if error:
        params.append(f"error={quote_plus(error)}")
    if q:
        params.append(f"q={quote_plus(q)}")
    if page > 1:
        params.append(f"page={page}")
    if page_size:
        params.append(f"page_size={page_size}")
    suffix = f"?{'&'.join(params)}" if params else ""
    return RedirectResponse(url=f"{path}{suffix}", status_code=303)


def _paginate(items: List[object], page: int, page_size: int) -> tuple[List[object], int, int]:
    total = len(items)
    total_pages = max(1, ceil(total / page_size)) if total else 1
    current_page = min(max(1, page), total_pages)
    start = (current_page - 1) * page_size
    end = start + page_size
    return items[start:end], current_page, total_pages


def _normalize_page_size(page_size: int, allowed: List[int], default: int) -> int:
    return page_size if page_size in allowed else default


def _get_cookie_int(request: Request, key: str) -> Optional[int]:
    raw_value = request.cookies.get(key)
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _resolve_page_size(
    request: Request,
    page_size: Optional[int],
    allowed: List[int],
    default: int,
    cookie_key: str,
) -> int:
    if page_size is not None:
        return _normalize_page_size(page_size, allowed, default)
    cookie_value = _get_cookie_int(request, cookie_key)
    if cookie_value is not None:
        return _normalize_page_size(cookie_value, allowed, default)
    return default


def _normalize_member_uid_input(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    # Supporta input da datalist in formato "Cognome Nome (uid)".
    match = re.search(r"\(([^()]+)\)\s*$", raw)
    if match:
        candidate = match.group(1).strip()
        if candidate:
            return candidate
    return raw


def _prune_password_reset_tokens() -> None:
    now = datetime.now(timezone.utc)
    expired = [token for token, data in password_reset_tokens.items() if data.expires_at <= now]
    for token in expired:
        del password_reset_tokens[token]


def _create_password_reset_token(uid: str) -> str:
    _prune_password_reset_tokens()
    token = secrets.token_urlsafe(32)
    password_reset_tokens[token] = PasswordResetToken(
        uid=uid,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TTL_MINUTES),
    )
    return token


def _get_password_reset_uid(token: str) -> Optional[str]:
    _prune_password_reset_tokens()
    data = password_reset_tokens.get(token)
    if not data:
        return None
    return data.uid


def _consume_password_reset_token(token: str) -> None:
    password_reset_tokens.pop(token, None)


def _build_reset_link(request: Request, token: str) -> str:
    if PASSWORD_RESET_BASE_URL:
        return f"{PASSWORD_RESET_BASE_URL.rstrip('/')}/password/reset/{token}"
    return str(request.url_for("password_reset_page", token=token))


def _smtp_is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def _send_password_reset_email(recipient_email: str, recipient_label: str, reset_link: str) -> None:
    if not _smtp_is_configured():
        raise RuntimeError("SMTP non configurato (SMTP_HOST/SMTP_FROM_EMAIL mancanti).")
    if SMTP_USE_TLS and SMTP_USE_SSL:
        raise RuntimeError("Configurazione SMTP non valida: SMTP_USE_TLS e SMTP_USE_SSL non possono essere entrambi attivi.")

    msg = EmailMessage()
    msg["Subject"] = SMTP_RESET_SUBJECT
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = recipient_email
    msg.set_content(
        "\n".join(
            [
                f"Ciao {recipient_label},",
                "",
                "hai richiesto la reimpostazione della password del tuo account LDAP.",
                f"Link reset (valido {PASSWORD_RESET_TTL_MINUTES} minuti):",
                reset_link,
                "",
                "Se non hai richiesto tu questa operazione, ignora questa email.",
            ]
        )
    )

    smtp_class = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
    with smtp_class(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        if SMTP_USE_TLS and not SMTP_USE_SSL:
            server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def _safe_next_path(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/users"
    return candidate


def _sign_session_payload(payload: str) -> str:
    return hmac.new(
        AUTH_SESSION_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _create_session_token(username: str) -> str:
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=AUTH_SESSION_TTL_HOURS)).timestamp())
    payload = f"{username}:{expires_at}"
    signature = _sign_session_payload(payload)
    raw = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _get_authenticated_username(request: Request) -> Optional[str]:
    token = request.cookies.get(AUTH_SESSION_COOKIE, "")
    if not token:
        return None

    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
    except Exception:
        return None

    parts = decoded.split(":")
    if len(parts) != 3:
        return None
    username, expires_raw, signature = parts
    if not username:
        return None

    expected_signature = _sign_session_payload(f"{username}:{expires_raw}")
    if not hmac.compare_digest(signature, expected_signature):
        return None

    try:
        expires_at = int(expires_raw)
    except ValueError:
        return None
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if expires_at <= now_ts:
        return None

    if username != AUTH_USERNAME:
        return None
    return username


def _is_authenticated_request(request: Request) -> bool:
    return _get_authenticated_username(request) is not None


templates.env.globals["is_authenticated_request"] = _is_authenticated_request


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if any(path.startswith(prefix) for prefix in AUTH_PUBLIC_PATH_PREFIXES):
        return await call_next(request)

    if _is_authenticated_request(request):
        return await call_next(request)

    next_target = request.url.path
    if request.url.query:
        next_target = f"{next_target}?{request.url.query}"
    return RedirectResponse(url=f"/login?next={quote_plus(next_target)}", status_code=303)


@app.get("/login")
def login_page(request: Request, error: Optional[str] = None, next: str = "/users"):
    if _is_authenticated_request(request):
        return RedirectResponse(url=_safe_next_path(next), status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": error,
            "next": _safe_next_path(next),
        },
    )


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/users")):
    if not hmac.compare_digest(username.strip(), AUTH_USERNAME) or not hmac.compare_digest(password, AUTH_PASSWORD):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Credenziali non valide.",
                "next": _safe_next_path(next),
            },
        )

    response = RedirectResponse(url=_safe_next_path(next), status_code=303)
    response.set_cookie(
        key=AUTH_SESSION_COOKIE,
        value=_create_session_token(AUTH_USERNAME),
        max_age=AUTH_SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(AUTH_SESSION_COOKIE)
    return response


@app.get("/")
def home():
    return RedirectResponse(url="/users", status_code=303)


@app.get("/users")
def users_page(
    request: Request,
    message: Optional[str] = None,
    error: Optional[str] = None,
    q: str = "",
    page: int = 1,
    page_size: Optional[int] = None,
):
    page_size_options = [10, 25, 50, 100]
    page_size = _resolve_page_size(
        request=request,
        page_size=page_size,
        allowed=page_size_options,
        default=25,
        cookie_key=USERS_PAGE_SIZE_COOKIE,
    )
    users = ldap_client.list_users()
    groups = ldap_client.list_groups()
    groups_by_user_uid: Dict[str, List[str]] = {}
    for group in groups:
        for member_uid in group.members:
            groups_by_user_uid.setdefault(member_uid, []).append(group.cn)
    for member_uid in list(groups_by_user_uid.keys()):
        groups_by_user_uid[member_uid] = sorted(set(groups_by_user_uid[member_uid]), key=str.lower)

    group_choices = sorted({g.cn for g in groups}, key=str.lower)
    filtered_users = [
        u
        for u in users
        if _matches_query(
            [
                u.uid,
                u.cn,
                u.sn,
                u.mail,
                u.given_name,
                u.display_name,
                u.telephone_number,
                u.mobile,
                u.personal_email,
                u.employee_type,
                u.user_status,
                u.employment_start,
                u.employment_end,
                u.office_name,
                u.title,
                u.notes,
            ],
            q,
        )
    ]
    page_users, current_page, total_pages = _paginate(filtered_users, page, page_size=page_size)
    response = templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "users": page_users,
            "total_users": len(filtered_users),
            "current_page": current_page,
            "total_pages": total_pages,
            "message": message,
            "error": error,
            "q": q,
            "groups_by_user_uid": groups_by_user_uid,
            "group_choices": group_choices,
            "page_size": page_size,
            "page_size_options": page_size_options,
            "active_page": "users",
            "active_subpage": "users_list",
        },
    )
    response.set_cookie(
        key=USERS_PAGE_SIZE_COOKIE,
        value=str(page_size),
        max_age=PREFERENCE_COOKIE_MAX_AGE,
        samesite="lax",
    )
    return response


@app.get("/users/new")
def users_new_page(
    request: Request,
    message: Optional[str] = None,
    error: Optional[str] = None,
):
    return templates.TemplateResponse(
        request=request,
        name="users_new.html",
        context={
            "message": message,
            "error": error,
            "active_page": "users",
            "active_subpage": "users_new",
        },
    )


@app.get("/groups")
def groups_page(
    request: Request,
    message: Optional[str] = None,
    error: Optional[str] = None,
    q: str = "",
    page: int = 1,
    page_size: Optional[int] = None,
):
    page_size_options = [10, 25, 50, 100]
    page_size = _resolve_page_size(
        request=request,
        page_size=page_size,
        allowed=page_size_options,
        default=25,
        cookie_key=GROUPS_PAGE_SIZE_COOKIE,
    )
    groups = ldap_client.list_groups()
    users = ldap_client.list_users()
    member_cn_by_uid = {u.uid: u.cn for u in users}
    member_name_by_uid = {
        u.uid: " ".join(part for part in [u.sn, u.given_name] if part).strip() or u.cn or u.uid
        for u in users
    }
    member_sort_key_by_uid = {u.uid: ((u.sn or "").lower(), (u.given_name or "").lower(), (u.uid or "").lower()) for u in users}
    users_for_member_suggestions = sorted(
        users,
        key=lambda u: ((u.sn or "").lower(), (u.given_name or "").lower(), (u.uid or "").lower()),
    )
    sorted_group_members_by_cn = {
        g.cn: sorted(g.members, key=lambda uid: member_sort_key_by_uid.get(uid, ("", "", uid.lower())))
        for g in groups
    }
    filtered_groups = [g for g in groups if _matches_query([g.cn, g.description, " ".join(g.members)], q)]
    page_groups, current_page, total_pages = _paginate(filtered_groups, page, page_size=page_size)
    response = templates.TemplateResponse(
        request=request,
        name="groups.html",
        context={
            "groups": page_groups,
            "total_groups": len(filtered_groups),
            "current_page": current_page,
            "total_pages": total_pages,
            "message": message,
            "error": error,
            "q": q,
            "member_cn_by_uid": member_cn_by_uid,
            "member_name_by_uid": member_name_by_uid,
            "sorted_group_members_by_cn": sorted_group_members_by_cn,
            "users_for_member_suggestions": users_for_member_suggestions,
            "page_size": page_size,
            "page_size_options": page_size_options,
            "active_page": "groups",
            "active_subpage": "groups_list",
        },
    )
    response.set_cookie(
        key=GROUPS_PAGE_SIZE_COOKIE,
        value=str(page_size),
        max_age=PREFERENCE_COOKIE_MAX_AGE,
        samesite="lax",
    )
    return response


@app.get("/groups/new")
def groups_new_page(
    request: Request,
    message: Optional[str] = None,
    error: Optional[str] = None,
):
    return templates.TemplateResponse(
        request=request,
        name="groups_new.html",
        context={
            "message": message,
            "error": error,
            "active_page": "groups",
            "active_subpage": "groups_new",
        },
    )


@app.get("/utilities")
def utilities_page(
    request: Request,
    dry_run: bool = True,
    include_groups: bool = False,
    debug_groups: bool = False,
    groups_filter: str = DEFAULT_GROUPS_FILTER,
    command: Optional[str] = None,
    output: Optional[str] = None,
    exit_code: Optional[int] = None,
):
    return templates.TemplateResponse(
        request=request,
        name="utilities.html",
        context={
            "active_page": "utilities",
            "dry_run": dry_run,
            "include_groups": include_groups,
            "debug_groups": debug_groups,
            "groups_filter": groups_filter,
            "command": command,
            "output": output,
            "exit_code": exit_code,
            "timeout_seconds": IMPORT_TIMEOUT_SECONDS,
        },
    )


@app.post("/utilities/import-legacy")
def utility_import_legacy(
    request: Request,
    dry_run: bool = Form(False),
    include_groups: bool = Form(False),
    debug_groups: bool = Form(False),
    groups_filter: str = Form(DEFAULT_GROUPS_FILTER),
):
    use_groups = include_groups or debug_groups
    command_parts = ["python", "scripts/import_from_legacy.py"]
    if dry_run:
        command_parts.append("--dry-run")
    if use_groups:
        command_parts.append("--include-groups")
        if groups_filter.strip():
            command_parts.extend(["--groups-filter", groups_filter.strip()])
        if debug_groups:
            command_parts.append("--debug-groups")

    try:
        result = subprocess.run(
            command_parts,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=IMPORT_TIMEOUT_SECONDS,
            check=False,
        )
        output_chunks = []
        if result.stdout:
            output_chunks.append(result.stdout.strip())
        if result.stderr:
            output_chunks.append(result.stderr.strip())
        output_text = "\n\n".join(chunk for chunk in output_chunks if chunk).strip() or "(nessun output)"
        if len(output_text) > 20000:
            output_text = output_text[-20000:]
            output_text = "(output troncato alle ultime 20000 battute)\n\n" + output_text

        return templates.TemplateResponse(
            request=request,
            name="utilities.html",
            context={
                "active_page": "utilities",
                "dry_run": dry_run,
                "include_groups": use_groups,
                "debug_groups": debug_groups,
                "groups_filter": groups_filter,
                "command": " ".join(command_parts),
                "output": output_text,
                "exit_code": result.returncode,
                "timeout_seconds": IMPORT_TIMEOUT_SECONDS,
                "message": "Import completato." if result.returncode == 0 else None,
                "error": None if result.returncode == 0 else "Il comando ha restituito un errore.",
            },
        )
    except subprocess.TimeoutExpired as exc:
        return templates.TemplateResponse(
            request=request,
            name="utilities.html",
            context={
                "active_page": "utilities",
                "dry_run": dry_run,
                "include_groups": use_groups,
                "debug_groups": debug_groups,
                "groups_filter": groups_filter,
                "command": " ".join(command_parts),
                "output": (exc.stdout or "") + ("\n\n" + exc.stderr if exc.stderr else ""),
                "exit_code": None,
                "timeout_seconds": IMPORT_TIMEOUT_SECONDS,
                "error": f"Timeout superato dopo {IMPORT_TIMEOUT_SECONDS} secondi.",
            },
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request=request,
            name="utilities.html",
            context={
                "active_page": "utilities",
                "dry_run": dry_run,
                "include_groups": use_groups,
                "debug_groups": debug_groups,
                "groups_filter": groups_filter,
                "command": " ".join(command_parts),
                "output": None,
                "exit_code": None,
                "error": f"Errore durante esecuzione: {exc}",
            },
        )


@app.post("/users")
def create_user(
    uid: str = Form(...),
    sn: str = Form(...),
    mail: str = Form(...),
    password: str = Form(...),
    given_name: str = Form(...),
    telephone_number: str = Form(""),
    mobile: str = Form(""),
    employee_type: str = Form(""),
    user_status: str = Form(""),
    employment_start: str = Form(""),
    employment_end: str = Form(""),
    personal_email: str = Form(""),
    office_name: str = Form(""),
    title: str = Form(""),
    notes: str = Form(""),
):
    try:
        ldap_client.create_user(
            uid=uid,
            sn=sn,
            mail=mail,
            password=password,
            given_name=given_name,
            telephone_number=telephone_number,
            mobile=mobile,
            employee_type=employee_type,
            user_status=user_status,
            employment_start=employment_start,
            employment_end=employment_end,
            personal_email=personal_email,
            office_name=office_name,
            title=title,
            notes=notes,
        )
        return _redirect_to("/users", message="Utente creato")
    except Exception as exc:
        return _redirect_to("/users/new", error=str(exc))


@app.get("/users/{uid}/edit")
def edit_user_page(
    uid: str,
    request: Request,
    message: Optional[str] = None,
    error: Optional[str] = None,
    q: str = "",
    page: int = 1,
    page_size: Optional[int] = None,
):
    page_size = _resolve_page_size(
        request=request,
        page_size=page_size,
        allowed=[10, 25, 50, 100],
        default=25,
        cookie_key=USERS_PAGE_SIZE_COOKIE,
    )
    try:
        user = ldap_client.get_user(uid)
    except Exception as exc:
        return _redirect_to("/users", error=str(exc), q=q, page=page)

    return templates.TemplateResponse(
        request=request,
        name="users_edit.html",
        context={
            "user": user,
            "message": message,
            "error": error,
            "q": q,
            "page": page,
            "page_size": page_size,
            "active_page": "users",
            "active_subpage": "users_edit",
        },
    )


@app.post("/users/{uid}/edit")
def edit_user(
    uid: str,
    sn: str = Form(...),
    mail: str = Form(...),
    given_name: str = Form(...),
    telephone_number: str = Form(""),
    mobile: str = Form(""),
    employee_type: str = Form(""),
    user_status: str = Form(""),
    employment_start: str = Form(""),
    employment_end: str = Form(""),
    personal_email: str = Form(""),
    office_name: str = Form(""),
    title: str = Form(""),
    notes: str = Form(""),
    q: str = Form(""),
    page: int = Form(1),
    page_size: int = Form(25),
):
    try:
        ldap_client.update_user(
            uid=uid,
            sn=sn,
            mail=mail,
            given_name=given_name,
            telephone_number=telephone_number,
            mobile=mobile,
            employee_type=employee_type,
            user_status=user_status,
            employment_start=employment_start,
            employment_end=employment_end,
            personal_email=personal_email,
            office_name=office_name,
            title=title,
            notes=notes,
        )
        return _redirect_to("/users", message="Utente aggiornato", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to(f"/users/{uid}/edit", error=str(exc), q=q, page=page, page_size=page_size)


@app.get("/password/forgot")
def password_forgot_page(request: Request, message: Optional[str] = None, error: Optional[str] = None):
    return templates.TemplateResponse(
        request=request,
        name="password_forgot.html",
        context={"message": message, "error": error, "active_page": "password"},
    )


@app.post("/password/forgot")
def password_forgot_submit(request: Request, identifier: str = Form(...)):
    identifier_clean = identifier.strip()
    if not identifier_clean:
        return templates.TemplateResponse(
            request=request,
            name="password_forgot.html",
            context={
                "error": "Inserisci nome utente o email istituzionale.",
                "active_page": "password",
            },
        )

    uid = ldap_client.find_user_uid_by_identifier(identifier_clean)
    generated_link = None
    if uid:
        token = _create_password_reset_token(uid)
        reset_link = _build_reset_link(request, token)
        try:
            user = ldap_client.get_user(uid)
            recipient_email = (user.mail or "").strip()
            recipient_full_name = " ".join(part for part in [user.given_name, user.sn] if (part or "").strip()).strip()
            if not recipient_full_name:
                cn_value = (user.cn or "").strip()
                recipient_full_name = cn_value if cn_value and cn_value != uid else ""
            recipient_label = f"{recipient_full_name} ({uid})" if recipient_full_name else uid
            if recipient_email:
                _send_password_reset_email(recipient_email=recipient_email, recipient_label=recipient_label, reset_link=reset_link)
                logger.warning("[PASSWORD_RESET_EMAIL_SENT] uid=%s to=%s", uid, recipient_email)
            else:
                logger.warning("[PASSWORD_RESET_EMAIL_SKIPPED] uid=%s motivo=email mancante", uid)
        except Exception as exc:
            logger.error("[PASSWORD_RESET_EMAIL_ERROR] uid=%s error=%s", uid, exc)

        if PASSWORD_RESET_SHOW_LINK:
            generated_link = reset_link
            logger.warning("[PASSWORD_RESET_LINK] uid=%s link=%s", uid, generated_link)
    else:
        logger.warning("[PASSWORD_RESET_IGNORED] identifier_non_trovato=%s", identifier_clean)

    return templates.TemplateResponse(
        request=request,
        name="password_forgot.html",
        context={
            "message": "Se l'account esiste, il link di reset e stato generato.",
            "generated_link": generated_link,
            "active_page": "password",
        },
    )


@app.get("/password/reset/{token}", name="password_reset_page")
def password_reset_page(token: str, request: Request, error: Optional[str] = None):
    uid = _get_password_reset_uid(token)
    if not uid:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={
                "error": "Link non valido o scaduto.",
                "token_valid": False,
                "active_page": "password",
            },
        )
    return templates.TemplateResponse(
        request=request,
        name="password_reset.html",
        context={
            "token": token,
            "uid": uid,
            "token_valid": True,
            "active_page": "password",
            "ttl_minutes": PASSWORD_RESET_TTL_MINUTES,
        },
    )


@app.post("/password/reset/{token}")
def password_reset_submit(token: str, request: Request, password: str = Form(...), password_confirm: str = Form(...)):
    uid = _get_password_reset_uid(token)
    if not uid:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={
                "error": "Link non valido o scaduto.",
                "token_valid": False,
                "active_page": "password",
            },
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={
                "error": "Le password non coincidono.",
                "token": token,
                "uid": uid,
                "token_valid": True,
                "active_page": "password",
                "ttl_minutes": PASSWORD_RESET_TTL_MINUTES,
            },
        )

    try:
        ldap_client.set_password(uid=uid, password=password)
    except Exception as exc:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={
                "error": f"Errore reset password: {exc}",
                "token": token,
                "uid": uid,
                "token_valid": True,
                "active_page": "password",
                "ttl_minutes": PASSWORD_RESET_TTL_MINUTES,
            },
        )

    _consume_password_reset_token(token)
    return templates.TemplateResponse(
        request=request,
        name="password_reset.html",
        context={
            "message": "Password aggiornata con successo. Ora puoi accedere con la nuova password.",
            "token_valid": False,
            "active_page": "password",
        },
    )


@app.post("/users/{uid}/delete")
def delete_user(uid: str, q: str = Form(""), page: int = Form(1), page_size: int = Form(25)):
    try:
        ldap_client.delete_user(uid=uid)
        return _redirect_to("/users", message="Utente eliminato", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/users", error=str(exc), q=q, page=page, page_size=page_size)


@app.post("/users/groups/add")
def add_user_to_group_from_users_page(
    uid: str = Form(...),
    group_cn: str = Form(...),
    q: str = Form(""),
    page: int = Form(1),
    page_size: int = Form(25),
):
    normalized_uid = (uid or "").strip()
    normalized_group_cn = (group_cn or "").strip()
    if not normalized_uid or not normalized_group_cn:
        return _redirect_to("/users", error="Utente o gruppo non valido.", q=q, page=page, page_size=page_size)
    try:
        ldap_client.add_user_to_group(group_cn=normalized_group_cn, uid=normalized_uid)
        return _redirect_to("/users", message="Gruppo assegnato all'utente.", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/users", error=str(exc), q=q, page=page, page_size=page_size)


@app.post("/users/groups/remove")
def remove_user_from_group_from_users_page(
    uid: str = Form(...),
    group_cn: str = Form(...),
    q: str = Form(""),
    page: int = Form(1),
    page_size: int = Form(25),
):
    normalized_uid = (uid or "").strip()
    normalized_group_cn = (group_cn or "").strip()
    if not normalized_uid or not normalized_group_cn:
        return _redirect_to("/users", error="Utente o gruppo non valido.", q=q, page=page, page_size=page_size)
    try:
        ldap_client.remove_user_from_group(group_cn=normalized_group_cn, uid=normalized_uid)
        return _redirect_to("/users", message="Gruppo rimosso dall'utente.", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/users", error=str(exc), q=q, page=page, page_size=page_size)


@app.post("/groups")
def create_group(
    group_cn: str = Form(...),
    description: str = Form(""),
    initial_member_uid: str = Form(...),
):
    try:
        ldap_client.create_group(cn=group_cn, description=description, initial_member_uid=initial_member_uid)
        return _redirect_to("/groups", message="Gruppo creato")
    except Exception as exc:
        return _redirect_to("/groups/new", error=str(exc))


@app.post("/groups/members/add")
def add_group_member(
    group_cn: str = Form(...),
    member_uid: str = Form(...),
    q: str = Form(""),
    page: int = Form(1),
    page_size: int = Form(25),
):
    try:
        normalized_member_uid = _normalize_member_uid_input(member_uid)
        ldap_client.add_user_to_group(group_cn=group_cn, uid=normalized_member_uid)
        return _redirect_to("/groups", message="Membro aggiunto", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/groups", error=str(exc), q=q, page=page, page_size=page_size)


@app.post("/groups/members/remove")
def remove_group_member(
    group_cn: str = Form(...),
    member_uid: str = Form(...),
    q: str = Form(""),
    page: int = Form(1),
    page_size: int = Form(25),
):
    try:
        ldap_client.remove_user_from_group(group_cn=group_cn, uid=member_uid)
        return _redirect_to("/groups", message="Membro rimosso", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/groups", error=str(exc), q=q, page=page, page_size=page_size)


@app.post("/groups/delete")
def delete_group(group_cn: str = Form(...), q: str = Form(""), page: int = Form(1), page_size: int = Form(25)):
    try:
        ldap_client.delete_group(cn=group_cn)
        return _redirect_to("/groups", message="Gruppo eliminato", q=q, page=page, page_size=page_size)
    except Exception as exc:
        return _redirect_to("/groups", error=str(exc), q=q, page=page, page_size=page_size)
