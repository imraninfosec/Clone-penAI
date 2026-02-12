"""
Cybersecurity Platform - Professional Edition
Fully functional with AI reports, PDF generation, and proper scanning
"""
import json
import base64
import sqlite3
import bcrypt
import subprocess
import asyncio
import uuid
import markdown
import os
import re
import csv
import tempfile
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import secrets
import string
from urllib.parse import quote, urlparse, urlunparse, parse_qsl, urlencode
import ssl
import socket
import time
import shutil
import sys
import signal
import threading
from zoneinfo import ZoneInfo
from datetime import timedelta
from pathlib import Path
from datetime import datetime
from collections import deque
from fastapi import FastAPI, HTTPException, Depends, Form, BackgroundTasks, Query, Request, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware


# ========== CONFIGURATION ==========
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pentest.db"
FRONTEND_DIR = BASE_DIR / "frontend"
LOG_DIR = BASE_DIR / "logs"
TOOLS_DIR = BASE_DIR / "tools"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
LLAMA_CLI = BASE_DIR / "llama.cpp" / "build" / "bin" / "llama-cli"
NUCLEI_TEMPLATES_DIR = TOOLS_DIR / "nuclei-templates"
LLAMA_SERVER_URL = os.getenv("LLAMA_SERVER_URL", "http://localhost:8080")
LLAMA_SERVER_BIN = BASE_DIR / "llama.cpp" / "build" / "bin" / "llama-server"
LLAMA_SERVER_LOG = BASE_DIR / "backend" / "llama_server.log"
PRODUCT_BRAND_NAME = (os.getenv("PRODUCT_BRAND_NAME", "Security Platform") or "Security Platform").strip()
PRODUCT_COMPANY_NAME = (os.getenv("PRODUCT_COMPANY_NAME", "Customer Organization") or "Customer Organization").strip()
PRODUCT_SECURITY_DIVISION = (
    os.getenv("PRODUCT_SECURITY_DIVISION", "Security Operations Division") or "Security Operations Division"
).strip()
BOOTSTRAP_ADMIN_USERNAME = (os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin") or "admin").strip()
BOOTSTRAP_ADMIN_PASSWORD = (os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "") or "").strip()
BOOTSTRAP_CREDENTIALS_FILE = BASE_DIR / "data" / "bootstrap_admin_credentials.txt"
AI_AGENT_ROLE = (
    f"You are the {PRODUCT_BRAND_NAME} Senior Offensive Security Lead and Reporting Specialist for {PRODUCT_COMPANY_NAME}. "
    "You provide enterprise-grade penetration testing support: scope clarification, automated scan orchestration, "
    "finding triage, business risk translation, and remediation planning. Use only platform tools (katana, nikto, "
    "nuclei, sqlmap, consolidated reports). Default timezone Asia/Dubai. Align guidance to OWASP Testing Guide, "
    "NIST SP 800-115, ISO 27001, UAE IAS, and PCI DSS only for payment-scope systems. "
    "For executives, provide concise risk-focused summaries; "
    "for engineers, provide clear evidence, PoC, reproduction steps, and remediation actions. Avoid speculation; "
    "if evidence is incomplete, state assumptions explicitly."
)
SUPPORTED_TOOLS = ["katana", "nikto", "nuclei", "sqlmap"]
ALL_TOOLS_SCAN_ORDER = ["katana", "nikto", "nuclei", "sqlmap"]
REPORT_FINDINGS_ORDER = ["katana", "sqlmap", "nuclei", "nikto"]
COMPANY_ONBOARDING_FIELDS = [
    "company_legal_name",
    "brand_display_name",
    "platform_title",
    "primary_domain",
    "additional_domains",
    "primary_contact_name",
    "primary_contact_email",
    "primary_contact_phone",
    "industry_sector",
    "compliance_scope",
    "logo_dark_url",
    "logo_light_url",
    "mark_dark_url",
    "mark_light_url",
    "avatar_url",
    "onboarding_notes",
]


def default_company_onboarding_profile() -> dict:
    return {
        "company_legal_name": "Company Legal Name Placeholder",
        "brand_display_name": "Company Brand Placeholder",
        "platform_title": "Security Platform Placeholder",
        "primary_domain": "example.com",
        "additional_domains": "api.example.com\nportal.example.com",
        "primary_contact_name": "Primary Security Contact Placeholder",
        "primary_contact_email": "security@example.com",
        "primary_contact_phone": "+971-00-000-0000",
        "industry_sector": "Industry Placeholder",
        "compliance_scope": "ISO 27001, SOC 2, NIST, OWASP",
        "logo_dark_url": "/static/branding/brand_logo_dark.svg?v=1",
        "logo_light_url": "/static/branding/brand_logo_light.svg?v=1",
        "mark_dark_url": "/static/dragon_ai_logo.svg?v=9",
        "mark_light_url": "/static/dragon_ai_logo_light.svg?v=2",
        "avatar_url": "/static/dragon_ai_icon.svg?v=9",
        "onboarding_notes": "Add customer branding assets and approved target domains before go-live.",
    }


def normalize_company_onboarding_profile(data: dict | None) -> dict:
    defaults = default_company_onboarding_profile()
    profile = {}
    for key in COMPANY_ONBOARDING_FIELDS:
        value = (data or {}).get(key, defaults.get(key, ""))
        if value is None:
            value = ""
        profile[key] = str(value).strip()
    return profile
SECURITY_TOPIC_GUIDES = [
    {
        "id": "mime_sniffing",
        "title": "Missing X-Content-Type-Options (MIME sniffing risk)",
        "patterns": [
            r"\bx-content-type-options\b",
            r"\bnosniff\b",
            r"\bmime(?:[\s-]+sniff(?:ing)?)?\b",
            r"\bmime[\s-]+header\b",
        ],
        "what_is": "When X-Content-Type-Options is missing (or not set to nosniff), some browsers may guess content types instead of trusting declared Content-Type.",
        "why_it_matters": "Content-type confusion can increase client-side injection/XSS exposure, especially on file-serving or upload flows.",
        "validation_steps": [
            "Inspect response headers across HTML, API, static file, and download endpoints.",
            "Confirm X-Content-Type-Options is present and equals nosniff.",
            "Verify endpoints send strict, correct Content-Type values and do not mix user-controlled files with executable contexts.",
        ],
        "remediation_steps": [
            "Set X-Content-Type-Options: nosniff at the reverse proxy/application layer for all responses.",
            "Enforce explicit Content-Type and avoid MIME ambiguity for downloadable or user-supplied content.",
            "Serve untrusted uploads from a separate domain/bucket with safe disposition and no script execution path.",
        ],
        "references": [
            "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/",
            "MDN X-Content-Type-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "CWE-16 Configuration: https://cwe.mitre.org/data/definitions/16.html",
        ],
    },
    {
        "id": "clickjacking",
        "title": "Clickjacking protection weakness (X-Frame-Options/frame-ancestors)",
        "patterns": [
            r"\bx-frame-options\b",
            r"\bframe-ancestors\b",
            r"\bclickjacking\b",
        ],
        "what_is": "The application does not sufficiently restrict framing, allowing pages to be embedded in attacker-controlled sites.",
        "why_it_matters": "Users can be tricked into clicking hidden UI elements, causing unauthorized actions under valid sessions.",
        "validation_steps": [
            "Review headers and CSP for X-Frame-Options and frame-ancestors.",
            "Attempt to embed sensitive pages in an external iframe and verify whether rendering is blocked.",
            "Prioritize high-value workflows such as payments, profile updates, and privileged actions.",
        ],
        "remediation_steps": [
            "Set Content-Security-Policy frame-ancestors 'none' (or explicit trusted origins).",
            "Set X-Frame-Options DENY or SAMEORIGIN for legacy browser coverage.",
            "Protect critical actions with anti-CSRF and re-authentication where appropriate.",
        ],
        "references": [
            "OWASP Clickjacking: https://owasp.org/www-community/attacks/Clickjacking",
            "MDN X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "MDN frame-ancestors: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
        ],
    },
    {
        "id": "hsts",
        "title": "Missing/weak HSTS policy",
        "patterns": [
            r"\bstrict-transport-security\b",
            r"\bhsts\b",
            r"\bhttps[\s-]+downgrade\b",
        ],
        "what_is": "HTTP Strict Transport Security is absent or weak, so browsers are not forced to use HTTPS for future requests.",
        "why_it_matters": "Without strong HSTS, downgrade/interception opportunities increase for first visits or mixed deployment paths.",
        "validation_steps": [
            "Check Strict-Transport-Security on HTTPS responses.",
            "Verify max-age is strong and evaluate includeSubDomains/preload suitability.",
            "Confirm no sensitive flows remain reachable over insecure HTTP.",
        ],
        "remediation_steps": [
            "Set Strict-Transport-Security with a strong max-age (e.g., >= 31536000).",
            "Use includeSubDomains when operationally safe and consider preload after readiness checks.",
            "Enforce HTTPS redirects everywhere and eliminate mixed-content dependencies.",
        ],
        "references": [
            "MDN HSTS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "RFC 6797: https://www.rfc-editor.org/rfc/rfc6797",
            "OWASP Transport Layer Protection: https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    {
        "id": "sqli",
        "title": "SQL Injection risk",
        "patterns": [
            r"\bsql[\s-]*injection\b",
            r"\bsqli\b",
            r"\binjectable\b",
        ],
        "what_is": "Untrusted input can alter SQL queries when queries are built unsafely.",
        "why_it_matters": "Can expose, modify, or destroy sensitive data and may enable privilege escalation.",
        "validation_steps": [
            "Test parameters with safe, staged payloads and compare behavioral differences/errors.",
            "Correlate tool output with database error signatures, timing anomalies, or Boolean response changes.",
            "Retest manually to confirm exploitability and reduce false positives.",
        ],
        "remediation_steps": [
            "Use parameterized queries/prepared statements everywhere.",
            "Apply strict server-side input validation and least-privilege DB accounts.",
            "Add query allow-listing and central error handling to avoid leaking DB internals.",
        ],
        "references": [
            "OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection",
            "OWASP ASVS (Validation & Data Protection): https://owasp.org/www-project-application-security-verification-standard/",
            "NIST SP 800-53 SA-11 / SI controls: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        ],
    },
]


def resolve_llama_model() -> Path:
    """Pick the best available local GGUF model for this platform, with env override."""
    forced = os.getenv("LLAMA_MODEL_PATH") or os.getenv("LLM_MODEL_PATH")
    if forced:
        return Path(forced)
    preferred = [
        MODELS_DIR / "qwen2.5-3b-instruct-q4_k_m.gguf",  # Fast and strong instruction following on low-memory edge devices.
        MODELS_DIR / "mistral-7b-instruct-v0.2.Q4_K_M.gguf",
        MODELS_DIR / "tinyllama.gguf",
    ]
    for candidate in preferred:
        if candidate.exists():
            return candidate
    ggufs = sorted(MODELS_DIR.glob("*.gguf"))
    return ggufs[0] if ggufs else MODELS_DIR / "mistral-7b-instruct-v0.2.Q4_K_M.gguf"


LLAMA_MODEL = resolve_llama_model()

# Create directories
for directory in [LOG_DIR, REPORTS_DIR, FRONTEND_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

security = HTTPBasic()
app = FastAPI(title=PRODUCT_BRAND_NAME, version="4.0")
pending_scan_target = {}
pending_report_scan = {}
last_scan_target = {}
running_processes: dict[int, asyncio.subprocess.Process] = {}
_cpu_prev_lock = threading.Lock()
_cpu_prev_total = None
_cpu_prev_idle = None
_cyber_news_cache = {"fetched_at": 0.0, "items": []}
_llama_backoff_until = 0.0
_llama_backoff_lock = threading.Lock()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def apply_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# ========== DATABASE ==========
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def generate_bootstrap_password(length: int = 20) -> str:
    """Generate a strong bootstrap password with guaranteed complexity classes."""
    if length < 12:
        length = 12
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}:,.?"
    all_chars = lowers + uppers + digits + symbols

    # Ensure at least one character from each class.
    base = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    base.extend(secrets.choice(all_chars) for _ in range(length - len(base)))
    secrets.SystemRandom().shuffle(base)
    return "".join(base)


def write_bootstrap_credentials(username: str, password: str) -> None:
    """Persist generated one-time bootstrap credentials with restrictive file permissions."""
    try:
        BOOTSTRAP_CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
        BOOTSTRAP_CREDENTIALS_FILE.write_text(
            "\n".join(
                [
                    "Bootstrap admin credentials (one-time)",
                    f"username={username}",
                    f"password={password}",
                    "action=login_and_change_password_immediately",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(BOOTSTRAP_CREDENTIALS_FILE, 0o600)
    except Exception as exc:
        print(f"⚠️ Could not write bootstrap credentials file: {exc}")


def is_legacy_default_admin_password(password_hash: str) -> bool:
    """Detect historical insecure default password to force immediate rotation on upgrade."""
    try:
        return bcrypt.checkpw(b"admin123", str(password_hash or "").encode())
    except Exception:
        return False


def resolve_report_logo_src() -> str:
    """Resolve branded report logo as data URI when possible, with static fallback."""
    candidates = [
        (BASE_DIR / "frontend" / "branding" / "brand_logo_dark.svg", "image/svg+xml"),
        (BASE_DIR / "frontend" / "logo2.png", "image/png"),
    ]
    for path, mime in candidates:
        try:
            if path.exists():
                data = path.read_bytes()
                return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
        except Exception:
            continue
    return "/static/branding/brand_logo_dark.svg?v=1"


def init_database():
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            must_change_password INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP,
            password_changed_at TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS company_onboarding (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            company_legal_name TEXT NOT NULL DEFAULT '',
            brand_display_name TEXT NOT NULL DEFAULT '',
            platform_title TEXT NOT NULL DEFAULT '',
            primary_domain TEXT NOT NULL DEFAULT '',
            additional_domains TEXT NOT NULL DEFAULT '',
            primary_contact_name TEXT NOT NULL DEFAULT '',
            primary_contact_email TEXT NOT NULL DEFAULT '',
            primary_contact_phone TEXT NOT NULL DEFAULT '',
            industry_sector TEXT NOT NULL DEFAULT '',
            compliance_scope TEXT NOT NULL DEFAULT '',
            logo_dark_url TEXT NOT NULL DEFAULT '',
            logo_light_url TEXT NOT NULL DEFAULT '',
            mark_dark_url TEXT NOT NULL DEFAULT '',
            mark_light_url TEXT NOT NULL DEFAULT '',
            avatar_url TEXT NOT NULL DEFAULT '',
            onboarding_notes TEXT NOT NULL DEFAULT '',
            updated_by TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            event_type TEXT NOT NULL,
            event_status TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            source_ip TEXT,
            user_agent TEXT,
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_username ON audit_events(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type)")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT NOT NULL,
            tool TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            results TEXT,
            report_html TEXT,
            report_executive TEXT,
            report_technical TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)

    # Ensure new columns exist for older databases
    cur.execute("PRAGMA table_info(scans)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "report_html" not in existing_cols:
        cur.execute("ALTER TABLE scans ADD COLUMN report_html TEXT")
    if "report_executive" not in existing_cols:
        cur.execute("ALTER TABLE scans ADD COLUMN report_executive TEXT")
    if "report_technical" not in existing_cols:
        cur.execute("ALTER TABLE scans ADD COLUMN report_technical TEXT")
    if "started_at" not in existing_cols:
        cur.execute("ALTER TABLE scans ADD COLUMN started_at TIMESTAMP")
    cur.execute(
        "UPDATE scans SET started_at = created_at "
        "WHERE started_at IS NULL AND status IN ('running', 'completed', 'failed')"
    )

    cur.execute("PRAGMA table_info(users)")
    user_cols = {row[1] for row in cur.fetchall()}
    if "role" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if "must_change_password" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
    if "is_active" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    if "created_at" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    if "last_login_at" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP")
    if "password_changed_at" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP")
    
    # Create or harden bootstrap admin account.
    cur.execute("SELECT * FROM users WHERE lower(username)=lower(?)", (BOOTSTRAP_ADMIN_USERNAME,))
    admin_row = cur.fetchone()
    bootstrap_password_written = None
    if not admin_row:
        bootstrap_password = BOOTSTRAP_ADMIN_PASSWORD or generate_bootstrap_password()
        hashed = bcrypt.hashpw(bootstrap_password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, password, role, must_change_password, is_active, password_changed_at) "
            "VALUES (?, ?, 'admin', 1, 1, NULL)",
            (BOOTSTRAP_ADMIN_USERNAME, hashed),
        )
        bootstrap_password_written = bootstrap_password
    else:
        cur.execute(
            "UPDATE users SET role='admin', is_active=1 WHERE id=?",
            (admin_row["id"],),
        )
        # Upgrade path: force reset if legacy insecure default is detected.
        if is_legacy_default_admin_password(admin_row["password"]):
            bootstrap_password = BOOTSTRAP_ADMIN_PASSWORD or generate_bootstrap_password()
            hashed = bcrypt.hashpw(bootstrap_password.encode(), bcrypt.gensalt()).decode()
            cur.execute(
                "UPDATE users SET password=?, must_change_password=1, password_changed_at=NULL WHERE id=?",
                (hashed, admin_row["id"]),
            )
            bootstrap_password_written = bootstrap_password

    # Any account still on initial setup state should be forced to rotate password before operations.
    cur.execute(
        """
        UPDATE users
        SET must_change_password = 1
        WHERE role='admin'
          AND (password_changed_at IS NULL OR password_changed_at = '')
        """
    )

    cur.execute("SELECT id FROM company_onboarding WHERE id = 1")
    if not cur.fetchone():
        defaults = default_company_onboarding_profile()
        cur.execute(
            """
            INSERT INTO company_onboarding (
                id,
                company_legal_name,
                brand_display_name,
                platform_title,
                primary_domain,
                additional_domains,
                primary_contact_name,
                primary_contact_email,
                primary_contact_phone,
                industry_sector,
                compliance_scope,
                logo_dark_url,
                logo_light_url,
                mark_dark_url,
                mark_light_url,
                avatar_url,
                onboarding_notes,
                updated_by,
                updated_at
            ) VALUES (
                1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
            )
            """,
            (
                defaults["company_legal_name"],
                defaults["brand_display_name"],
                defaults["platform_title"],
                defaults["primary_domain"],
                defaults["additional_domains"],
                defaults["primary_contact_name"],
                defaults["primary_contact_email"],
                defaults["primary_contact_phone"],
                defaults["industry_sector"],
                defaults["compliance_scope"],
                defaults["logo_dark_url"],
                defaults["logo_light_url"],
                defaults["mark_dark_url"],
                defaults["mark_light_url"],
                defaults["avatar_url"],
                defaults["onboarding_notes"],
                "system",
            ),
        )

    # Note: non-admin users are created explicitly via admin user management.
    # Do not auto-create ITSec (or any other operational user) at startup.
    
    db.commit()
    db.close()
    if bootstrap_password_written:
        write_bootstrap_credentials(BOOTSTRAP_ADMIN_USERNAME, bootstrap_password_written)
        print(f"🔐 Bootstrap admin credentials written to: {BOOTSTRAP_CREDENTIALS_FILE}")
    print("✅ Database initialized")

# ========== AUTHENTICATION ==========
def verify_user(credentials: HTTPBasicCredentials):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (credentials.username,))
    user = cur.fetchone()
    db.close()
    
    if not user:
        time.sleep(0.2)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="User account is disabled")
    
    if not bcrypt.checkpw(credentials.password.encode(), user["password"].encode()):
        time.sleep(0.2)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return dict(user)


def is_admin_user(user: dict) -> bool:
    return str(user.get("role", "")).strip().lower() == "admin"


def get_request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def log_audit_event(
    request: Request | None,
    event_type: str,
    event_status: str,
    user: dict | None = None,
    *,
    severity: str = "info",
    details: dict | None = None,
    username_override: str | None = None,
):
    """Persist audit telemetry for authentication and user activity."""
    try:
        db = get_db()
        cur = db.cursor()
        username = username_override or (user.get("username") if user else None)
        payload = {
            "details": details or {},
            "path": request.url.path if request else None,
            "method": request.method if request else None,
        }
        cur.execute(
            """
            INSERT INTO audit_events
                (user_id, username, event_type, event_status, severity, source_ip, user_agent, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user.get("id") if user else None,
                username,
                event_type,
                event_status,
                severity,
                get_request_ip(request) if request else None,
                request.headers.get("user-agent", "") if request else "",
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        db.commit()
        db.close()
    except Exception:
        # Never block core app actions because telemetry write failed.
        pass


def require_action_password(user: dict, request: Request, action_label: str):
    """For non-admin users, force password re-entry on sensitive actions."""
    if is_admin_user(user):
        return
    provided = (request.headers.get("X-Action-Password") or "").strip()
    if not provided:
        log_audit_event(
            request,
            "stepup_denied",
            "failure",
            user,
            severity="warning",
            details={"action": action_label, "reason": "missing_password"},
        )
        raise HTTPException(status_code=401, detail="Password verification required for this action")
    if not bcrypt.checkpw(provided.encode(), str(user["password"]).encode()):
        log_audit_event(
            request,
            "stepup_denied",
            "failure",
            user,
            severity="warning",
            details={"action": action_label, "reason": "invalid_password"},
        )
        raise HTTPException(status_code=401, detail="Password verification failed")
    log_audit_event(
        request,
        "stepup_verified",
        "success",
        user,
        details={"action": action_label},
    )


def enforce_password_rotation(user: dict, request: Request):
    """Block operational actions until first-login password reset is completed."""
    if int(user.get("must_change_password") or 0) == 1:
        log_audit_event(
            request,
            "password_rotation_required",
            "failure",
            user,
            severity="warning",
            details={"reason": "must_change_password"},
        )
        raise HTTPException(status_code=403, detail="Password change required before using this action")


def validate_new_password(password: str) -> str | None:
    """Return validation error message, or None when password is acceptable."""
    if not password or len(password) < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    return None


def esc_html(value: str) -> str:
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def get_scan_for_user(scan_id: int, user_id: int):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
    row = cur.fetchone()
    db.close()
    return row


def user_owns_target_ref(user_id: int, target_or_ref: str) -> bool:
    target_ref = target_report_ref(target_or_ref)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT target FROM scans WHERE user_id=?", (user_id,))
    rows = cur.fetchall()
    db.close()
    for row in rows:
        if is_excluded_target(row["target"]):
            continue
        if target_report_ref(row["target"]) == target_ref:
            return True
    return False


def get_user_target_by_ref(user_id: int, target_or_ref: str) -> str | None:
    target_ref = target_report_ref(target_or_ref)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT target FROM scans WHERE user_id=? ORDER BY id DESC", (user_id,))
    rows = cur.fetchall()
    db.close()
    for row in rows:
        if is_excluded_target(row["target"]):
            continue
        if target_report_ref(row["target"]) == target_ref:
            return row["target"]
    return None


def report_templates_newer_than(report_path: Path) -> bool:
    """Return True when report templates/styles changed after a report file was generated."""
    if not report_path.exists():
        return True
    try:
        report_mtime = report_path.stat().st_mtime
        template_files = [
            BASE_DIR / "newreports" / "report.css",
            BASE_DIR / "newreports" / "exerpt.html",
            BASE_DIR / "newreports" / "techrpt.html",
            BASE_DIR / "newreports" / "compliance.html",
        ]
        for template in template_files:
            if template.exists() and template.stat().st_mtime > report_mtime:
                return True
    except Exception:
        # Prefer regeneration when freshness check cannot be completed safely.
        return True
    return False


def ensure_scan_report_file(scan_id: int, mode: str) -> None:
    file_map = {
        "combined": REPORTS_DIR / f"report_scan_{scan_id}.html",
        "executive": REPORTS_DIR / f"report_scan_{scan_id}_executive.html",
        "technical": REPORTS_DIR / f"report_scan_{scan_id}_technical.html",
    }
    path = file_map[mode]
    if (not path.exists()) or has_unresolved_placeholders(path) or report_templates_newer_than(path):
        asyncio.run(generate_scan_reports(scan_id))


def ensure_target_report_file(user_id: int, target_or_ref: str, mode: str) -> bool:
    target = get_user_target_by_ref(user_id, target_or_ref)
    if not target:
        return False
    safe = target_report_ref(target)
    file_map = {
        "combined": REPORTS_DIR / f"report_target_{safe}.html",
        "executive": REPORTS_DIR / f"report_target_{safe}_executive.html",
        "technical": REPORTS_DIR / f"report_target_{safe}_technical.html",
    }
    path = file_map[mode]
    needs_regen = (not path.exists()) or has_unresolved_placeholders(path) or report_templates_newer_than(path)
    if not needs_regen:
        latest_scan_ts = latest_finished_scan_ts_for_target_ref(user_id, safe)
        if latest_scan_ts:
            try:
                report_dt = datetime.utcfromtimestamp(path.stat().st_mtime)
                if report_dt < latest_scan_ts:
                    needs_regen = True
            except Exception:
                needs_regen = True
    if needs_regen:
        asyncio.run(generate_consolidated_reports(user_id, target))
    return True


def scan_report_files_ready(scan_id: int) -> bool:
    paths = [
        REPORTS_DIR / f"report_scan_{scan_id}.html",
        REPORTS_DIR / f"report_scan_{scan_id}_executive.html",
        REPORTS_DIR / f"report_scan_{scan_id}_technical.html",
    ]
    for path in paths:
        if (not path.exists()) or has_unresolved_placeholders(path) or report_templates_newer_than(path):
            return False
    return True


def target_report_files_ready(target_or_ref: str) -> bool:
    safe = target_report_ref(target_or_ref)
    paths = [
        REPORTS_DIR / f"report_target_{safe}.html",
        REPORTS_DIR / f"report_target_{safe}_executive.html",
        REPORTS_DIR / f"report_target_{safe}_technical.html",
    ]
    for path in paths:
        if (not path.exists()) or has_unresolved_placeholders(path) or report_templates_newer_than(path):
            return False
    return True


def latest_finished_scan_ts_for_target_ref(user_id: int, target_or_ref: str) -> datetime | None:
    """Return the newest completed/failed scan timestamp for a target_ref.

    Used to avoid serving stale cached target reports when new scans finish.
    """
    target_ref = target_report_ref(target_or_ref)
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT target, status, created_at, completed_at FROM scans WHERE user_id=? ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    db.close()

    latest = None
    for row in rows:
        t = str(row["target"] or "").strip()
        if not t:
            continue
        if is_excluded_target(t):
            continue
        if target_report_ref(t) != target_ref:
            continue
        status = str(row["status"] or "").strip().lower()
        if status not in ("completed", "failed"):
            continue
        ts = parse_ts(row["completed_at"] or row["created_at"])
        if not ts:
            continue
        if latest is None or ts > latest:
            latest = ts
    return latest

# ========== LLM HELPERS ==========
def llama_available():
    return LLAMA_CLI.exists() and LLAMA_MODEL.exists()

def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def ensure_llama_server():
    if not (LLAMA_SERVER_BIN.exists() and LLAMA_MODEL.exists()):
        return False
    if is_port_open("127.0.0.1", 8080):
        return True
    try:
        LLAMA_SERVER_LOG.parent.mkdir(parents=True, exist_ok=True)
        logf = open(LLAMA_SERVER_LOG, "ab", buffering=0)
        subprocess.Popen(
            [str(LLAMA_SERVER_BIN), "-m", str(LLAMA_MODEL), "--host", "0.0.0.0", "--port", "8080"],
            stdout=logf,
            stderr=logf,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True
        )
    except Exception:
        return False
    # Give it time to boot (model load can take a while)
    for _ in range(60):
        if is_port_open("127.0.0.1", 8080):
            return True
        time.sleep(0.5)
    return False


def llama_backoff_active() -> bool:
    with _llama_backoff_lock:
        return time.time() < _llama_backoff_until


def mark_llama_backoff() -> None:
    cooldown = float(os.getenv("LLAMA_BACKOFF_SECONDS", "120"))
    with _llama_backoff_lock:
        global _llama_backoff_until
        _llama_backoff_until = max(_llama_backoff_until, time.time() + max(cooldown, 10.0))


def clear_llama_backoff() -> None:
    with _llama_backoff_lock:
        global _llama_backoff_until
        _llama_backoff_until = 0.0


def llama_server_request(prompt: str, max_tokens: int, timeout: float | None = None) -> str:
    request_timeout = float(timeout if timeout is not None else os.getenv("LLAMA_HTTP_TIMEOUT", "12"))
    payload = json.dumps({
        "prompt": prompt,
        "n_predict": max_tokens,
        "temperature": 0.2,
        "top_p": 0.8,
        "repeat_penalty": 1.15,
        # Keep stop markers model-agnostic for Mistral/Qwen GGUF chat templates.
        "stop": ["\n\n\n", "<|im_end|>", "<|endoftext|>"]
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{LLAMA_SERVER_URL}/completion",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=request_timeout) as resp:
        body = resp.read().decode("utf-8")
        data = json.loads(body)
        return (data.get("content") or data.get("completion") or "").strip()

def run_llama_prompt(prompt: str, max_tokens: int = 128) -> str:
    if not llama_available():
        return f"LLM is not available. Ensure llama.cpp is installed and model exists at: {LLAMA_MODEL}"
    threads = int(os.getenv("LLAMA_THREADS", "4"))
    # Prefer llama-server if running to avoid per-request model load
    try:
        server_output = llama_server_request(prompt, max_tokens)
        if server_output:
            return server_output
    except Exception:
        # Attempt to start server then retry once
        if ensure_llama_server():
            try:
                server_output = llama_server_request(prompt, max_tokens)
                if server_output:
                    return server_output
                return "LLM server returned no output. Try again in a few seconds."
            except Exception:
                return "LLM server is not responding. Try again in a few seconds."

    # Fall back to llama-cli (slower). Keep prompt size reasonable.
    if len(prompt) > 4000:
        prompt = prompt[:4000]
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(prompt.strip())
        prompt_file = f.name
    cmd = [
        str(LLAMA_CLI),
        "-m", str(LLAMA_MODEL),
        "-f", prompt_file,
        "-n", str(max_tokens),
        "--no-display-prompt",
        "--temp", "0.2",
        "--top-p", "0.8",
        "--repeat-penalty", "1.15",
        "--threads", str(threads)
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            stdin=subprocess.DEVNULL
        )
        if result.returncode != 0:
            return f"LLM error: {result.stderr.strip() or 'unknown error'}"
        output = (result.stdout or "").strip()
        # Basic cleanup of echoed prefixes
        if output:
            cleaned = []
            for line in output.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith(("response:", "assistant:", "user:", ">")):
                    stripped = stripped.split(":", 1)[-1].strip()
                    if not stripped:
                        continue
                cleaned.append(stripped)
            if cleaned:
                output = "\n".join(cleaned)
        if not output:
            return "LLM returned no output. Try again or reduce prompt size."
        return output[:800]
    except subprocess.TimeoutExpired:
        return "LLM timed out while generating a response."
    finally:
        try:
            os.unlink(prompt_file)
        except Exception:
            pass


def build_fallback_reply(user_message: str, recent_scans: list[dict]) -> str:
    """Deterministic guidance when the LLM is unavailable."""
    scans_line = ""
    if recent_scans:
        summaries = [f"#{s['id']} {s['target']} ({s['tool']}) {s['status']}" for s in recent_scans[:5]]
        scans_line = "Recent scans: " + "; ".join(summaries)
    tips = [
        "I can still help with built-in commands:",
        "- scan <target> with katana|nikto|nuclei|sqlmap|all tools",
        "- history (last scans)",
        "- status <scan_id> or logs <scan_id>",
        "- report <scan_id> or report target <domain>",
    ]
    base = "\n".join(tips)
    if scans_line:
        base += "\n" + scans_line
    if not user_message.strip():
        return base
    return f"{base}\n\nTell me a target to start a scan or a scan ID to report on."

def normalize_target(target: str) -> str:
    target = clean_target(target.strip())
    if not target:
        return target
    # Preserve caller-provided host exactly (including www subdomain) and
    # only add a default scheme when missing.
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"

def normalize_target_display(target: str) -> str:
    target = clean_target(target.strip())
    if not target:
        return target
    if target.startswith(("http://", "https://")):
        target = target.split("://", 1)[1]
    if target.startswith("www."):
        target = target[4:]
    return target

def clean_target(value: str) -> str:
    value = value.strip()
    value = value.translate({
        ord("–"): "-",
        ord("—"): "-",
        ord("−"): "-",
        ord("‑"): "-"
    })
    value = value.rstrip(").,;:!?\"'")
    value = value.lstrip("([\"'")
    return value

def parse_chat_command(message: str):
    text = message.strip()
    lower = text.lower()
    if not text:
        return ("empty", {})
    if lower in ("help", "/help", "commands", "?"):
        return ("help", {})
    if lower in ("history", "list scans", "list scan", "scans"):
        return ("history", {})
    if lower in ("nuclei", "nikto", "sqlmap", "katana", "all tools", "all", "all tools please"):
        return ("scan_tool", {"tool": lower})

    # Explanation intent should win over report-opening for phrases like:
    # "explain the report 126", "summarize findings for scan 126", etc.
    explain_intent = re.search(
        r"(?:^|\b)(?:explain|summari[sz]e|interpret|clarify|walk\s+me\s+through)\b",
        lower,
    )
    if explain_intent and re.search(r"\b(?:report|findings?|scan)\b", lower):
        explain_scan_match = re.search(r"\b(?:report|scan)(?:\s+id)?(?:\s+for)?\s*#?\s*(\d+)\b", lower)
        if not explain_scan_match:
            explain_scan_match = re.search(r"\b(\d+)\b", lower)
        if explain_scan_match:
            return ("explain", {"scan_id": int(explain_scan_match.group(1))})

    # Same target shorthand
    if "same target" in lower or "same site" in lower:
        tool_match = re.search(r"(?:with|using)\s+(.+)", lower)
        if tool_match:
            tool = tool_match.group(1).strip()
            return ("scan_same", {"tool": tool})
        return ("scan_same", {})

    # Report phrasing like "scan 71 report" or "report scan 71"
    report_scan_phrase = re.search(r"(?:report\s+(?:for\s+)?scan\s+|scan\s+)(\d+)\s+report", lower)
    if report_scan_phrase:
        return ("report", {"scan_id": int(report_scan_phrase.group(1))})

    # Only treat as command when user explicitly starts with it
    scan_match = re.match(r"^(?:/scan|scan)\s+([^\s]+)(?:\s+with\s+(.+))?$", lower)
    if scan_match:
        target = clean_target(scan_match.group(1))
        if scan_match.group(2):
            tool = scan_match.group(2).strip()
            return ("scan", {"target": target, "tool": tool})
        return ("scan_prompt", {"target": target})

    # Natural language scan commands
    scan_on_match = re.search(r"(?:run|conduct|perform|start)\s+(?:a\s+)?scan\s+on\s+([a-z0-9.-]+|https?://[^\\s]+)", lower)
    if scan_on_match:
        target = clean_target(scan_on_match.group(1))
        tool_match = re.search(r"(?:with|using)\s+(.+)", lower)
        if tool_match:
            tool = tool_match.group(1).strip()
            return ("scan", {"target": target, "tool": tool})
        return ("scan_prompt", {"target": target})

    scan_target_match = re.search(r"(?:scan\s+target|scan)\s+([a-z0-9.-]+|https?://[^\\s]+)", lower)
    if scan_target_match:
        target = clean_target(scan_target_match.group(1))
        tool_match = re.search(r"(?:with|using)\s+(.+)", lower)
        if tool_match:
            tool = tool_match.group(1).strip()
            return ("scan", {"target": target, "tool": tool})
        return ("scan_prompt", {"target": target})

    # If user only provided a target, prompt for tool
    if " " not in lower and is_valid_target(lower):
        return ("scan_prompt", {"target": clean_target(lower)})

    conduct_scan_match = re.search(r"(?:conduct|perform|start)\s+(?:a\s+)?scan(?:\s+for|\s+against|\s+of)?\s+([a-z0-9.-]+|https?://[^\\s]+)", lower)
    if conduct_scan_match:
        target = clean_target(conduct_scan_match.group(1))
        tool_match = re.search(r"(?:with|using)\s+(.+)", lower)
        if tool_match:
            tool = tool_match.group(1).strip()
            return ("scan", {"target": target, "tool": tool})
        return ("scan_prompt", {"target": target})

    report_target_match = re.match(r"^(?:/report_target|report target|consolidated report|report for)\s+([a-z0-9.-]+)$", lower)
    if report_target_match:
        return ("report_target", {"target": report_target_match.group(1)})

    report_match = re.match(r"^(?:/report|report|get report|open report|open the report)\s+(?:scan\s+)?(\d+)$", lower)
    if report_match:
        return ("report", {"scan_id": int(report_match.group(1))})

    report_type_match = re.match(r"^(?:executive|technical)\s+report\s+(?:scan\s+)?(\d+)$", lower)
    if report_type_match:
        report_type = "executive" if lower.startswith("executive") else "technical"
        return ("report", {"scan_id": int(report_type_match.group(1)), "report_type": report_type})

    status_match = re.match(r"^(?:/status|status|scan status)\s+(?:scan\s+)?(\d+)$", lower)
    if status_match:
        return ("status", {"scan_id": int(status_match.group(1))})

    logs_match = re.match(r"^(?:/logs|logs|scan logs)\s+(?:scan\s+)?(\d+)$", lower)
    if logs_match:
        return ("logs", {"scan_id": int(logs_match.group(1))})

    explain_match = re.match(r"^(?:/explain|explain|summarize findings for|explain findings for)\s+(?:scan\s+)?(\d+)$", lower)
    if explain_match:
        return ("explain", {"scan_id": int(explain_match.group(1))})

    # Natural language report/status/history/explain
    nl_report_scan = re.search(r"(?:generate|get|fetch|create)\s+report\s+(?:for\s+)?(?:scan\s+)?(\d+)", lower)
    if nl_report_scan:
        return ("report", {"scan_id": int(nl_report_scan.group(1))})

    nl_report_target = re.search(r"(?:generate|get|fetch|create|provide)\s+(?:consolidated\s+)?report\s+(?:for|on)\s+([a-z0-9.-]+)", lower)
    if nl_report_target:
        return ("report_target", {"target": nl_report_target.group(1)})

    nl_status = re.search(r"(?:status|progress)\s+(?:of\s+)?(?:scan\s+)?(\d+)", lower)
    if nl_status:
        return ("status", {"scan_id": int(nl_status.group(1))})

    nl_history = re.search(r"(?:scan\s+history|show\s+history|scan\s+list)", lower)
    if nl_history:
        return ("history", {})

    nl_explain = re.search(r"(?:explain|summarize|findings)\s+(?:for\s+)?(?:scan\s+)?(\d+)", lower)
    if nl_explain:
        return ("explain", {"scan_id": int(nl_explain.group(1))})

    return ("chat", {"message": message.strip()})

# ========== SCANNER - FIXED VERSION ==========
def parse_ts(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def compute_scan_duration_seconds(scan: dict) -> int:
    """Compute duration from actual run start, keeping pending scans at 0 seconds."""
    status = str(scan.get("status", "")).strip().lower()
    created_dt = parse_ts(scan.get("created_at"))
    started_dt = parse_ts(scan.get("started_at"))
    completed_dt = parse_ts(scan.get("completed_at"))
    now_dt = datetime.utcnow()

    if status == "pending":
        return 0
    if status == "running":
        if not started_dt:
            return 0
        return max(int((now_dt - started_dt).total_seconds()), 0)

    start_dt = started_dt or created_dt
    if not start_dt:
        return 0
    end_dt = completed_dt or now_dt
    return max(int((end_dt - start_dt).total_seconds()), 0)


def add_months(dt_value: datetime, months: int) -> datetime:
    """Calendar-accurate month addition without external dependencies."""
    year = dt_value.year + ((dt_value.month - 1 + months) // 12)
    month = ((dt_value.month - 1 + months) % 12) + 1
    # month-end safe day selection
    if month == 2:
        leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
        max_day = 29 if leap else 28
    elif month in (4, 6, 9, 11):
        max_day = 30
    else:
        max_day = 31
    day = min(dt_value.day, max_day)
    return dt_value.replace(year=year, month=month, day=day)


def format_abu_dhabi(dt_value):
    try:
        if not dt_value:
            return None
        dt = parse_ts(dt_value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(ZoneInfo("Asia/Dubai")).strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return None


def format_report_datetime(dt_value):
    """Report display format: YYYY-MM-DD HH:MM AM/PM (Asia/Dubai)."""
    return format_abu_dhabi(dt_value)


def format_assessment_period(start_value, end_value=None):
    """Report assessment window format in Asia/Dubai based on actual scan start/end."""
    try:
        tz = ZoneInfo("Asia/Dubai")
        start_dt = parse_ts(start_value) or datetime.now()
        end_dt = parse_ts(end_value) or start_dt
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=ZoneInfo("UTC"))
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=ZoneInfo("UTC"))
        start_local = start_dt.astimezone(tz)
        end_local = end_dt.astimezone(tz)
        start_str = start_local.strftime("%d-%b-%Y %I:%M %p").upper()
        end_str = end_local.strftime("%d-%b-%Y %I:%M %p").upper()
        if start_str == end_str:
            return start_str
        return f"{start_str} TO {end_str}"
    except Exception:
        return None


def get_cpu_usage_percent() -> float:
    """Compute host CPU usage from /proc/stat with lightweight rolling delta."""
    global _cpu_prev_total, _cpu_prev_idle
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            first = f.readline().strip().split()
        if len(first) < 5 or first[0] != "cpu":
            return 0.0
        values = [int(v) for v in first[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        with _cpu_prev_lock:
            if _cpu_prev_total is None or _cpu_prev_idle is None:
                _cpu_prev_total, _cpu_prev_idle = total, idle
                # First sample fallback: use normalized load average estimate.
                load1 = os.getloadavg()[0]
                cores = max(os.cpu_count() or 1, 1)
                return max(0.0, min(100.0, (load1 / cores) * 100.0))
            total_delta = total - _cpu_prev_total
            idle_delta = idle - _cpu_prev_idle
            _cpu_prev_total, _cpu_prev_idle = total, idle
        if total_delta <= 0:
            return 0.0
        busy = 100.0 * (1.0 - (idle_delta / total_delta))
        return max(0.0, min(100.0, busy))
    except Exception:
        return 0.0


def get_memory_usage_percent() -> float:
    """Compute host memory usage from /proc/meminfo."""
    try:
        mem = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, value = line.split(":", 1)
                mem[key.strip()] = int(value.strip().split()[0])  # kB
        total = float(mem.get("MemTotal", 0))
        available = float(mem.get("MemAvailable", 0))
        if total <= 0:
            return 0.0
        used_pct = ((total - available) / total) * 100.0
        return max(0.0, min(100.0, used_pct))
    except Exception:
        return 0.0


CYBER_NEWS_SOURCES = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Security Affairs", "https://securityaffairs.com/feed"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("CISA Alerts", "https://www.cisa.gov/uscert/ncas/alerts.xml"),
    ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
]

CYBER_NEWS_KEYWORDS = (
    "attack", "attacks", "breach", "ransomware", "malware", "phishing",
    "exploit", "zero-day", "ddos", "hijack", "backdoor", "compromise",
    "vulnerability", "leak", "threat", "botnet", "espionage", "hacked",
    "incident", "cyber",
)


def parse_feed_items(xml_text: str, source_name: str) -> list[dict]:
    items = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return items

    # RSS feeds
    for node in root.findall(".//item"):
        title = (node.findtext("title") or "").strip()
        link = (node.findtext("link") or "").strip()
        if title:
            items.append({"title": title, "source": source_name, "link": link})

    # Atom feeds
    atom_ns = {"atom": "http://www.w3.org/2005/Atom"}
    for node in root.findall(".//atom:entry", atom_ns):
        title = (node.findtext("atom:title", default="", namespaces=atom_ns) or "").strip()
        link = ""
        link_node = node.find("atom:link", atom_ns)
        if link_node is not None:
            link = (link_node.get("href") or "").strip()
        if title:
            items.append({"title": title, "source": source_name, "link": link})

    return items


def fetch_cyber_news(limit: int = 8) -> list[dict]:
    collected = []
    seen = set()
    headers = {"User-Agent": "SecurityPlatform-Pentest/1.0"}
    per_source_cap = 2
    parsed_by_source = []

    def normalized_key(text: str) -> str:
        return re.sub(r"\s+", " ", (text or "").strip().lower())

    def qualifies(title: str) -> bool:
        lowered = title.lower()
        return any(keyword in lowered for keyword in CYBER_NEWS_KEYWORDS)

    def push_item(item: dict) -> bool:
        title = (item.get("title") or "").strip()
        if not title:
            return False
        if not qualifies(title):
            return False
        key = normalized_key(title)
        if key in seen:
            return False
        seen.add(key)
        collected.append({
            "title": title,
            "source": item.get("source", "Threat Intelligence"),
            "link": item.get("link", "")
        })
        return True

    for source_name, source_url in CYBER_NEWS_SOURCES:
        try:
            req = urllib.request.Request(source_url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as response:
                xml_text = response.read().decode("utf-8", errors="ignore")
            parsed_items = parse_feed_items(xml_text, source_name)
        except Exception:
            parsed_items = []
        parsed_by_source.append(parsed_items)

        added_from_source = 0
        for item in parsed_items:
            if added_from_source >= per_source_cap:
                break
            if push_item(item):
                added_from_source += 1
            if len(collected) >= limit:
                return collected

    # Fill remaining slots from all sources (if any source had more relevant items).
    if len(collected) < limit:
        for source_items in parsed_by_source:
            for item in source_items:
                push_item(item)
                if len(collected) >= limit:
                    return collected

    return collected


def get_cached_cyber_news(limit: int = 8) -> list[dict]:
    now = time.time()
    ttl_seconds = 300
    cached_items = _cyber_news_cache.get("items") or []
    last_fetch = float(_cyber_news_cache.get("fetched_at") or 0.0)
    if cached_items and (now - last_fetch) < ttl_seconds:
        return cached_items[:limit]

    fetched = fetch_cyber_news(limit=limit)
    if not fetched:
        fetched = [
            {
                "title": "Ransomware actors continue targeting internet-facing platforms with double-extortion tactics.",
                "source": "Threat Intelligence",
                "link": "",
            },
            {
                "title": "Exploitation activity is accelerating after critical vulnerability disclosures in public services.",
                "source": "Threat Intelligence",
                "link": "",
            },
            {
                "title": "Business email compromise and phishing campaigns remain top initial access vectors.",
                "source": "Threat Intelligence",
                "link": "",
            },
        ]
    _cyber_news_cache["items"] = fetched
    _cyber_news_cache["fetched_at"] = now
    return fetched[:limit]

def is_nuclei_stats(text: str) -> bool:
    if not text:
        return False
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    return all(re.search(r"Templates:\s+\d+.*Requests:\s+\d+/\d+", l) for l in lines)


def extract_cli_option(command: str, option: str) -> str | None:
    """Extract a CLI option value from a flattened command string."""
    if not command or not option:
        return None
    # Support both "--opt value" and "--opt=value" styles (many tools emit the latter).
    match = re.search(rf"(?:^|\s){re.escape(option)}(?:\s+|=)([^\s]+)", command)
    if not match:
        return None
    value = match.group(1).strip().strip("\"'")
    return value or None


def is_negative_injection_signal(text: str) -> bool:
    """Detect wording that indicates SQL injection was *not* confirmed."""
    t = (text or "").lower()
    negatives = [
        "no injectable parameters detected",
        "no injectable parameters found",
        "no injectable parameters were found",
        "no injectable parameters confirmed",
        "no injectable parameters were confirmed",
        "no injectable parameters were identified",
        "did not confirm sql injection",
        "sql injection not detected",
        "no sql injection detected",
        "not injectable",
        "no sql injection",
        "without confirmed injection",
    ]
    return any(token in t for token in negatives)

def summarize_findings_basic(tool_name: str, output: str, err: str, target_url: str, command: str | None = None) -> str:
    findings = build_findings_from_output(tool_name, output, err, target_url, command=command)
    if not findings:
        return "No findings available."
    lines = []
    for item in findings[:20]:
        severity = item.get("severity", "info").upper()
        title = item.get("title", "Finding")
        evidence = item.get("evidence", "")
        evidence = evidence.replace("\n", " ")
        lines.append(f"- [{severity}] {title} :: {evidence[:160]}")
    return "\n".join(lines)


def build_executive_bullets(tool: str, output: str, err: str, progress: dict | None = None) -> list[str]:
    """Create concise, business-friendly bullets for executive report."""
    bullets = []
    text = (output or "") + "\n" + (err or "")
    lower = text.lower()

    if tool == "nikto":
        # Missing headers
        if "x-content-type-options" in lower:
            bullets.append("Missing X-Content-Type-Options header leaves browsers free to MIME-sniff responses.")
        if "x-frame-options" in lower:
            bullets.append("Clickjacking control uses deprecated X-Frame-Options; should move to CSP frame-ancestors.")
        # Backup / key stores
        suspicious = [l for l in text.splitlines() if any(ext in l for ext in [".jks", ".tar", ".tgz", ".lzma", ".war", ".bz2"])]
        if suspicious:
            bullets.append(f"Exposed backup/archive artifacts detected ({len(suspicious)} paths) — risk of source or keys leakage.")
        # Generic completion
        if not bullets:
            bullets.append("Web server reachable over HTTPS; Nikto completed with warnings, no critical misconfigs confirmed.")
    elif tool == "nuclei":
        matches = [l for l in text.splitlines() if l.strip() and "[" in l and "]" in l]
        if matches:
            bullets.append(f"Nuclei matched {len(matches)} finding(s); see technical details.")
        else:
            tpl = progress.get("templates") if progress else None
            bullets.append(f"Nuclei executed {tpl or 'configured'} template(s); no vulnerabilities matched.")
    elif tool == "sqlmap":
        if "connection reset" in lower or "waf" in lower:
            bullets.append("SQL injection probing blocked/unstable; target likely protected (WAF/connection resets).")
        elif "not injectable" in lower:
            bullets.append("No injectable parameters found at tested entry point (low-risk based on current scope).")
        else:
            bullets.append("SQL injection scan completed; no confirmed injection found in tested path.")
    elif tool == "katana":
        urls = [l for l in text.splitlines() if l.startswith("http")]
        if urls:
            bullets.append(f"Discovery crawl completed; {len(urls)} URLs harvested for further testing.")
        else:
            bullets.append("Discovery crawl completed; no additional endpoints enumerated.")

    return bullets[:4]


ansi_re = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def clean_scan_text(text: str) -> str:
    """Strip ANSI codes and noisy banners from tool output for readable reports."""
    if not text:
        return ""
    cleaned = ansi_re.sub("", text)
    lines = []
    skip_markers = [
        "__        __",  # katana banner line
        "/ /_____ _/ /____",  # katana banner variants
        "/  '_/ _  / __/ _",  # katana banner line 2
        "_/\\\\_,_/",  # katana banner tail
        "_/\\\\_\\\\_,_/\\\\__/\\\\_,_/_//_/\\\\_,_/",  # katana full tail line
        "projectdiscovery.io",
        "Current katana version",
        "Started standard crawling for =>",
        "[INF] Current katana version",
    ]
    for line in cleaned.splitlines():
        if line and not any(ch.isalnum() for ch in line):
            continue
        if any(marker in line for marker in skip_markers):
            continue
        lines.append(line)
    return "\n".join(l for l in lines if l.strip())


def sanitize_tool_error(tool_name: str, err: str, output: str = "") -> tuple[str, str | None]:
    """Filter noisy tool errors that should not appear as standalone findings."""
    cleaned_err = clean_scan_text(err or "")
    warning = None
    if not cleaned_err:
        return cleaned_err, warning

    if tool_name == "katana":
        # Katana often prints banners/info to stderr; keep only actionable failures.
        kept_lines = []
        for line in cleaned_err.splitlines():
            lower = line.strip().lower()
            if not lower:
                continue
            if lower.startswith("[inf]") or lower.startswith("[info]"):
                continue
            if "current katana version" in lower or "started standard crawling for" in lower:
                continue
            if line.strip() in {"___", "__h__"}:
                continue
            kept_lines.append(line.strip())
        cleaned_err = "\n".join(l for l in kept_lines if l)
        return cleaned_err, warning

    if tool_name == "nuclei":
        # Nuclei stats lines are progress telemetry, not errors.
        lines = [l.strip() for l in cleaned_err.splitlines() if l.strip()]
        if lines:
            def _is_stats_line(s: str) -> bool:
                ls = s.lower()
                if re.search(r"\[\d+:\d+:\d+\]\s*\|", s):
                    return True
                if "templates:" in ls and "requests:" in ls:
                    return True
                # Some stderr fragments can be clipped and still be pure stats telemetry.
                if "matched:" in ls and "errors:" in ls and "requests:" in ls:
                    return True
                if "tched:" in ls and "errors:" in ls and "requests:" in ls:
                    return True
                return False

            if all(_is_stats_line(line) for line in lines):
                return "", warning
        if is_nuclei_stats(cleaned_err):
            return "", warning
        return cleaned_err, warning

    if tool_name != "nikto":
        return cleaned_err, warning

    kept_lines = []
    suppressed = False
    for line in cleaned_err.splitlines():
        lower = line.strip().lower()
        # Treat Nikto remote-read-limit warnings as coverage telemetry, not a finding.
        if "nikto reached remote http read error limit" in lower:
            suppressed = True
            continue
        if "error limit (" in lower and "error reading http response" in lower:
            suppressed = True
            continue
        kept_lines.append(line.strip())

    cleaned_err = "\n".join(l for l in kept_lines if l)
    if suppressed:
        warning = "Nikto reached remote HTTP read error limit; findings may be partial."
    return cleaned_err, warning


def remediation_for_finding(tool_name: str, title: str, evidence: str) -> str:
    text = f"{title} {evidence}".lower()
    if is_negative_injection_signal(text):
        return "No SQL injection was confirmed in this scope. Maintain secure query practices and expand parameter coverage in follow-up tests."
    if ("false positive" in text or "unexploitable" in text) and "injection" in text:
        return (
            "SQLMap flagged an injection-like response but marked it false positive/unexploitable. "
            "Validate the parameter handling and retest with a stable request capture (same session/cookies). "
            "Treat as informational unless reproducible and confirmed with evidence."
        )
    if tool_name == "sqlmap":
        if any(
            marker in text
            for marker in (
                "sql injection not tested",
                "payload testing was not executed",
                "no parameters/forms discovered",
                "no usable links found",
                "no parameter(s) found for testing",
            )
        ):
            return (
                "SQLMap did not have testable input vectors in this scope. Provide parameterized URLs or "
                "authenticated request captures (cookies/HTTP auth or -r request file), increase crawl depth/sitemap parsing, "
                "then rerun SQLMap to validate injection risk on real parameters."
            )
        if "401" in text and ("unauthorized" in text or "not authorized" in text):
            return (
                "Target returned HTTP 401. Provide valid HTTP authentication or session cookies (or allowlist the scanner), "
                "then rerun SQLMap against parameter-rich endpoints (including authenticated flows)."
            )
        if "403" in text and "forbidden" in text:
            return (
                "Target returned HTTP 403. Validate access controls and scanner allowlisting, then rerun SQLMap "
                "on permitted parameterized endpoints to restore coverage."
            )
        if "429" in text and ("too many requests" in text or "rate limited" in text):
            return (
                "Target rate-limited SQLMap traffic (HTTP 429). Reduce threads/rate, add delays, coordinate with WAF rules, "
                "then rerun to achieve full parameter coverage without throttling."
            )
    if any(k in text for k in ["x-frame-options", "frame-ancestors", "clickjacking"]):
        return "Replace/augment X-Frame-Options with CSP frame-ancestors; verify allowed framing origins only."
    if any(k in text for k in ["x-content-type-options", "mime-sniff"]):
        return "Set X-Content-Type-Options: nosniff on all HTTP responses and re-test with curl -I."
    if any(k in text for k in ["strict-transport-security", "hsts"]):
        return "Enable HSTS with appropriate max-age and includeSubDomains after TLS hardening validation."
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return "Remove exposed backup/build artifacts from web root, rotate affected secrets/keys, and restrict direct file access."
    if any(k in text for k in ["sql injection", "injectable", "payload", "parameter"]):
        return "Use parameterized queries, strict server-side input validation, and WAF rules for injection patterns; re-test affected parameters."
    if tool_name == "katana":
        return "Review discovered endpoints, disable unused routes, enforce authentication/authorization, and restrict sensitive paths."
    if "scan error" in text:
        return "Resolve scanner/runtime errors and rerun assessment to confirm true security posture."
    return "Apply secure configuration hardening, validate fix in staging, and confirm remediation with targeted re-scan."


def impact_for_finding(title: str, evidence: str) -> str:
    text = f"{title} {evidence}".lower()
    if is_negative_injection_signal(text):
        return "No confirmed SQL injection impact in tested inputs; residual risk depends on untested parameters and future code changes."
    if ("false positive" in text or "unexploitable" in text) and "injection" in text:
        return "SQLMap observed an injection-like indicator but marked it false positive/unexploitable; no confirmed injection impact in tested scope."
    if any(
        marker in text
        for marker in (
            "sql injection not tested",
            "payload testing was not executed",
            "no parameters/forms discovered",
            "no usable links found",
            "no parameter(s) found for testing",
        )
    ):
        return "SQL injection assurance was not established because SQLMap could not identify testable input parameters/forms in the scanned scope."
    if any(code in text for code in ["http 401", "401 unauthorized", "not authorized", "http 403", "403 forbidden", "http 429", "429 too many requests"]):
        return "Assessment coverage was blocked by access controls or rate limiting; injection risk cannot be concluded until authenticated/allowed retesting is completed."
    if any(k in text for k in ["sql injection", "injectable"]):
        return "Potential unauthorized data access/modification and possible full database compromise."
    if any(k in text for k in ["backup", ".jks", ".tar", ".war", ".zip", "archive"]):
        return "Potential leakage of source code, credentials, certificates, or internal architecture details."
    if any(k in text for k in ["header", "x-frame-options", "x-content-type-options", "hsts"]):
        return "Reduced browser-side protections, increasing exposure to clickjacking, MIME-sniffing, or transport downgrade risks."
    if "endpoint discovery" in text:
        return "Expanded attack surface; hidden or ungoverned endpoints may introduce exploitable paths."
    if "scan error" in text:
        return "Incomplete visibility may hide true security weaknesses until re-validation."
    return "Security weakness may increase likelihood of compromise depending on exploitability and exposure."


def poc_for_finding(tool_name: str, location: str, title: str, evidence: str) -> str:
    text = f"{title} {evidence}".lower()
    host = location or "<target>"
    if tool_name == "sqlmap":
        if ("false positive" in text or "unexploitable" in text) and "injection" in text:
            return (
                f"Capture a stable request for {host} (same cookies/session) and rerun SQLMap to confirm whether the indicator reproduces "
                "and can be validated with consistent evidence."
            )
        if any(
            marker in text
            for marker in (
                "sql injection not tested",
                "payload testing was not executed",
                "no parameters/forms discovered",
                "no usable links found",
                "no parameter(s) found for testing",
            )
        ):
            return (
                f"Provide a parameterized endpoint (e.g., /search?id=1) or an authenticated request capture for {host} "
                "and rerun SQLMap with crawl/forms enabled to generate evidence on real parameters."
            )
        if "401" in text and ("unauthorized" in text or "not authorized" in text):
            return (
                f"Rerun SQLMap with valid HTTP authentication or session cookies against {host} (HTTP 200 access), "
                "then test discovered parameters for injection."
            )
        if "403" in text and "forbidden" in text:
            return f"Confirm access policy/allowlisting for {host} and rerun SQLMap on permitted parameterized endpoints."
        if "429" in text and ("too many requests" in text or "rate limited" in text):
            return f"Reduce scan concurrency/rate and rerun SQLMap against {host} to avoid HTTP 429 throttling."
    if is_negative_injection_signal(text):
        return f"Rerun sqlmap against additional in-scope parameters for {host} to validate broader coverage."
    if any(k in text for k in ["x-frame-options", "x-content-type-options", "strict-transport-security", "header"]):
        return f"curl -I {host} | egrep -i 'x-frame-options|content-security-policy|x-content-type-options|strict-transport-security'"
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return "Request the exposed path directly in browser/curl and verify whether file content is downloadable."
    if any(k in text for k in ["sql injection", "injectable"]):
        return "Re-run sqlmap with the same URL/parameter and confirm payload-specific behavioral differences or DB fingerprint output."
    if tool_name == "katana":
        return "Use the discovered URL list and manually verify each endpoint response code and access controls."
    return "Reproduce using the same scanner command and capture request/response evidence."


def reproduction_steps_for_finding(tool_name: str, location: str, title: str, evidence: str) -> list[str]:
    text = f"{title} {evidence}".lower()
    if is_negative_injection_signal(text):
        return [
            "Confirm tested parameters and request methods used in this scan.",
            "Expand coverage to additional forms/APIs and rerun SQL injection checks.",
            "Document negative validation evidence for assurance and audit traceability."
        ]
    if tool_name == "sqlmap" and ("false positive" in text or "unexploitable" in text) and "injection" in text:
        return [
            "Identify the parameter flagged by SQLMap and collect the exact request/response evidence.",
            "Capture a stable request (same cookies/session) and rerun SQLMap to check reproducibility.",
            "If reproducible, validate with manual review and confirm severity before treating as a true SQL injection weakness."
        ]
    if tool_name == "sqlmap":
        if any(
            marker in text
            for marker in (
                "sql injection not tested",
                "payload testing was not executed",
                "no parameters/forms discovered",
                "no usable links found",
                "no parameter(s) found for testing",
            )
        ):
            return [
                "Confirm crawl/forms settings and whether any parameterized URLs were discovered in the scanned scope.",
                "Identify a parameterized endpoint or capture an authenticated request (cookies/HTTP auth or -r request file).",
                "Rerun SQLMap with increased crawl depth/sitemap parsing and verify it tests real parameters (HTTP 200 responses).",
            ]
        if "401" in text and ("unauthorized" in text or "not authorized" in text):
            return [
                "Confirm the target endpoint requires authentication (HTTP 401).",
                "Provide valid HTTP auth or session cookies (or allowlist the scanner) for the tested endpoint.",
                "Rerun SQLMap and verify it reaches HTTP 200 before concluding injection posture.",
            ]
        if "403" in text and "forbidden" in text:
            return [
                "Confirm access policy blocks the scanner (HTTP 403).",
                "Allowlist scanner IP / adjust access controls for authorized testing scope.",
                "Rerun SQLMap against permitted parameterized endpoints and compare evidence.",
            ]
        if "429" in text and ("too many requests" in text or "rate limited" in text):
            return [
                "Confirm target is throttling automated requests (HTTP 429).",
                "Reduce SQLMap threads/rate and add delays; coordinate with WAF rate limits.",
                "Rerun SQLMap and confirm full parameter coverage without throttling.",
            ]
    if any(k in text for k in ["header", "x-frame-options", "x-content-type-options", "strict-transport-security"]):
        return [
            f"Run: curl -I {location} and capture response headers.",
            "Verify missing/deprecated header and compare against policy baseline.",
            "Apply header fix and rerun curl/scan to confirm closure."
        ]
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return [
            "Request the reported artifact URL and confirm exposure.",
            "Document file metadata/content sensitivity and access controls.",
            "Remove/protect artifact and validate 403/404 after fix."
        ]
    if any(k in text for k in ["sql injection", "injectable"]):
        return [
            "Re-run sqlmap on the same endpoint/parameter with recorded options.",
            "Capture payload, server response, and any DBMS fingerprint evidence.",
            "Fix query handling, then rerun sqlmap to verify non-injectable state."
        ]
    if tool_name == "katana":
        return [
            "Rerun katana with identical scope to reproduce endpoint list.",
            "Validate each discovered endpoint for authN/authZ and exposure.",
            "Restrict or remove unnecessary endpoints and retest."
        ]
    return [
        "Rerun the original scan command with same target and options.",
        "Capture output, response artifacts, and timestamps.",
        "Apply remediation and verify closure with a focused re-scan."
    ]


def humanize_finding_title(tool_name: str, title: str, evidence: str) -> str:
    """Convert raw scanner lines into concise, human-readable report titles."""
    raw = str(title or "").strip()
    if not raw:
        raw = "Finding"
    text = f"{raw} {evidence}".lower()

    if "scan error" in text:
        return "Scanner Runtime Error"
    if is_negative_injection_signal(text):
        return "No SQL Injection Evidence Detected"
    if ("false positive" in text or "unexploitable" in text) and "injection" in text:
        return "SQL Injection Indicator Marked False Positive/Unexploitable"
    if "completed with no output" in text or "no scan output captured" in text:
        return "Scan Completed Without Actionable Output"
    if "completed without actionable findings" in text:
        return f"No Actionable {tool_name.capitalize()} Findings Detected"
    if any(k in text for k in ["sql injection", "injectable"]):
        if any(k in text for k in ["might be injectable", "heuristic", "potential"]):
            return "Potential SQL Injection Indicator"
        return "SQL Injection Vulnerability Detected"
    if any(k in text for k in ["x-frame-options", "frame-ancestors", "clickjacking"]):
        if "deprecated" in text:
            return "Deprecated Clickjacking Header Configuration"
        return "Missing or Weak Clickjacking Protection Header"
    if "x-content-type-options" in text or "mime-sniff" in text:
        return "Missing MIME Sniffing Protection Header"
    if any(k in text for k in ["strict-transport-security", " hsts", "hsts "]):
        return "Missing HTTP Strict Transport Security (HSTS) Header"
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return "Potential Exposure of Backup or Archive Files"
    if "directory indexing" in text:
        return "Directory Listing Exposure"
    if tool_name == "katana" and raw.lower().startswith("endpoint discovery -"):
        return raw
    if tool_name == "katana" and ("endpoint discovery" in text or " urls" in text):
        return "Externally Reachable Endpoints Discovered"
    if "cve-" in text:
        m = re.search(r"(cve-\d{4}-\d+)", text)
        if m:
            return f"Potential {m.group(1).upper()} Exposure"

    cleaned = re.sub(r"https?://\S+", "", raw).strip()
    cleaned = re.sub(r"^/[^:]{1,240}:\s*", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if len(cleaned) > 120:
        cleaned = cleaned.split(". ", 1)[0].strip()
    if len(cleaned) > 120:
        cleaned = cleaned[:117].rstrip() + "..."
    if cleaned:
        return cleaned[0].upper() + cleaned[1:]
    return "Finding"


def cvss_score_for_finding(tool_name: str, severity: str, title: str, evidence: str) -> float:
    """Estimate CVSS base score from severity and finding context."""
    text = f"{title} {evidence}".lower()
    sev = str(severity or "info").lower()
    base = {"critical": 9.8, "high": 8.2, "medium": 6.0, "low": 3.5, "info": 0.0}

    if is_negative_injection_signal(text):
        return 0.0
    if ("false positive" in text or "unexploitable" in text) and "injection" in text:
        return 0.0
    if any(k in text for k in ["scan error", "no output"]):
        return 0.0
    if any(k in text for k in ["sql injection", "injectable"]):
        if any(k in text for k in ["potential", "heuristic", "might be injectable"]):
            return 6.8
        return 9.1
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return 7.5
    if "x-frame-options" in text and "deprecated" in text:
        return 4.3
    if "x-frame-options" in text:
        return 4.8
    if "x-content-type-options" in text:
        return 4.0
    if any(k in text for k in ["strict-transport-security", "hsts"]):
        return 5.3
    if "directory indexing" in text:
        return 5.0
    if tool_name == "katana" or "endpoint discovery" in text:
        return 2.6
    if "cve-" in text or any(k in text for k in ["rce", "remote code execution"]):
        return max(base.get(sev, 0.0), 8.8)

    return base.get(sev, 0.0)


def format_cvss(value) -> str:
    if value is None:
        return "CVSS N/A"
    text = str(value).strip()
    if not text:
        return "CVSS N/A"
    if text.upper().startswith("CVSS"):
        matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", text)
        if not matches:
            return "CVSS N/A"
        text = matches[-1]
    try:
        score = max(0.0, min(float(text), 10.0))
        return f"CVSS v4.0 {score:.1f}"
    except Exception:
        return "CVSS N/A"


def enrich_findings(tool_name: str, findings_list: list[dict]) -> list[dict]:
    enriched = []
    for finding in findings_list:
        item = dict(finding)
        title = item.get("title", "")
        evidence = item.get("evidence", "")
        location = item.get("location", "")
        # System-wide guardrail: suppress SQLMap heuristic/false-positive indicators.
        # Only confirmed SQLi should be carried forward into reports/posture/compliance.
        sqlmap_text = f"{title} {evidence}".lower()
        if tool_name == "sqlmap" and (
            "false positive" in sqlmap_text
            or "unexploitable" in sqlmap_text
            or "potential sql injection indicator" in sqlmap_text
            or ("appears to be" in sqlmap_text and "injectable" in sqlmap_text)
            or "might be injectable" in sqlmap_text
        ):
            continue
        item["raw_title"] = str(title or "")
        item["title"] = humanize_finding_title(tool_name, title, evidence)
        item["impact"] = item.get("impact") or impact_for_finding(title, evidence)
        item["recommendation"] = item.get("recommendation") or remediation_for_finding(tool_name, title, evidence)
        item["poc"] = item.get("poc") or poc_for_finding(tool_name, location, title, evidence)
        item["reproduction_steps"] = item.get("reproduction_steps") or reproduction_steps_for_finding(tool_name, location, title, evidence)
        if not item.get("cvss"):
            item["cvss"] = cvss_score_for_finding(tool_name, item.get("severity", "info"), item["title"], evidence)
        item["cvss"] = format_cvss(item.get("cvss"))
        enriched.append(item)
    return enriched


def ai_summarize_findings(tool_name: str, target: str, findings_list: list[dict], audience: str = "executive") -> str:
    """Use local LLM when available; enforce clean fallback for production reports."""
    if not findings_list:
        return "No material findings were identified in the tested scope."

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(
        findings_list,
        key=lambda x: severity_order.get(str(x.get("severity", "info")).lower(), 4),
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in ordered:
        sev = str(f.get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1

    compact = []
    for f in ordered[:8]:
        compact.append(
            f"[{str(f.get('severity', 'info')).upper()}] {f.get('title', 'Finding')} | "
            f"Impact: {f.get('impact', '')} | Evidence: {str(f.get('evidence', '')).replace(chr(10), ' ')[:180]} | "
            f"Remediation: {f.get('recommendation', '')}"
        )
    compact_text = "\n".join(compact)

    if audience == "executive":
        fallback_lines = [
            f"- Risk profile for {tool_name} on {target}: "
            f"Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, "
            f"Low {counts['low']}, Informational {counts['info']}.",
        ]
        for f in ordered[:3]:
            sev = str(f.get("severity", "info")).upper()
            fallback_lines.append(
                f"- {sev}: {f.get('title', 'Finding')} - {f.get('impact', 'Impact requires validation')}"
            )
        fallback_lines.append(
            "- Priority action: remediate critical/high findings first, then validate closure with re-testing."
        )
        fallback = "\n".join(fallback_lines)
    else:
        fallback = "\n".join([
            f"- {f.get('title','Finding')} ({str(f.get('severity','info')).upper()}): "
            f"Evidence: {str(f.get('evidence','No evidence'))[:180]}. "
            f"Remediation: {f.get('recommendation','Apply hardening and retest.')}"
            for f in ordered[:8]
        ])

    def sanitize_summary(text: str, max_lines: int) -> str:
        blocked_prefixes = (
            "rule", "assistant:", "user:", "question:", "answer:", "context:",
            "impact:", "remedy:", "rules:"
        )
        lines = []
        for raw in text.splitlines():
            line = raw.strip(" -*\t")
            if not line:
                continue
            if line.lower().startswith(blocked_prefixes):
                continue
            if "executive summary:" in line.lower() or "technical summary:" in line.lower():
                continue
            # Guard against prompt leakage and malformed artifacts.
            if "###" in line or "{'" in line or "}" == line:
                continue
            lines.append(f"- {line}")
        lines = lines[:max_lines]
        return "\n".join(lines)

    if llama_backoff_active():
        return fallback

    if not (llama_available() and is_port_open("127.0.0.1", 8080)):
        return fallback

    if audience == "executive":
        prompt = (
            f"{AI_AGENT_ROLE}\n"
            f"Produce an executive summary for a {tool_name} assessment on {target}.\n"
            "Output format: 4-6 bullet points only, each line starts with '- '.\n"
            "Keep it business-focused: risk, exposure, priority remediation.\n"
            "Do not include raw payloads, prompt rules, or tool logs.\n\n"
            f"Findings:\n{compact_text}\n\nOutput:"
        )
        max_tokens = 220
        max_lines = 6
    else:
        prompt = (
            f"{AI_AGENT_ROLE}\n"
            f"Produce a technical summary for a {tool_name} assessment on {target}.\n"
            "Output format: 5-8 bullet points only, each line starts with '- '.\n"
            "Include evidence theme + remediation priority, no prompt echoes.\n\n"
            f"Findings:\n{compact_text}\n\nOutput:"
        )
        max_tokens = 300
        max_lines = 8
    try:
        text = llama_server_request(
            prompt,
            max_tokens=max_tokens,
            timeout=float(os.getenv("LLAMA_SUMMARY_TIMEOUT", "8")),
        ).strip()
        if not text:
            mark_llama_backoff()
            return fallback
        bad = ["llm is not available", "not responding", "timed out", "error"]
        if any(b in text.lower() for b in bad):
            mark_llama_backoff()
            return fallback
        clean = sanitize_summary(text, max_lines=max_lines)
        if clean:
            clear_llama_backoff()
            return clean
        mark_llama_backoff()
        return fallback
    except Exception:
        mark_llama_backoff()
        return fallback


def compact_text_for_chat(value: str, max_len: int = 220) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def detect_security_topic_for_chat(user_message: str) -> dict | None:
    lower = str(user_message or "").strip().lower()
    if not lower:
        return None
    security_intent = re.search(
        r"\b(explain|issue|vulnerab|remediat|mitigat|fix|hardening|header|security|pentest|risk|attack|weakness|owasp|what is|why|how to)\b",
        lower,
    )
    for topic in SECURITY_TOPIC_GUIDES:
        patterns = topic.get("patterns", [])
        if not any(re.search(pattern, lower) for pattern in patterns):
            continue
        # Avoid hijacking generic MIME-type questions without security context.
        if topic.get("id") == "mime_sniffing":
            if (
                "mime type" in lower
                and "x-content-type-options" not in lower
                and "nosniff" not in lower
                and not security_intent
            ):
                continue
        if security_intent or topic.get("id") in ("mime_sniffing", "clickjacking", "hsts", "sqli"):
            return topic
    return None


def build_topic_fallback_reply(topic: dict) -> str:
    title = topic.get("title", "Security issue explanation")
    what_is = topic.get("what_is", "Security control weakness observed.")
    why = topic.get("why_it_matters", "This can increase exploitable attack surface.")
    validation_steps = topic.get("validation_steps", [])
    remediation_steps = topic.get("remediation_steps", [])
    references = topic.get("references", [])

    lines = [
        f"{title}",
        f"What it is: {what_is}",
        f"Why it matters: {why}",
        "Pentest validation logic:",
    ]
    for step in validation_steps[:3]:
        lines.append(f"- {step}")
    lines.append("Remediation:")
    for step in remediation_steps[:4]:
        lines.append(f"- {step}")
    lines.append("References:")
    for ref in references[:4]:
        lines.append(f"- {ref}")
    return "\n".join(lines)


def sanitize_topic_ai_reply(text: str, max_lines: int = 16) -> str:
    blocked_prefixes = (
        "assistant:",
        "user:",
        "context:",
        "question:",
        "answer:",
        "response:",
    )
    lines = []
    for raw in str(text or "").splitlines():
        line = raw.strip(" \t-*")
        if not line:
            continue
        low = line.lower()
        if low.startswith(blocked_prefixes):
            continue
        if "which scan id should i explain" in low:
            continue
        if "example: explain findings for scan" in low:
            continue
        lines.append(line)
        if len(lines) >= max_lines:
            break
    if not lines:
        return ""
    return "\n".join(f"- {line}" for line in lines)


def build_security_topic_reply_for_chat(user_message: str) -> str | None:
    topic = detect_security_topic_for_chat(user_message)
    if not topic:
        return None

    fallback = build_topic_fallback_reply(topic)
    if llama_backoff_active():
        return fallback
    if not (llama_available() and is_port_open("127.0.0.1", 8080)):
        return fallback

    references = topic.get("references", [])
    refs_block = "\n".join(f"- {r}" for r in references[:4])
    prompt = (
        f"{AI_AGENT_ROLE}\n"
        f"User request: {user_message}\n"
        f"Topic: {topic.get('title', 'Security issue')}\n\n"
        "Answer as a professional pentest advisor.\n"
        "Output requirements:\n"
        "- 8 to 12 concise bullet points only.\n"
        "- Cover: what it is, why it matters, pentest validation logic, remediation, references.\n"
        "- Include practical remediation and verification actions.\n"
        "- Do not ask for scan ID unless the user explicitly asks about a specific scan/report.\n"
        "- Do not include 'Response:'.\n"
        "Use these references where relevant:\n"
        f"{refs_block}\n\n"
        "Answer:"
    )
    try:
        response = llama_server_request(
            prompt,
            max_tokens=320,
            timeout=float(os.getenv("LLAMA_SUMMARY_TIMEOUT", "8")),
        ).strip()
        if not response:
            mark_llama_backoff()
            return fallback
        clean = sanitize_topic_ai_reply(response)
        if clean:
            clear_llama_backoff()
            return clean
        mark_llama_backoff()
        return fallback
    except Exception:
        mark_llama_backoff()
        return fallback


def explain_issue_for_chat(title: str, evidence: str) -> str:
    text = f"{title} {evidence}".lower()
    if is_negative_injection_signal(text):
        return "SQL injection tests on the assessed parameters did not confirm an exploitable injection path."
    if any(k in text for k in ["x-content-type-options", "mime-sniff"]):
        return "The X-Content-Type-Options header is missing, so browsers may MIME-sniff response content."
    if any(k in text for k in ["x-frame-options", "frame-ancestors", "clickjacking"]):
        return "The clickjacking protection configuration is missing, weak, or deprecated for modern browser controls."
    if any(k in text for k in ["strict-transport-security", "hsts"]):
        return "HSTS is not enforced, so secure transport policy is weaker than recommended."
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return "Potential backup or archive files were exposed in web-accessible paths."
    if any(k in text for k in ["endpoint discovery", "discovered endpoint", "externally reachable endpoints discovered"]):
        return "Additional reachable endpoints were discovered and need control validation."
    if any(k in text for k in ["sql injection", "injectable"]):
        return "Input handling showed potential or confirmed SQL injection behavior on tested parameters."
    if any(k in text for k in ["scan error", "runtime error", "timed out", "partial timeout"]):
        return "Scanner/runtime issues reduced evidence quality and may have limited coverage."
    evidence_line = compact_text_for_chat(evidence, max_len=200)
    if evidence_line:
        return evidence_line
    return "The scanner reported this finding and it requires validation and remediation."


def threat_for_finding_chat(title: str, evidence: str, severity: str) -> str:
    text = f"{title} {evidence}".lower()
    sev = str(severity or "info").lower()
    if is_negative_injection_signal(text):
        return "No exploitable SQL injection was confirmed in tested scope, but untested parameters remain a residual risk."
    if any(k in text for k in ["sql injection", "injectable"]):
        return "An attacker could tamper with backend queries to access, alter, or exfiltrate sensitive data."
    if any(k in text for k in ["x-content-type-options", "mime-sniff"]):
        return "Client-side content handling can be abused in browser-based attack chains."
    if any(k in text for k in ["x-frame-options", "frame-ancestors", "clickjacking"]):
        return "Attackers may frame application pages and trick users into unauthorized actions."
    if any(k in text for k in ["strict-transport-security", "hsts"]):
        return "Session traffic may be downgraded in interception scenarios without strict transport policy."
    if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
        return "Exposed artifacts can accelerate attacker reconnaissance and secret compromise attempts."
    if any(k in text for k in ["endpoint discovery", "discovered endpoint", "externally reachable endpoints discovered"]):
        return "Untracked endpoints increase attack surface and may expose weak or unaudited routes."
    if any(k in text for k in ["scan error", "runtime error", "timed out", "partial timeout"]):
        return "Coverage blind spots may hide exploitable weaknesses until retesting is completed."
    if sev in ("critical", "high"):
        return "This finding is likely exploitable with potentially significant operational or data impact."
    return "This weakness may be exploited depending on exposure and control effectiveness."


def is_non_actionable_chat_observation(item: dict) -> bool:
    text = " ".join(
        [
            str(item.get("title", "")),
            str(item.get("evidence", "")),
            str(item.get("impact", "")),
            str(item.get("recommendation", "")),
        ]
    ).lower()
    markers = (
        "no sql injection evidence detected",
        "completed without matched templates",
        "scan completed without actionable output",
        "completed with no output",
        "no actionable",
        "no endpoints discovered",
    )
    return any(marker in text for marker in markers)


def build_chat_findings_explanation(
    scan_id: int,
    target: str,
    tool: str,
    status_display: str,
    findings_list: list[dict],
    counts: dict,
    overall_risk: str,
) -> str:
    if not findings_list:
        return (
            f"Findings summary for scan #{scan_id} ({tool} on {target})\n"
            f"Status: {status_display}\n"
            "No material findings were identified in the captured scan output."
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def cvss_numeric(value) -> float:
        matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", str(value or ""))
        if not matches:
            return 0.0
        try:
            return max(0.0, min(float(matches[-1]), 10.0))
        except Exception:
            return 0.0

    ordered = sorted(
        findings_list,
        key=lambda item: (
            severity_order.get(str(item.get("severity", "info")).lower(), 4),
            -cvss_numeric(item.get("cvss")),
            str(item.get("title", "")),
        ),
    )

    material = [item for item in ordered if not is_non_actionable_chat_observation(item)] or ordered
    curated = []
    seen = set()
    for item in material:
        dedupe_key = (
            str(item.get("severity", "info")).lower(),
            str(item.get("title", "")).strip().lower(),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        curated.append(item)
        if len(curated) >= 5:
            break

    lines = [
        f"Findings summary for scan #{scan_id} ({tool} on {target})",
        f"Status: {status_display}",
        (
            f"Overall risk: {overall_risk}. Severity mix: "
            f"Critical {counts['critical']}, High {counts['high']}, "
            f"Medium {counts['medium']}, Low/Info {counts['low'] + counts['info']}."
        ),
        "",
    ]

    for idx, finding in enumerate(curated, 1):
        sev = str(finding.get("severity", "info")).upper()
        title = compact_text_for_chat(finding.get("title", "Finding"), max_len=130)
        evidence = str(finding.get("evidence", ""))
        cvss = compact_text_for_chat(finding.get("cvss", "CVSS N/A"), max_len=24) or "CVSS N/A"
        impact = compact_text_for_chat(
            finding.get("impact", "Business impact requires contextual validation."),
            max_len=220,
        )
        threat = compact_text_for_chat(
            threat_for_finding_chat(title, evidence, sev),
            max_len=220,
        )
        remediation = compact_text_for_chat(
            finding.get("recommendation", "Apply secure remediation and validate with retesting."),
            max_len=220,
        )
        what_is = compact_text_for_chat(explain_issue_for_chat(title, evidence), max_len=220)

        lines.extend(
            [
                f"{idx}) {sev} - {title} ({cvss})",
                f"   Issue found: {title}.",
                f"   What is the issue: {what_is}",
                f"   Business impact: {impact}",
                f"   Threat: {threat}",
                f"   Remediation: {remediation}",
                "",
            ]
        )

    return "\n".join(lines).strip()


def build_findings_from_output(
    tool_name: str,
    output: str,
    err: str,
    target_url: str,
    progress: dict | None = None,
    command: str | None = None,
):
    output = clean_scan_text(output or "")
    err, _ = sanitize_tool_error(tool_name, err, output)
    findings_list = []
    if tool_name == "nuclei" and is_nuclei_stats(err):
        err = ""
    if err and tool_name != "sqlmap":
        findings_list.append({
            "severity": "info",
            "title": f"{tool_name} scan error",
            "tool": tool_name,
            "location": target_url,
            "evidence": err
        })
    if not output:
        evidence = "No scan output captured."
        if tool_name == "nuclei" and progress:
            evidence = (
                f"Nuclei executed {progress.get('templates', 'configured')} template(s); "
                f"matched {progress.get('matched', 0)}; "
                f"requests {progress.get('requests_done')}/{progress.get('requests_total')}."
            )
        findings_list.append({
            "severity": "info",
            "title": f"{tool_name} completed with no output",
            "tool": tool_name,
            "location": target_url,
            "evidence": evidence
        })
        return enrich_findings(tool_name, findings_list)
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    if tool_name == "nuclei":
        for line in lines:
            m = re.match(r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)", line)
            if not m:
                continue
            tpl, sev, proto, rest = m.groups()
            findings_list.append({
                "severity": sev.lower(),
                "title": rest or tpl,
                "tool": "nuclei",
                "location": target_url,
                "evidence": line,
                "template": tpl
            })
        if not findings_list:
            evidence = "Nuclei scan completed without matched templates."
            if progress:
                evidence = (
                    f"Nuclei executed {progress.get('templates', 'configured')} template(s); "
                    f"matched {progress.get('matched', 0)}; "
                    f"requests {progress.get('requests_done')}/{progress.get('requests_total')}."
                )
            findings_list.append({
                "severity": "info",
                "title": "Nuclei completed without matched templates",
                "tool": "nuclei",
                "location": target_url,
                "evidence": evidence
            })
        return enrich_findings(tool_name, findings_list)
    if tool_name == "nikto":
        for line in lines:
            if line.startswith("+"):
                finding_text = line.lstrip("+ ").strip()
                lower = finding_text.lower()
                ignore_prefixes = (
                    "target ip", "target hostname", "target port", "ssl info", "start time",
                    "end time", "server:", "1 host(s) tested", "scan terminated", "no cgi directories found"
                )
                if any(lower.startswith(prefix) for prefix in ignore_prefixes):
                    continue
                # Nikto's "Potentially interesting backup/cert file found" entries are heuristic
                # wordlist hits and frequently false positives unless the path is directly
                # confirmed downloadable (e.g., via explicit curl/browser verification).
                if "potentially interesting backup" in lower and "file found" in lower:
                    continue
                is_path_finding = re.match(r"^/[^\\s]+:", finding_text) is not None
                markers = [
                    "vulnerable", "potentially interesting", "backup", "exposed", "deprecated",
                    "header is not set", "x-frame-options", "x-content-type-options", "hsts",
                    "directory indexing", "cve", "osvdb"
                ]
                if not is_path_finding and not any(marker in lower for marker in markers):
                    continue
                if any(k in lower for k in ["critical", "rce", "remote code", "sql injection", "cve-"]):
                    sev = "high"
                elif any(k in lower for k in ["vulnerable", "exposed", "backup", "deprecated", "header is not set", "potentially interesting", "osvdb"]):
                    sev = "medium"
                else:
                    sev = "low"
                findings_list.append({
                    "severity": sev,
                    "title": finding_text,
                    "tool": "nikto",
                    "location": target_url,
                    "evidence": line
                })
        if not findings_list:
            findings_list.append({
                "severity": "info",
                "title": "Nikto completed without actionable findings",
                "tool": "nikto",
                "location": target_url,
                "evidence": "Nikto output did not include confirmed vulnerabilities in current scope."
            })
        return enrich_findings(tool_name, findings_list)
    if tool_name == "sqlmap":
        combined_text = f"{output}\n{err}".strip()
        lower_text = combined_text.lower()
        non_injectable = (
            is_negative_injection_signal(combined_text)
            or "all tested parameters do not appear to be injectable" in lower_text
        )
        conn_issue = sqlmap_connection_failure_reason(output or "", err or "", timed_out=False)
        waf_hint = "waf/ips" in lower_text or "captcha" in lower_text

        err_lower = (err or "").strip().lower()
        err_is_warning_only = bool(err_lower) and all(
            line.strip().startswith("warning:")
            for line in err_lower.splitlines()
            if line.strip()
        )

        def sqlmap_extract_techniques(text: str) -> list[str]:
            techniques: list[str] = []
            for ln in (text or "").splitlines():
                m = re.search(r"testing\s+'([^']+)'", ln, re.IGNORECASE)
                if m:
                    label = m.group(1).strip()
                    if label and label not in techniques:
                        techniques.append(label)
            return techniques

        def sqlmap_methodology(command: str | None, text: str) -> str:
            level = extract_cli_option(command or "", "--level") or "1"
            risk = extract_cli_option(command or "", "--risk") or "1"
            technique_flag = extract_cli_option(command or "", "--technique")
            tamper_flag = extract_cli_option(command or "", "--tamper")
            crawl_flag = extract_cli_option(command or "", "--crawl")
            forms_enabled = "--forms" in (command or "")
            multi_target = extract_cli_option(command or "", "-m")
            techniques = sqlmap_extract_techniques(text)
            if technique_flag:
                tech_text = f"Techniques: {technique_flag}"
            elif techniques:
                sample = "; ".join(techniques[:3])
                extra = f" (+{len(techniques) - 3} more)" if len(techniques) > 3 else ""
                tech_text = f"Techniques tested: {sample}{extra}"
            else:
                tech_text = "Techniques tested: standard SQLMap suite"

            method = f"SQLMap automated SQL injection checks (level {level}, risk {risk}). {tech_text}."
            if multi_target:
                method += " Multi-target input list provided from discovery."
            if crawl_flag:
                method += f" Crawl depth {crawl_flag}."
            if forms_enabled:
                method += " Form discovery enabled."
            if tamper_flag:
                method += f" Tamper: {tamper_flag}."
            return method

        if conn_issue:
            title = "SQLMap execution blocked"
            lower_issue = conn_issue.lower()
            if "401" in lower_issue or "unauthorized" in lower_issue:
                title = "SQLMap blocked by HTTP 401 Unauthorized"
            elif "403" in lower_issue or "forbidden" in lower_issue:
                title = "SQLMap blocked by HTTP 403 Forbidden"
            elif "429" in lower_issue or "too many requests" in lower_issue:
                title = "SQLMap rate limited (HTTP 429)"
            elif "404" in lower_issue or "not found" in lower_issue:
                title = "SQLMap received HTTP 404 Not Found"
            findings_list.append({
                "severity": "info",
                "title": title,
                "tool": "sqlmap",
                "location": target_url,
                "evidence": conn_issue,
            })
            return enrich_findings(tool_name, findings_list)

        if err and (not non_injectable) and (not err_is_warning_only):
            # SQLMap can emit partial findings even when it encounters errors mid-run.
            findings_list.append({
                "severity": "info",
                "title": "SQLMap runtime error",
                "tool": "sqlmap",
                "location": target_url,
                "evidence": err,
            })

        # When SQLMap can't discover parameters or forms, it didn't actually test for injection.
        if any(
            marker in lower_text
            for marker in (
                "no usable links found (with get parameters)",
                "no usable links found (with get parameters) or forms",
                "no usable links found",
                "no parameter(s) found for testing",
            )
        ):
            method = sqlmap_methodology(command, combined_text)
            crawl_flag = extract_cli_option(command or "", "--crawl")
            forms_enabled = "--forms" in (command or "")
            scope_bits = []
            if crawl_flag:
                scope_bits.append(f"crawl depth {crawl_flag}")
            if forms_enabled:
                scope_bits.append("forms enabled")
            scope_suffix = f" ({', '.join(scope_bits)})" if scope_bits else ""
            extra = " Potential CAPTCHA/WAF protection was detected." if waf_hint else ""
            findings_list.append({
                "severity": "info",
                "title": "SQL injection not tested (no parameters/forms discovered)",
                "tool": "sqlmap",
                "location": target_url,
                "evidence": (
                    f"{method} SQLMap did not find testable GET parameters or forms in the discovered scope{scope_suffix}; "
                    f"injection payload testing was not executed.{extra}"
                ),
            })
            return enrich_findings(tool_name, findings_list)

        # If SQLMap ran in multi-target mode, prefer the authoritative results CSV.
        sqlmap_csv_rows: list[dict] = []
        out_dir_opt = extract_cli_option(command or "", "--output-dir")
        if out_dir_opt:
            csv_path = _sqlmap_latest_results_csv(Path(out_dir_opt))
            if csv_path:
                sqlmap_csv_rows = _sqlmap_parse_results_csv(csv_path)

        def sqlmap_technique_names(letters: str) -> str:
            mapping = {
                "B": "boolean-based blind",
                "E": "error-based",
                "U": "UNION query",
                "S": "stacked queries",
                "T": "time-based blind",
                "Q": "inline queries",
            }
            parts = []
            for ch in (letters or "").strip().upper():
                if ch in mapping:
                    parts.append(mapping[ch])
            return ", ".join(parts)

        if sqlmap_csv_rows:
            confirmed_rows = []
            for row in sqlmap_csv_rows:
                note = (row.get("Note(s)") or row.get("Notes") or "").strip().lower()
                techniques = (row.get("Technique(s)") or row.get("Techniques") or "").strip()
                if ("false positive" in note) or ("unexploitable" in note):
                    continue
                if techniques:
                    confirmed_rows.append(row)

            if confirmed_rows:
                for row in confirmed_rows[:25]:
                    url = row.get("Target URL") or target_url
                    param = row.get("Parameter") or ""
                    place = row.get("Place") or ""
                    techniques = sqlmap_technique_names(row.get("Technique(s)") or "")
                    note = row.get("Note(s)") or row.get("Notes") or ""
                    title = f"SQL injection confirmed{(' in ' + param) if param else ''}"
                    bits = [b for b in [place, (f"Techniques: {techniques}" if techniques else ""), note] if b]
                    findings_list.append({
                        "severity": "high",
                        "title": title,
                        "tool": "sqlmap",
                        "location": url,
                        "evidence": " | ".join(bits) if bits else "SQLMap confirmed an injectable parameter.",
                    })
                return enrich_findings(tool_name, findings_list)

        current_url = target_url
        expect_url_line = False
        current = None
        injections = []
        seen_keys: set[tuple] = set()

        for line in lines:
            stripped = (line or "").strip()
            if not stripped:
                continue
            lower = stripped.lower()

            # Track which URL SQLMap is currently testing (multi-target logs).
            if lower in ("url:", "form:"):
                expect_url_line = True
                continue
            if expect_url_line:
                m = re.match(r"^(get|post)\s+(https?://\S+)", stripped, re.IGNORECASE)
                if m:
                    current_url = m.group(2).strip()
                expect_url_line = False
                continue
            m = re.search(r"testing\s+url\s+'([^']+)'", stripped, re.IGNORECASE)
            if m:
                current_url = m.group(1).strip()

            # Confirmed injection lines
            if (
                ("is injectable" in lower or "is vulnerable" in lower)
                and "does not seem to be injectable" not in lower
            ):
                pm = re.search(r"parameter '([^']+)'", stripped, re.IGNORECASE)
                param = pm.group(1).strip() if pm else ""
                key = ("confirmed_line", current_url, param)
                if key not in seen_keys:
                    title = f"SQL injection detected{(' in ' + param) if param else ''}"
                    findings_list.append({
                        "severity": "high",
                        "title": title,
                        "tool": "sqlmap",
                        "location": current_url,
                        "evidence": stripped,
                    })
                    seen_keys.add(key)

            # Ignore SQLMap heuristic/false-positive indicator lines.
            if (
                ("appears to be" in lower and "injectable" in lower)
                or ("false positive" in lower)
                or ("unexploitable" in lower)
            ):
                continue

            if "xss" in lower and "might be vulnerable" in lower:
                key = ("xss_hint", current_url, stripped)
                if key not in seen_keys:
                    findings_list.append({
                        "severity": "low",
                        "title": "Potential XSS indicator from heuristic test",
                        "tool": "sqlmap",
                        "location": current_url,
                        "evidence": stripped,
                    })
                    seen_keys.add(key)

            # Confirmed injection blocks in SQLMap output (Parameter/Type/Title/Payload)
            if stripped.startswith("Parameter:"):
                if current:
                    injections.append(current)
                current = {"param": stripped.split(":", 1)[1].strip(), "url": current_url}
            elif current and stripped.startswith("Type:"):
                current["type"] = stripped.split(":", 1)[1].strip()
            elif current and stripped.startswith("Title:"):
                current["title"] = stripped.split(":", 1)[1].strip()
            elif current and stripped.startswith("Payload:"):
                current["payload"] = stripped.split(":", 1)[1].strip()
            elif current and stripped == "---":
                injections.append(current)
                current = None

        if current:
            injections.append(current)

        if injections:
            for item in injections[:12]:
                url = item.get("url") or target_url
                param = item.get("param")
                title = item.get("title") or "SQL injection detected"
                evidence_parts = [p for p in [item.get("type"), item.get("payload")] if p]
                evidence = " | ".join(evidence_parts) if evidence_parts else "Injection point detected."
                findings_list.append({
                    "severity": "high",
                    "title": f"SQL injection confirmed{(' in ' + param) if param else ''}",
                    "tool": "sqlmap",
                    "location": url,
                    "evidence": f"{title} :: {evidence}",
                })

        has_high_injection = any(
            f.get("tool") == "sqlmap" and f.get("severity") == "high" for f in findings_list
        )
        if not has_high_injection:
            method = sqlmap_methodology(command, combined_text)
            extra = " Target appears protected by WAF/CAPTCHA." if waf_hint else ""
            findings_list.append({
                "severity": "info",
                "title": "SQL injection not detected",
                "tool": "sqlmap",
                "location": target_url,
                "evidence": f"{method} No injectable parameters were confirmed in the tested input scope.{extra}",
            })

        return enrich_findings(tool_name, findings_list)
    if tool_name == "katana":
        urls = [l for l in lines if l.startswith("http")]
        if urls:
            endpoint_label = "Endpoint" if len(urls) == 1 else "Endpoints"
            findings_list.append({
                "severity": "info",
                "title": f"Endpoint Discovery - {len(urls)} {endpoint_label} Discovered",
                "tool": "katana",
                "location": target_url,
                "evidence": "\n".join(urls[:25])
            })
        else:
            findings_list.append({
                "severity": "info",
                "title": "Endpoint Discovery - 0 Endpoints Discovered",
                "tool": "katana",
                "location": target_url,
                "evidence": "Katana did not discover additional endpoints."
            })
        return enrich_findings(tool_name, findings_list)
    findings_list.append({
        "severity": "info",
        "title": f"{tool_name} scan completed",
        "tool": tool_name,
        "location": target_url,
        "evidence": "\n".join(lines[:20])
    })
    return enrich_findings(tool_name, findings_list)

def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)


def target_report_ref(target: str) -> str:
    """Stable path-safe target reference for report URLs/files."""
    raw = clean_target((target or "").strip())
    if not raw:
        return "target"

    # Backward compatibility with legacy refs like `https___example.com`.
    legacy = re.match(r"^(https?)___(.+)$", raw.lower())
    if legacy:
        raw = f"{legacy.group(1)}://{legacy.group(2)}"

    parsed = None
    if "://" in raw:
        parsed = urlparse(raw)
    elif re.match(r"^[a-z0-9.-]+(?::\d+)?(?:[/?#].*)?$", raw.lower()):
        parsed = urlparse(f"https://{raw}")

    if parsed and parsed.netloc:
        host = (parsed.hostname or parsed.netloc or "").lower()
        if host.startswith("www."):
            host = host[4:]
        parts = [host]
        if parsed.port:
            parts.append(str(parsed.port))
        path = (parsed.path or "").strip("/")
        if path:
            parts.append(path)
        if parsed.query:
            parts.append(parsed.query)
        if parsed.fragment:
            parts.append(parsed.fragment)
        ref = "_".join(p for p in parts if p)
    else:
        ref = raw.lower()

    ref = safe_filename(ref)
    ref = re.sub(r"_+", "_", ref).strip("_.-")
    return ref or "target"


def report_id_target_label(target: str) -> str:
    """Human-readable target label for report IDs (keeps protocol when available)."""
    raw = clean_target((target or "").strip())
    if not raw:
        return "target"
    legacy = re.match(r"^(https?)___(.+)$", raw.lower())
    if legacy:
        raw = f"{legacy.group(1)}://{legacy.group(2)}"
    if not raw.startswith(("http://", "https://")) and is_valid_target(raw):
        raw = normalize_target(raw)
    return raw


def build_target_report_links(target: str) -> dict:
    ref = quote(target_report_ref(target), safe="")
    return {
        "combined_html": f"/api/report/target/{ref}/html",
        "executive_html": f"/api/report/target/{ref}/executive_html",
        "technical_html": f"/api/report/target/{ref}/technical_html",
        "compliance_html": f"/api/report/target/{ref}/compliance_html",
    }


# Targets to hide/remove from production views (legacy test placeholders).
_EXCLUDED_TARGETS_RAW = {
    "?",
    "the",
}
_EXCLUDED_TARGET_REFS = {
    # Localhost / nip.io dev targets
    target_report_ref("http://127.0.0.1:8000"),
    target_report_ref("http://127.0.0.1:9001/"),
    target_report_ref("http://www.127.0.0.1.nip.io:9001/"),
    target_report_ref("http://127.0.0.1.nip.io:9001/blocked?id=1"),
    target_report_ref("http://127.0.0.1.nip.io:9002/"),
    # Generic test targets
    target_report_ref("https://example.com"),
    target_report_ref("scanme.nmap.org"),
    target_report_ref("http://testphp.vulnweb.com/listproducts.php?cat=1"),
}


def is_excluded_target(target: str) -> bool:
    """Return True when a target should be hidden/blocked (test placeholders)."""
    raw = str(target or "").strip()
    if not raw:
        return False
    if raw.strip().lower() in _EXCLUDED_TARGETS_RAW:
        return True
    try:
        return target_report_ref(raw) in _EXCLUDED_TARGET_REFS
    except Exception:
        return False


# ========== POSTURE & COMPLIANCE SUMMARY (DASHBOARD) ==========
_POSTURE_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(value: str) -> str:
    text = str(value or "").strip().lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "low" in text:
        return "low"
    return "info"


def parse_cvss_score(value) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", text)
    if not matches:
        return None
    try:
        # Use trailing numeric token to avoid pulling the "4.0" from strings like "CVSS v4.0 6.5".
        return max(0.0, min(float(matches[-1]), 10.0))
    except Exception:
        return None


def cvss_band(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def effective_severity(item: dict) -> str:
    declared = normalize_severity(item.get("severity"))
    derived = cvss_band(parse_cvss_score(item.get("cvss")))
    if _POSTURE_SEV_RANK.get(derived, 0) > _POSTURE_SEV_RANK.get(declared, 0):
        return derived
    return declared


def posture_risk_score(items: list[dict]) -> float:
    scores: list[float] = []
    for item in items or []:
        score = parse_cvss_score(item.get("cvss"))
        if score is None:
            continue
        scores.append(score)
    if scores:
        return round(max(0.0, min(max(scores), 10.0)), 1)
    counts = posture_severity_counts(items)
    if counts["critical"] > 0:
        return 9.5
    if counts["high"] > 0:
        return 8.0
    if counts["medium"] > 0:
        return 5.5
    if counts["low"] > 0:
        return 2.5
    return 0.0


def posture_risk_level(score: float, counts: dict) -> tuple[str, str]:
    if score >= 9.0 or counts.get("critical", 0) > 0:
        return ("CRITICAL", "critical")
    if score >= 7.0 or counts.get("high", 0) > 0:
        return ("HIGH", "high")
    if score >= 4.0 or counts.get("medium", 0) > 0:
        return ("MEDIUM", "medium")
    if score > 0.0 or counts.get("low", 0) > 0:
        return ("LOW", "low")
    return ("INFO", "info")


def posture_severity_counts(items: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items or []:
        sev = effective_severity(item)
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def finding_corpus(item: dict) -> str:
    return " ".join(
        [
            str(item.get("title", "")),
            str(item.get("raw_title", "")),
            str(item.get("evidence", "")),
            str(item.get("impact", "")),
            str(item.get("recommendation", "")),
            str(item.get("tool", "")),
        ]
    ).lower()


def is_assurance_observation(item: dict) -> bool:
    text = finding_corpus(item)
    markers = (
        "no sql injection evidence detected",
        "sql injection not detected",
        "sqlmap did not find injectable parameters",
        "completed without matched templates",
        "completed without actionable findings",
        "completed with no output",
        "scan completed without actionable output",
        "no endpoints discovered",
        "no scan output captured",
    )
    return any(marker in text for marker in markers)


def is_coverage_gap_observation(item: dict) -> bool:
    text = finding_corpus(item)
    markers = (
        "runtime error",
        "scan error",
        "timed out",
        "timeout",
        "execution blocked",
        "rate limited",
        "too many requests",
        "forbidden",
        "unauthorized",
        "unreachable",
        "connection refused",
        "could not resolve",
    )
    return any(marker in text for marker in markers)


def finding_themes(item: dict) -> set[str]:
    text = finding_corpus(item)
    themes: set[str] = set()
    negative_injection = is_negative_injection_signal(text) or "sql injection not detected" in text
    if (not negative_injection) and any(
        k in text for k in ("sql injection", "sqli", "injectable", "union query", "boolean-based", "time-based", "payload:")
    ):
        themes.add("injection")
    if any(
        k in text
        for k in (
            "x-frame-options",
            "frame-ancestors",
            "clickjacking",
            "x-content-type-options",
            "nosniff",
            "content-security-policy",
            "csp",
            "cors",
            "permissions-policy",
            "referrer-policy",
        )
    ):
        themes.add("security_headers")
    # Avoid using generic "https" (present in most URLs); require transport-control signals.
    if any(k in text for k in ("strict-transport-security", " hsts", "hsts ", "tls", "ssl")):
        themes.add("transport_security")
    if any(k in text for k in ("directory listing", "directory indexing", "backup", "archive", ".jks", ".zip", ".tar", ".tgz", ".war", "exposed artifact", "sensitive file exposure")):
        themes.add("sensitive_exposure")
    if "cve-" in text or any(k in text for k in ("remote code execution", " rce ", "rce vulnerability")):
        themes.add("vulnerability_exposure")
    if any(k in text for k in ("endpoint discovery", "externally reachable endpoints", "attack surface", "discovered endpoint", "discovered endpoints")):
        themes.add("attack_surface")
    if is_coverage_gap_observation(item):
        themes.add("coverage_gap")
    if is_assurance_observation(item):
        themes.add("assurance")
    return themes


_FRAMEWORK_THEME_TAGS: dict[str, dict[str, list[str]]] = {
    "injection": {
        "iso27001": ["Secure coding & input validation", "Technical vulnerability management"],
        "soc2": ["Security (TSC): vulnerability management & change control", "Security (TSC): application security monitoring"],
        "nist": ["NIST CSF: Protect (PR) / Detect (DE)", "NIST 800-53 families: SI, SA"],
        "owasp": ["OWASP Top 10 (2021): A03 Injection"],
        "cis": ["CIS Controls v8: 16 Application Software Security", "CIS Controls v8: 7 Continuous Vulnerability Management"],
        "uae_ias": ["UAE IAS: application security controls", "UAE IAS: vulnerability remediation evidence"],
    },
    "security_headers": {
        "iso27001": ["Secure configuration baseline", "Web security hardening controls"],
        "soc2": ["Security (TSC): secure configuration & system operations"],
        "nist": ["NIST CSF: Protect (PR)", "NIST 800-53 families: CM, SC"],
        "owasp": ["OWASP Top 10 (2021): A05 Security Misconfiguration"],
        "cis": ["CIS Controls v8: 4 Secure Configuration of Enterprise Assets and Software", "CIS Controls v8: 13 Network Monitoring and Defense"],
        "uae_ias": ["UAE IAS: internet-facing service hardening"],
    },
    "transport_security": {
        "iso27001": ["Network security & secure communications", "Cryptographic controls (where applicable)"],
        "soc2": ["Security (TSC): secure transmission & protection of information"],
        "nist": ["NIST CSF: Protect (PR)", "NIST 800-53 families: SC"],
        "owasp": ["OWASP Top 10 (2021): A02 Cryptographic Failures", "OWASP Top 10 (2021): A05 Security Misconfiguration"],
        "cis": ["CIS Controls v8: 12 Network Infrastructure Management", "CIS Controls v8: 3 Data Protection"],
        "uae_ias": ["UAE IAS: secure communications baseline"],
    },
    "sensitive_exposure": {
        "iso27001": ["Information classification & handling", "Secure configuration / publishing controls"],
        "soc2": ["Confidentiality/Security (TSC): data exposure prevention controls"],
        "nist": ["NIST CSF: Protect (PR)", "NIST 800-53 families: MP, SC, CM"],
        "owasp": ["OWASP Top 10 (2021): A05 Security Misconfiguration"],
        "cis": ["CIS Controls v8: 3 Data Protection", "CIS Controls v8: 8 Audit Log Management (for evidence/traceability)"],
        "uae_ias": ["UAE IAS: data handling and exposure prevention controls"],
    },
    "vulnerability_exposure": {
        "iso27001": ["Technical vulnerability management", "Patch and configuration management"],
        "soc2": ["Security (TSC): vulnerability management & remediation tracking"],
        "nist": ["NIST CSF: Identify (ID) / Protect (PR)", "NIST 800-53 families: SI, CM"],
        "owasp": ["OWASP Top 10 (2021): A06 Vulnerable and Outdated Components"],
        "cis": ["CIS Controls v8: 7 Continuous Vulnerability Management"],
        "uae_ias": ["UAE IAS: vulnerability management controls"],
    },
    "attack_surface": {
        "iso27001": ["Asset inventory & exposure governance", "Secure configuration baseline"],
        "soc2": ["Security (TSC): system operations & monitoring"],
        "nist": ["NIST CSF: Identify (ID) / Protect (PR)", "NIST 800-53 families: CM, PM"],
        "owasp": ["OWASP Testing Guide: attack surface validation (routes/endpoints)"],
        "cis": ["CIS Controls v8: 1 Inventory and Control of Enterprise Assets", "CIS Controls v8: 2 Inventory and Control of Software Assets"],
        "uae_ias": ["UAE IAS: asset exposure and service inventory validation"],
    },
    "coverage_gap": {
        "iso27001": ["Assurance evidence & retesting requirements", "Continuous improvement (ISMS)"],
        "soc2": ["Security (TSC): monitoring and incident response readiness (evidence quality)"],
        "nist": ["NIST SP 800-115: scope/limitations documentation", "NIST CSF: Govern (GV) / Identify (ID)"],
        "owasp": ["OWASP Testing Guide: document limitations and retest plan"],
        "cis": ["CIS Controls v8: 17 Incident Response Management (when blocks indicate WAF/controls)", "CIS Controls v8: 8 Audit Log Management"],
        "uae_ias": ["UAE IAS: evidence retention and retesting requirements"],
    },
}


def map_themes_to_frameworks(themes: set[str]) -> dict[str, list[str]]:
    frameworks = {
        "iso27001": [],
        "soc2": [],
        "nist": [],
        "owasp": [],
        "cis": [],
        "uae_ias": [],
    }
    for theme in sorted(themes or set()):
        mapping = _FRAMEWORK_THEME_TAGS.get(theme) or {}
        for fw, tags in mapping.items():
            if fw not in frameworks:
                continue
            for tag in tags or []:
                t = str(tag or "").strip()
                if not t:
                    continue
                if t not in frameworks[fw]:
                    frameworks[fw].append(t)
    return frameworks


def map_finding_to_frameworks(item: dict) -> dict[str, list[str]]:
    return map_themes_to_frameworks(finding_themes(item))


def merge_framework_maps(maps: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {
        "iso27001": [],
        "soc2": [],
        "nist": [],
        "owasp": [],
        "cis": [],
        "uae_ias": [],
    }
    for m in maps or []:
        if not isinstance(m, dict):
            continue
        for fw, tags in m.items():
            if fw not in merged:
                continue
            for tag in tags or []:
                t = str(tag or "").strip()
                if not t:
                    continue
                if t not in merged[fw]:
                    merged[fw].append(t)
    return merged


def _db_fetch_scans_for_user(user_id: int) -> list[sqlite3.Row]:
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, target, tool, status, results, created_at, started_at, completed_at "
        "FROM scans WHERE user_id=? ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    db.close()
    return [r for r in rows if not is_excluded_target(r["target"])]


def _select_latest_rows_by_target_ref(user_id: int) -> tuple[dict[str, dict[str, sqlite3.Row]], dict[str, str]]:
    rows = _db_fetch_scans_for_user(user_id)
    latest_target_for_ref: dict[str, str] = {}
    finished: dict[tuple[str, str], sqlite3.Row] = {}
    fallback: dict[tuple[str, str], sqlite3.Row] = {}

    for row in rows:
        target = str(row["target"] or "").strip()
        tool = str(row["tool"] or "").strip().lower()
        if not target or not tool:
            continue
        ref = target_report_ref(target)
        if ref not in latest_target_for_ref:
            latest_target_for_ref[ref] = target

        key = (ref, tool)
        if key in finished:
            continue
        if key not in fallback:
            fallback[key] = row
        status = str(row["status"] or "").strip().lower()
        if status in ("completed", "failed"):
            finished[key] = row

    selected: dict[tuple[str, str], sqlite3.Row] = {}
    for key in set(list(fallback.keys()) + list(finished.keys())):
        selected[key] = finished.get(key) or fallback.get(key)

    by_ref: dict[str, dict[str, sqlite3.Row]] = {}
    for (ref, tool), row in selected.items():
        by_ref.setdefault(ref, {})[tool] = row

    return by_ref, latest_target_for_ref


def _parse_scan_results(results_json: str) -> dict:
    if not results_json:
        return {}
    try:
        parsed = json.loads(results_json)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _build_findings_for_scan_row(row: sqlite3.Row) -> list[dict]:
    tool = str(row["tool"] or "").strip().lower()
    target = str(row["target"] or "").strip()
    status = str(row["status"] or "").strip().lower()
    results = _parse_scan_results(row["results"] or "")

    output = results.get("output", "") or ""
    error = results.get("error", "") or ""
    warning = (results.get("warning", "") or "").strip()
    command = results.get("command", "") or ""
    progress = results.get("progress")

    # Keep warnings visible in evidence for posture/compliance mapping.
    if warning:
        error = (error or "").strip()
        error = f"{error}\nWARNING: {warning}".strip() if error else f"WARNING: {warning}"

    findings = build_findings_from_output(tool, output, error, target, progress, command=command)
    # Attach scan metadata for posture views.
    for f in findings:
        f.setdefault("scan_id", row["id"])
        f.setdefault("scan_status", status)
        f.setdefault("scan_created_at", row["created_at"])
        f.setdefault("scan_completed_at", row["completed_at"])
    return findings


def compute_posture_summary(user_id: int) -> dict:
    by_ref, latest_target_for_ref = _select_latest_rows_by_target_ref(user_id)
    targets: list[dict] = []

    for ref, tool_rows in sorted(by_ref.items(), key=lambda kv: kv[0]):
        display_target = latest_target_for_ref.get(ref) or get_user_target_by_ref(user_id, ref) or ref

        selected_rows = []
        for tool_id in SUPPORTED_TOOLS:
            row = tool_rows.get(tool_id.lower())
            if row is not None:
                selected_rows.append(row)
        # Include any extra tools that may exist in the DB (future-proofing).
        for tool_id, row in tool_rows.items():
            if tool_id.lower() in [t.lower() for t in SUPPORTED_TOOLS]:
                continue
            selected_rows.append(row)

        all_findings: list[dict] = []
        for row in selected_rows:
            all_findings.extend(_build_findings_for_scan_row(row))

        counts = posture_severity_counts(all_findings)
        score = posture_risk_score(all_findings)
        level, level_class = posture_risk_level(score, counts)

        theme_counts: dict[str, int] = {}
        fw_maps: list[dict[str, list[str]]] = []
        coverage_gap = False
        for f in all_findings:
            themes = finding_themes(f)
            if "coverage_gap" in themes:
                coverage_gap = True
            for t in themes:
                theme_counts[t] = theme_counts.get(t, 0) + 1
            if effective_severity(f) != "info" or is_coverage_gap_observation(f):
                fw_maps.append(map_themes_to_frameworks(themes))

        frameworks = merge_framework_maps(fw_maps)

        # Best-effort timestamp: newest completed_at among included rows.
        last_completed = None
        last_created = None
        for row in selected_rows:
            if row["completed_at"]:
                last_completed = max(last_completed or row["completed_at"], row["completed_at"])
            if row["created_at"]:
                last_created = max(last_created or row["created_at"], row["created_at"])
        last_scan_at = last_completed or last_created

        targets.append(
            {
                "target_ref": ref,
                "target": display_target,
                "last_scan_at": last_scan_at,
                "risk": {"score": score, "level": level, "class": level_class},
                "counts": counts,
                "themes": theme_counts,
                "frameworks": frameworks,
                "coverage_gap": coverage_gap,
                "tools": {
                    str(row["tool"] or "").strip().lower(): {
                        "scan_id": row["id"],
                        "status": str(row["status"] or "").strip().lower(),
                        "created_at": row["created_at"],
                        "completed_at": row["completed_at"],
                    }
                    for row in selected_rows
                },
                "reports": build_target_report_links(ref),
            }
        )

    # Global rollups
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for t in targets:
        for k in totals:
            totals[k] += int((t.get("counts") or {}).get(k, 0) or 0)

    targets_sorted = sorted(
        targets,
        key=lambda t: (
            -float((t.get("risk") or {}).get("score") or 0.0),
            -int((t.get("counts") or {}).get("critical", 0) or 0),
            -int((t.get("counts") or {}).get("high", 0) or 0),
            str(t.get("target_ref") or ""),
        ),
    )

    framework_totals = {
        "iso27001": 0,
        "soc2": 0,
        "nist": 0,
        "owasp": 0,
        "cis": 0,
        "uae_ias": 0,
    }
    for t in targets:
        fw = t.get("frameworks") if isinstance(t.get("frameworks"), dict) else None
        if not fw:
            continue
        for key in framework_totals:
            if fw.get(key):
                framework_totals[key] += 1

    return {
        "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "stats": {
            "targets": len(targets),
            "totals": totals,
            "coverage_gaps": sum(1 for t in targets if t.get("coverage_gap")),
            "framework_targets": framework_totals,
            "top_targets": [
                {
                    "target_ref": t.get("target_ref"),
                    "target": t.get("target"),
                    "risk": t.get("risk"),
                    "counts": t.get("counts"),
                }
                for t in targets_sorted[:6]
            ],
        },
        "targets": targets_sorted,
    }


def _inline_report_css(html: str) -> str:
    css_path = BASE_DIR / "newreports" / "report.css"
    if not css_path.exists():
        return html
    try:
        css = css_path.read_text()
    except Exception:
        return html
    return html.replace('<link rel="stylesheet" href="report-styles.css">', f"<style>{css}</style>")


def _load_report_template(name: str) -> str:
    path = BASE_DIR / "newreports" / name
    return path.read_text(encoding="utf-8", errors="ignore")


def _apply_html_placeholders(html: str, mapping: dict) -> str:
    for key, value in (mapping or {}).items():
        html = html.replace(f"{{{{{key}}}}}", str(value))
    return html


async def generate_target_compliance_report(user_id: int, target_or_ref: str) -> dict:
    """Generate a separate compliance + posture report mapped to multiple standards/frameworks."""
    target = get_user_target_by_ref(user_id, target_or_ref) or str(target_or_ref or "").strip()
    target_ref = target_report_ref(target)

    # Load latest scan rows per tool for this target_ref.
    rows = _db_fetch_scans_for_user(user_id)
    finished: dict[str, sqlite3.Row] = {}
    fallback: dict[str, sqlite3.Row] = {}
    latest_target = None
    for row in rows:
        t = str(row["target"] or "").strip()
        if not t:
            continue
        if target_report_ref(t) != target_ref:
            continue
        if latest_target is None:
            latest_target = t
        tool = str(row["tool"] or "").strip().lower()
        if not tool:
            continue
        if tool in finished:
            continue
        if tool not in fallback:
            fallback[tool] = row
        status = str(row["status"] or "").strip().lower()
        if status in ("completed", "failed"):
            finished[tool] = row

    selected_rows: list[sqlite3.Row] = []
    for tool_id in REPORT_FINDINGS_ORDER:
        row = finished.get(tool_id) or fallback.get(tool_id)
        if row is not None:
            selected_rows.append(row)
    # Add any leftover tool rows.
    for tool_id, row in (finished | fallback).items():
        if tool_id in [str(r["tool"] or "").strip().lower() for r in selected_rows]:
            continue
        selected_rows.append(row)

    display_target = latest_target or target

    findings: list[dict] = []
    tool_sev_counts: dict[str, dict] = {}
    tool_statuses: dict[str, dict] = {}
    for row in selected_rows:
        tool = str(row["tool"] or "").strip().lower()
        tool_statuses[tool] = {
            "scan_id": row["id"],
            "status": str(row["status"] or "").strip().lower(),
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
        }
        tool_findings = _build_findings_for_scan_row(row)
        findings.extend(tool_findings)
        tool_sev_counts[tool] = posture_severity_counts(tool_findings)

    counts = posture_severity_counts(findings)
    score = posture_risk_score(findings)
    level, level_class = posture_risk_level(score, counts)

    # Framework aggregation + finding-level mapping.
    mapped_rows = []
    framework_maps = []
    theme_rollup: dict[str, int] = {}
    for f in sorted(findings, key=lambda it: (_POSTURE_SEV_RANK.get(effective_severity(it), 0) * -1, -(parse_cvss_score(it.get("cvss")) or 0.0))):
        themes = finding_themes(f)
        for t in themes:
            theme_rollup[t] = theme_rollup.get(t, 0) + 1
        fw_map = map_themes_to_frameworks(themes)
        framework_maps.append(fw_map)
        mapped_rows.append((f, themes, fw_map))
    frameworks = merge_framework_maps(framework_maps)

    # Build Heatmap: tool x severity
    severities = ["critical", "high", "medium", "low", "info"]
    heat_rows = []
    for tool_id in REPORT_FINDINGS_ORDER:
        c = tool_sev_counts.get(tool_id)
        if not c:
            continue
        heat_rows.append((tool_id, c))
    for tool_id, c in tool_sev_counts.items():
        if tool_id in [t for t, _ in heat_rows]:
            continue
        heat_rows.append((tool_id, c))
    heat_max = 0
    for _, c in heat_rows:
        heat_max = max(heat_max, max(int(c.get(s, 0) or 0) for s in severities))

    def heat_style(sev: str, count: int) -> str:
        base = {
            "critical": "220,38,38",
            "high": "234,88,12",
            "medium": "245,158,11",
            "low": "47,133,90",
            "info": "100,116,139",
        }.get(sev, "100,116,139")
        # Always show a subtle tint even for 0 to maintain a "heat map" look.
        intensity = 0.08 if count <= 0 else min(0.55, 0.12 + (0.43 * (count / max(1, heat_max))))
        return f"background: rgba({base}, {intensity:.3f});"

    heatmap_html_rows = []
    for tool_id, c in heat_rows:
        tname = esc_html(tool_id.upper())
        cells = []
        for sev in severities:
            count = int(c.get(sev, 0) or 0)
            cells.append(f"<td class=\"heat-cell\" style=\"{heat_style(sev, count)}\"><span class=\"heat-num\">{count}</span></td>")
        heatmap_html_rows.append(f"<tr><th class=\"heat-row\">{tname}</th>{''.join(cells)}</tr>")
    heatmap_html = (
        "<table class=\"matrix-table compliance-heatmap\">"
        "<thead><tr><th>Tool</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>"
        f"<tbody>{''.join(heatmap_html_rows) or ''}</tbody></table>"
    )

    # Framework cards
    fw_cards = []
    fw_meta = [
        ("ISO/IEC 27001", "iso27001"),
        ("SOC 2", "soc2"),
        ("NIST", "nist"),
        ("OWASP", "owasp"),
        ("CIS Controls", "cis"),
        ("UAE IAS", "uae_ias"),
    ]
    for label, key in fw_meta:
        tags = frameworks.get(key) or []
        chips = "".join([f"<span class=\"framework-chip\">{esc_html(t)}</span>" for t in tags[:10]])
        note = "No mapped issues in current evidence set." if not tags else f"{len(tags)} mapped control theme(s) triggered by findings."
        fw_cards.append(
            "<div class=\"framework-card\">"
            f"<div class=\"framework-title\">{esc_html(label)}</div>"
            f"<div class=\"framework-note\">{esc_html(note)}</div>"
            f"<div class=\"framework-chips\">{chips}</div>"
            "</div>"
        )
    frameworks_html = f"<div class=\"framework-grid\">{''.join(fw_cards)}</div>"

    # Finding mapping table
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def cvss_num(item: dict) -> float:
        return parse_cvss_score(item.get("cvss")) or 0.0

    mapped_rows_sorted = sorted(
        mapped_rows,
        key=lambda tup: (
            sev_rank.get(effective_severity(tup[0]), 4),
            -cvss_num(tup[0]),
            str(tup[0].get("title", "")),
        ),
    )
    mapping_rows_html = []
    for idx, (f, themes, fw_map) in enumerate(mapped_rows_sorted[:50], 1):
        sev = effective_severity(f)
        cvss_str = str(f.get("cvss") or "CVSS N/A")
        cvss_class = cvss_band(parse_cvss_score(f.get("cvss")))
        title = esc_html(str(f.get("title") or "Finding"))
        loc = esc_html(str(f.get("location") or display_target))
        tool = esc_html(str(f.get("tool") or "tool").upper())
        remediation = esc_html(str(f.get("recommendation") or "Apply remediation and validate with retest."))
        theme_text = ", ".join(sorted([t.replace("_", " ").title() for t in themes if t not in ("assurance",)])) or "General"
        fw_lines = []
        for label, key in fw_meta[:4]:  # keep table readable
            tags = fw_map.get(key) or []
            if not tags:
                continue
            fw_lines.append(f"<div class=\"fw-line\"><strong>{esc_html(label)}:</strong> {esc_html('; '.join(tags[:3]))}</div>")
        fw_html = "".join(fw_lines) or "<div class=\"fw-line\"><strong>Frameworks:</strong> No specific mapping tags.</div>"
        mapping_rows_html.append(
            "<tr>"
            f"<td>{idx:02d}</td>"
            f"<td><span class=\"severity-badge {sev}\">{sev.upper()}</span><div class=\"cvss-score cvss-{esc_html(cvss_class)}\">{esc_html(cvss_str)}</div></td>"
            f"<td><div class=\"map-title\">{title}</div><div class=\"map-meta\">{tool} | {loc}</div><div class=\"map-themes\">{esc_html(theme_text)}</div></td>"
            f"<td>{fw_html}</td>"
            f"<td><div class=\"map-remediation\">{remediation}</div></td>"
            "</tr>"
        )
    mapping_table_html = (
        "<table class=\"tools-table compliance-mapping-table\">"
        "<thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Framework Mapping</th><th>Remediation Summary</th></tr></thead>"
        f"<tbody>{''.join(mapping_rows_html) or ''}</tbody></table>"
    )

    # Remediation appendix grouped by themes
    theme_labels = {
        "injection": "Injection",
        "security_headers": "Security Headers",
        "transport_security": "Transport Security",
        "sensitive_exposure": "Sensitive Exposure",
        "vulnerability_exposure": "Vulnerability / CVE Exposure",
        "attack_surface": "Attack Surface",
        "coverage_gap": "Coverage Gaps / Reliability",
        "assurance": "Assurance Signals",
    }
    appendix_sections = []
    for theme_key in [
        "injection",
        "security_headers",
        "transport_security",
        "sensitive_exposure",
        "vulnerability_exposure",
        "attack_surface",
        "coverage_gap",
    ]:
        related = [f for f in findings if theme_key in finding_themes(f)]
        if not related:
            continue
        recs = []
        seen = set()
        for f in related:
            rec = str(f.get("recommendation") or "").strip()
            if not rec:
                continue
            key = rec.lower()
            if key in seen:
                continue
            seen.add(key)
            recs.append(rec)
            if len(recs) >= 6:
                break
        if not recs:
            continue
        lis = "".join([f"<li>{esc_html(r)}</li>" for r in recs])
        appendix_sections.append(
            "<div class=\"summary-box\">"
            f"<h3>{esc_html(theme_labels.get(theme_key, theme_key.title()))}</h3>"
            f"<ul>{lis}</ul>"
            "</div>"
        )
    remediation_appendix_html = "".join(appendix_sections) or "<p>No remediation appendix entries available.</p>"

    # Tool status block (coverage/recency)
    tool_status_lines = []
    for tool_id in REPORT_FINDINGS_ORDER:
        st = tool_statuses.get(tool_id)
        if not st:
            continue
        tool_status_lines.append(
            f"<li><strong>{esc_html(tool_id.upper())}</strong>: scan #{st.get('scan_id')} ({esc_html(st.get('status') or 'n/a')})</li>"
        )
    tool_status_html = "<ul>" + "".join(tool_status_lines) + "</ul>" if tool_status_lines else "<p>No scan records were available for this target.</p>"

    created_at = None
    completed_at = None
    for st in tool_statuses.values():
        if st.get("created_at"):
            created_at = min(created_at or st.get("created_at"), st.get("created_at"))
        if st.get("completed_at"):
            completed_at = max(completed_at or st.get("completed_at"), st.get("completed_at"))
    assessment_period = format_assessment_period(created_at, completed_at) or (format_abu_dhabi(created_at) or str(created_at or ""))
    report_date = format_report_datetime(created_at) or (format_abu_dhabi(created_at) or str(created_at or datetime.utcnow().isoformat()))

    # Branded logo for compliance reports.
    logo_src = resolve_report_logo_src()

    extra_css = """
    .framework-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:10px}
    .framework-card{border:1px solid var(--border-medium);border-radius:14px;background:rgba(255,255,255,0.78);padding:14px 14px 12px}
    .framework-title{font-weight:800;letter-spacing:.3px}
    .framework-note{margin-top:6px;color:var(--text-muted);font-size:10pt}
    .framework-chips{margin-top:10px;display:flex;flex-wrap:wrap;gap:6px}
    .framework-chip{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;border:1px solid var(--border-medium);background:rgba(18,59,44,0.05);font-size:9.5pt}
    .compliance-heatmap .heat-row{font-weight:800;text-transform:uppercase;letter-spacing:.6px;font-size:10pt}
    .compliance-heatmap .heat-cell{text-align:center}
    .compliance-heatmap .heat-num{font-variant-numeric:tabular-nums;font-weight:800}
    .compliance-mapping-table .map-title{font-weight:800}
    .compliance-mapping-table .map-meta{color:var(--text-muted);font-size:9.5pt;margin-top:2px}
    .compliance-mapping-table .map-themes{color:var(--text-secondary);font-size:9.5pt;margin-top:6px}
    .compliance-mapping-table .fw-line{font-size:9.5pt;color:var(--text-secondary);margin-bottom:4px}
    .compliance-mapping-table .map-remediation{font-size:9.5pt}
    @media (max-width: 900px){.framework-grid{grid-template-columns:1fr}}
    """

    template_name = "compliance.html"
    if not (BASE_DIR / "newreports" / template_name).exists():
        # Safe fallback template (kept inline if the file is missing for any reason).
        template = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
            "<title>Compliance Summary</title>"
            "<link rel=\"stylesheet\" href=\"report-styles.css\">"
            "</head><body>"
            "<div class=\"report-page cover-page page-break\">"
            "<div class=\"cover-header\"><div class=\"logo-icon\"><img src=\"{{LOGO_SRC}}\" class=\"report-logo-img\" alt=\"logo\"></div></div>"
            "<h1 class=\"cover-title\">Compliance &amp; Security Posture Summary</h1>"
            "<p class=\"cover-subtitle\">{{TARGET_URL}}</p>"
            "</div>"
            "<div class=\"report-page page-break\"><h2>Posture Snapshot</h2>{{POSTURE_SNAPSHOT_BLOCK}}</div>"
            "<div class=\"report-page page-break\"><h2>Heatmap Summary</h2>{{HEATMAP_BLOCK}}</div>"
            "<div class=\"report-page page-break\"><h2>Framework Alignment</h2>{{FRAMEWORK_BLOCK}}</div>"
            "<div class=\"report-page page-break\"><h2>Findings Mapping</h2>{{MAPPING_TABLE}}</div>"
            "<div class=\"report-page page-break\"><h2>Appendix: Remediation Summary</h2>{{REMEDIATION_APPENDIX}}</div>"
            "</body></html>"
        )
    else:
        template = _load_report_template(template_name)

    template = _inline_report_css(template)
    template = template.replace("</head>", f"<style>{extra_css}</style></head>")

    posture_snapshot = (
        "<div class=\"summary-box\">"
        "<h3>Risk Snapshot</h3>"
        f"<p><strong>Overall Rating:</strong> <span class=\"risk-badge {esc_html(level_class)}\">{esc_html(level)}</span> "
        f"<span class=\"cvss-score cvss-{esc_html(level_class)}\">CVSS v4.0 reference {score:.1f}/10</span></p>"
        f"<p><strong>Finding Distribution:</strong> Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, Low {counts['low']}, Info {counts['info']}.</p>"
        "</div>"
        "<div class=\"summary-box\">"
        "<h3>Coverage & Recency</h3>"
        f"<p><strong>Assessment Period:</strong> {esc_html(assessment_period)}</p>"
        f"{tool_status_html}"
        "</div>"
    )

    mapping = {
        "LOGO_SRC": logo_src,
        "COMPANY_NAME": PRODUCT_COMPANY_NAME,
        "SECURITY_DIVISION": PRODUCT_SECURITY_DIVISION,
        "PRODUCT_BRAND_NAME": PRODUCT_BRAND_NAME,
        "TARGET_URL": esc_html(display_target),
        "REPORT_DATE": esc_html(report_date),
        "ASSESSMENT_PERIOD": esc_html(assessment_period),
        "REPORT_ID": esc_html(f"ASH-COMPLIANCE-{report_id_target_label(display_target)}"),
        "POSTURE_SNAPSHOT_BLOCK": posture_snapshot,
        "HEATMAP_BLOCK": heatmap_html,
        "FRAMEWORK_BLOCK": frameworks_html,
        "MAPPING_TABLE": mapping_table_html,
        "REMEDIATION_APPENDIX": remediation_appendix_html,
    }

    html = _apply_html_placeholders(template, mapping)
    report_file = REPORTS_DIR / f"report_target_{target_ref}_compliance.html"
    write_text_atomic(report_file, html)
    return {"html_path": str(report_file), "target_ref": target_ref}


def ensure_target_compliance_report_file(user_id: int, target_or_ref: str) -> bool:
    target = get_user_target_by_ref(user_id, target_or_ref)
    if not target:
        return False
    safe = target_report_ref(target)
    path = REPORTS_DIR / f"report_target_{safe}_compliance.html"
    needs_regen = (not path.exists()) or has_unresolved_placeholders(path) or report_templates_newer_than(path)
    if not needs_regen:
        latest_scan_ts = latest_finished_scan_ts_for_target_ref(user_id, safe)
        if latest_scan_ts:
            try:
                report_dt = datetime.utcfromtimestamp(path.stat().st_mtime)
                if report_dt < latest_scan_ts:
                    needs_regen = True
            except Exception:
                needs_regen = True
    if needs_regen:
        asyncio.run(generate_target_compliance_report(user_id, safe))
    return True


def write_text_atomic(path: Path, content: str) -> None:
    """Write file content without requiring ownership of an existing destination file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)


def has_unresolved_placeholders(path: Path) -> bool:
    """Detect stale or unreadable report content that should be regenerated."""
    try:
        if not path.exists():
            return False
        text = path.read_text(errors="ignore")
        stale_markers = [
            "{{TOC_BLOCK}}",
            "{{TARGET_",
            "{{REPORT_",
            "{{TOOLS_APPENDIX_ROWS}}",
            "{{TESTING_PHASE_ROWS}}",
            "{{GLOSSARY_BLOCK}}",
            "projectdiscovery.io",
            "Current katana version",
            "Started standard crawling for =>",
            "__        __",
            "␛[",
            "\u001b[",
        ]
        return any(marker in text for marker in stale_markers)
    except Exception:
        return False

def extract_host(value: str) -> str:
    value = clean_target(value.strip().lower())
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    host = parsed.netloc or parsed.path
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host

def is_valid_target(target: str) -> bool:
    if not target:
        return False
    target = clean_target(target.strip().lower())
    if target in ("the", "a", "an", "target", "this", "that", "?"):
        return False
    host = extract_host(target)
    if not host:
        return False
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return True
    return False


def _probe_tcp_connectivity(host: str, port: int, timeout_seconds: float) -> tuple[bool, str]:
    """Check whether at least one resolved address is reachable over TCP."""
    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as exc:
        return False, f"DNS resolution failed for {host}:{port} ({exc})"

    tried_ips = []
    seen = set()
    for info in addrinfo:
        ip = info[4][0]
        if ip in seen:
            continue
        seen.add(ip)
        tried_ips.append(ip)
        try:
            with socket.create_connection((ip, port), timeout=timeout_seconds):
                return True, f"reachable via {ip}:{port}"
        except Exception:
            continue

    shown = ", ".join(tried_ips[:6]) + (" ..." if len(tried_ips) > 6 else "")
    return False, f"no TCP path to {host}:{port}; resolved: {shown or 'none'}"


def _probe_http_semantics(
    host: str,
    port: int,
    scheme: str,
    timeout_seconds: float,
    *,
    path: str = "/",
) -> tuple[bool, str, int | None]:
    """
    Best-effort application-level probe to distinguish HTTP vs HTTPS on a reachable TCP port.

    Returns (ok, detail, http_status). This is intentionally lightweight and tolerant:
    - Any valid HTTP status line (including 401/403/404/429) counts as "ok".
    - TLS verification is disabled for the probe (we only need to know whether TLS speaks).
    """
    scheme = (scheme or "").strip().lower()
    if scheme not in ("http", "https"):
        return False, f"unsupported scheme {scheme!r}", None

    req_path = (path or "/").strip()
    if not req_path.startswith("/"):
        req_path = "/" + req_path
    # Avoid huge/invalid probe paths; preflight only needs the protocol banner.
    req_path = req_path.split("?", 1)[0][:512] or "/"

    request_bytes = (
        f"GET {req_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: ai-pentest-preflight/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")

    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as exc:
        return False, f"DNS resolution failed for {host}:{port} ({exc})", None

    # IMPORTANT: CDNs frequently return multiple IPs. We must try each resolved IP because
    # an arbitrary `socket.create_connection((host, port))` may pick an unroutable address.
    ips: list[str] = []
    seen: set[str] = set()
    for info in addrinfo:
        ip = info[4][0]
        if ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)
    if not ips:
        return False, f"no resolved addresses for {host}:{port}", None

    last_detail = ""
    for ip in ips[:12]:
        try:
            raw_sock = socket.create_connection((ip, port), timeout=timeout_seconds)
        except Exception as exc:
            last_detail = f"tcp connect failed via {ip}:{port} ({exc})"
            continue

        try:
            raw_sock.settimeout(timeout_seconds)
            sock = raw_sock
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    # Use SNI hostname even when connecting to a specific IP.
                    sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                except ssl.SSLError as exc:
                    last_detail = f"tls handshake failed via {ip}:{port} ({exc})"
                    continue

            try:
                sock.sendall(request_bytes)
            except Exception as exc:
                last_detail = f"write failed via {ip}:{port} ({exc})"
                continue

            try:
                data = sock.recv(1024) or b""
            except Exception as exc:
                last_detail = f"read failed via {ip}:{port} ({exc})"
                continue

            if not data.startswith(b"HTTP/"):
                shown = data[:12]
                last_detail = f"unexpected banner via {ip}:{port} {shown!r}"
                continue

            # Parse status code (best effort).
            status = None
            try:
                first_line = data.split(b"\r\n", 1)[0]
                parts = first_line.split()
                if len(parts) >= 2:
                    status = int(parts[1])
            except Exception:
                status = None

            detail = f"HTTP {status}" if status is not None else "received HTTP response"
            return True, f"{detail} via {ip}:{port}", status
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass

    tail = "; ".join(ips[:6]) + (" ..." if len(ips) > 6 else "")
    return False, f"{last_detail or 'no HTTP response'} (resolved: {tail})", None


def _parse_duration_seconds(value: str, default_seconds: int) -> int:
    """
    Parse a simple duration string into seconds.

    Supports:
    - "90" (seconds)
    - "90s", "5m", "2h", "1d"

    Katana's `-ct` expects a numeric value (seconds) in many builds; passing "90s" can lead to
    unbounded crawls. We normalize to an integer seconds string for CLI usage.
    """
    raw = str(value or "").strip().lower()
    if not raw:
        return int(default_seconds)
    m = re.fullmatch(r"(\d+)([smhd]?)", raw)
    if not m:
        return int(default_seconds)
    amount = int(m.group(1))
    unit = m.group(2) or "s"
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 1)
    seconds = amount * mult
    # Avoid 0s (which can act like "no limit" in some tools).
    return max(1, int(seconds))


def _url_with_scheme(url: str, scheme: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme:
        return parsed._replace(scheme=scheme).geturl()
    return f"{scheme}://{url}"


def _url_with_host(url: str, host: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{host}"
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    port_part = f":{parsed.port}" if parsed.port else ""
    return parsed._replace(netloc=f"{userinfo}{host}{port_part}").geturl()


def _base_domain(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def _normalize_discovered_url(
    candidate: str,
    *,
    preferred_scheme: str,
    preferred_host: str,
    preferred_port: int | None,
    base_domain: str,
    allow_subdomains: bool,
) -> str | None:
    """
    Normalize URLs harvested from crawlers (Katana/Nikto/etc.) so they can be used as SQLMap targets.

    Goals:
    - Accept absolute URLs and relative paths.
    - Keep scans scoped to the provided host by default (rewrite simple www variants).
    - Drop obviously invalid JS string fragments produced by JS parsing.
    - Ensure query-string parameters have non-empty values (SQLMap needs real values).
    """
    raw = (candidate or "").strip()
    if not raw:
        return None

    # Trim common wrappers/punctuation from tool outputs.
    raw = raw.strip().strip("\"'<>")
    raw = raw.rstrip(").,;")
    if not raw:
        return None

    # Filter obvious JS concatenation fragments and malformed URL strings.
    lowered = raw.lower()
    if any(bad in lowered for bad in ("concat(", "').concat", "\".concat", "+'")):
        return None
    if any(ch in raw for ch in (" ", "\\", "{", "}", "[", "]")):
        return None

    # Build an absolute URL.
    preferred_netloc = preferred_host
    if preferred_port is not None:
        preferred_netloc = f"{preferred_host}:{preferred_port}"

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
    elif raw.startswith("/"):
        parsed = urlparse(f"{preferred_scheme}://{preferred_netloc}{raw}")
    elif base_domain and raw.startswith(base_domain):
        # e.g. "example.com/path?x=1"
        parsed = urlparse(f"{preferred_scheme}://{raw}")
    else:
        return None

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None

    target_host = (preferred_host or "").strip().lower()
    if target_host:
        if host != target_host:
            # Allow apex <-> www without rewriting: some sites serve different content on each host.
            if host.lstrip("www.") == target_host.lstrip("www."):
                pass
            elif not (allow_subdomains and base_domain and (host == base_domain or host.endswith("." + base_domain))):
                return None

    # If the user provided an explicit port for the scan target, keep discovery scoped to that port.
    if preferred_port is not None:
        eff_scheme = (parsed.scheme or preferred_scheme or "https").lower()
        eff_port = parsed.port
        if eff_port is None:
            eff_port = 443 if eff_scheme == "https" else 80
        if eff_port != preferred_port:
            return None

    path = parsed.path or "/"
    # Skip obvious static assets even if query params exist (avoid wasting SQLMap time).
    static_ext = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip)$", re.IGNORECASE)
    if path and static_ext.search(path):
        return None

    # SQLMap needs real query param values. Replace empty/placeholder values with '1'.
    qsl = parse_qsl(parsed.query or "", keep_blank_values=True)
    if not qsl:
        return None
    normalized_qsl = []
    for k, v in qsl:
        key = (k or "").strip()
        if not key:
            continue
        val = (v or "").strip()
        if (not val) or (val.upper() == "EXPR"):
            val = "1"
        normalized_qsl.append((key, val))
    if not normalized_qsl:
        return None

    netloc = host + (f":{parsed.port}" if parsed.port else "")
    query = urlencode(normalized_qsl, doseq=True)
    # Preserve scheme for absolute URLs (to allow http/https discovery),
    # but still apply preferred scheme for relative/path-only candidates.
    scheme = parsed.scheme or preferred_scheme or "https"
    return urlunparse((scheme, netloc, path, "", query, ""))

def _extract_param_urls_from_lines(
    lines,
    base_domain: str,
    max_urls: int,
    *,
    preferred_scheme: str,
    preferred_host: str,
    preferred_port: int | None,
    allow_subdomains: bool,
) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    base_domain = (base_domain or "").lower()
    for line in lines:
        cleaned = _normalize_discovered_url(
            str(line or ""),
            preferred_scheme=preferred_scheme,
            preferred_host=preferred_host,
            preferred_port=preferred_port,
            base_domain=base_domain,
            allow_subdomains=allow_subdomains,
        )
        if not cleaned:
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        urls.append(cleaned)
        if len(urls) >= max_urls:
            break
    return urls


def _extract_param_urls(
    output: str,
    base_domain: str,
    max_urls: int | None = None,
    *,
    preferred_scheme: str,
    preferred_host: str,
    preferred_port: int | None,
    allow_subdomains: bool,
    # Backward-compat alias: older code passed max_targets=... which caused runtime crashes.
    max_targets: int | None = None,
) -> list[str]:
    if not output:
        return []
    if max_urls is None:
        max_urls = max_targets if max_targets is not None else 25
    return _extract_param_urls_from_lines(
        output.splitlines(),
        base_domain,
        max_urls,
        preferred_scheme=preferred_scheme,
        preferred_host=preferred_host,
        preferred_port=preferred_port,
        allow_subdomains=allow_subdomains,
    )

def _extract_param_candidates_from_nikto_output(output: str) -> list[str]:
    """Extract likely parameterized URL/path candidates from Nikto findings."""
    text = clean_scan_text(output or "")
    if not text:
        return []
    candidates: list[str] = []
    for raw_line in text.splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        if line.startswith("+"):
            line = line.lstrip("+").strip()
        # Prefer full URLs when present.
        m = re.search(r"(https?://[^\s]+\\?[^\s]+)", line, re.IGNORECASE)
        if m:
            candidates.append(m.group(1))
            continue
        # Nikto often reports as "/path: Finding text".
        m = re.search(r"(/[^\\s:]+\\?[^\\s:]+)", line)
        if m:
            candidates.append(m.group(1))
    return candidates


def _latest_katana_output_for_target(scan_id: int, target: str) -> str:
    """Fetch latest katana output for the same user/target (fallback to same host)."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    user_id = row["user_id"] if row else None
    if not user_id:
        db.close()
        return ""
    cur.execute(
        "SELECT target, results FROM scans WHERE user_id=? AND tool='katana' ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    db.close()
    if not rows:
        return ""
    # Prefer exact target match.
    for r in rows:
        if str(r["target"] or "") == str(target or ""):
            try:
                results = json.loads(r["results"] or "{}")
                return results.get("output", "") or ""
            except Exception:
                return ""
    # Fallback: same host match.
    target_host = extract_host(target)
    if not target_host:
        return ""
    for r in rows:
        if extract_host(r["target"]) == target_host:
            try:
                results = json.loads(r["results"] or "{}")
                return results.get("output", "") or ""
            except Exception:
                return ""
    return ""

def _latest_nikto_output_for_target(scan_id: int, target: str) -> str:
    """Fetch latest nikto output for the same user/target (fallback to same host)."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    user_id = row["user_id"] if row else None
    if not user_id:
        db.close()
        return ""
    cur.execute(
        "SELECT target, results FROM scans WHERE user_id=? AND tool='nikto' ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    db.close()
    if not rows:
        return ""
    # Prefer exact target match.
    for r in rows:
        if str(r["target"] or "") == str(target or ""):
            try:
                results = json.loads(r["results"] or "{}")
                return results.get("output", "") or ""
            except Exception:
                return ""
    # Fallback: same host match.
    target_host = extract_host(target)
    if not target_host:
        return ""
    for r in rows:
        if extract_host(r["target"]) == target_host:
            try:
                results = json.loads(r["results"] or "{}")
                return results.get("output", "") or ""
            except Exception:
                return ""
    return ""

def _latest_katana_output_file_for_target(scan_id: int, target: str) -> str | None:
    """Return path to latest katana output file for the same user/target (fallback to same host)."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    user_id = row["user_id"] if row else None
    if not user_id:
        db.close()
        return None
    cur.execute(
        "SELECT target, results FROM scans WHERE user_id=? AND tool='katana' ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    db.close()
    if not rows:
        return None

    def pick_file(results_json: str) -> str | None:
        if not results_json:
            return None
        try:
            results = json.loads(results_json) or {}
        except Exception:
            return None
        path = str(results.get("katana_output_file") or "").strip()
        if not path:
            return None
        try:
            p = Path(path)
            return str(p) if p.exists() else None
        except Exception:
            return None

    # Prefer exact target match.
    for r in rows:
        if str(r["target"] or "") == str(target or ""):
            return pick_file(r["results"] or "")

    # Fallback: same host match.
    target_host = extract_host(target)
    if not target_host:
        return None
    for r in rows:
        if extract_host(r["target"]) == target_host:
            return pick_file(r["results"] or "")
    return None


def prepare_sqlmap_target(target: str) -> tuple[str, str | None, str | None]:
    """
    Validate target reachability for SQLMap.
    Returns: (possibly adjusted target, error_message, warning_message)
    """
    if str(os.getenv("SQLMAP_PREFLIGHT", "1")).strip().lower() in ("0", "false", "no", "off"):
        return target, None, None

    parsed = urlparse(target)
    host = parsed.hostname
    scheme = (parsed.scheme or "http").lower()
    if not host:
        return target, f"Invalid SQLMap target URL: {target}", None

    timeout_seconds = float(os.getenv("SQLMAP_PREFLIGHT_TIMEOUT", "3"))
    http_probe_enabled = str(os.getenv("SQLMAP_PREFLIGHT_HTTP_PROBE", "1")).strip().lower() not in ("0", "false", "no", "off")
    explicit_port = parsed.port is not None
    probe_path = parsed.path or "/"

    def _build_url(sch: str, h: str) -> str:
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        port_part = f":{parsed.port}" if explicit_port and parsed.port is not None else ""
        netloc = f"{userinfo}{h}{port_part}"
        return urlunparse((sch, netloc, parsed.path or "/", parsed.params or "", parsed.query or "", parsed.fragment or ""))

    # Candidate hosts: original first, then (optionally) www/apex variant.
    host_candidates: list[str] = [host]
    try_www = str(os.getenv("SQLMAP_TRY_WWW_FALLBACK", "1")).strip().lower() not in ("0", "false", "no", "off")
    is_ip = re.match(r"^\\d{1,3}(?:\\.\\d{1,3}){3}$", host) is not None
    if try_www and (not is_ip) and host not in ("localhost",) and "." in host:
        apex = host[4:] if host.startswith("www.") else host
        www = f"www.{apex}"
        if host.startswith("www."):
            if apex not in host_candidates:
                host_candidates.append(apex)
        else:
            if www not in host_candidates:
                host_candidates.append(www)

    # Candidate schemes: original first, then alternate. For explicit ports, we test both schemes
    # on the same port to avoid "TCP reachable but wrong protocol" failures.
    alt_scheme = "http" if scheme == "https" else "https"
    scheme_candidates = [scheme]
    if alt_scheme not in scheme_candidates:
        scheme_candidates.append(alt_scheme)

    primary_port = parsed.port if explicit_port and parsed.port is not None else (443 if scheme == "https" else 80)
    probe_notes: list[str] = []
    first_tcp_ok_note = None

    def _status_score(code: int | None) -> int:
        if code is None:
            return 0
        if 200 <= code < 300:
            return 100
        if code in (401, 403, 404, 405, 406, 429):
            # Still a strong signal that the protocol/host is correct (even if access is blocked).
            return 80
        if 300 <= code < 400:
            return 60
        if 500 <= code < 600:
            return 40
        return 50

    # Evaluate all candidates and pick the best (instead of returning the first responder).
    best: list[tuple[int, str, str | None]] = []
    for h in host_candidates:
        for sch in scheme_candidates:
            port = parsed.port if explicit_port and parsed.port is not None else (443 if sch == "https" else 80)
            ok_tcp, tcp_detail = _probe_tcp_connectivity(h, port, timeout_seconds)
            probe_notes.append(f"{sch.upper()} {h}:{port} tcp={ok_tcp} ({tcp_detail})")
            if not ok_tcp:
                continue
            if first_tcp_ok_note is None:
                first_tcp_ok_note = f"{sch.upper()} {h}:{port} ({tcp_detail})"

            status_code = None
            if http_probe_enabled:
                ok_proto, proto_detail, status_code = _probe_http_semantics(h, port, sch, timeout_seconds, path=probe_path)
                probe_notes.append(f"{sch.upper()} {h}:{port} proto={ok_proto} ({proto_detail})")
                if not ok_proto:
                    continue

            candidate_url = _build_url(sch, h)
            candidate_warning = None
            if (h != host) or (sch != scheme):
                candidate_warning = (
                    f"SQLMap target preflight adjusted endpoint: requested {scheme.upper()} {host}:{primary_port} "
                    f"but using {sch.upper()} {h}:{port}."
                )

            score = _status_score(status_code)
            # Prefer HTTPS when otherwise equivalent (reduces redirects and matches modern defaults).
            if sch == "https":
                score += 5
            # Small preference to keep the user-supplied host/scheme when equally good.
            if h == host:
                score += 2
            if sch == scheme:
                score += 1

            best.append((score, candidate_url, candidate_warning))

    if best:
        best.sort(key=lambda item: item[0], reverse=True)
        score, chosen_url, chosen_warning = best[0]
        return chosen_url, None, chosen_warning

    # If TCP is reachable somewhere but we couldn't validate protocol, don't hard-fail.
    if http_probe_enabled and first_tcp_ok_note:
        warning = (
            f"SQLMap preflight: target is TCP-reachable ({first_tcp_ok_note}) but did not return a recognizable "
            f"{scheme.upper()} HTTP response during preflight. Proceeding with requested URL; scans may fail if "
            "the protocol is incorrect or access is blocked."
        )
        return target, None, warning

    tail = "; ".join(probe_notes[:6]) + (" ..." if len(probe_notes) > 6 else "")
    err = f"Target unreachable from scanner network for SQLMap. Probes: {tail or 'none'}"
    return target, err, None


def sqlmap_discovery_targets(target: str) -> list[str]:
    """
    Generate a small set of base URLs (http/https + apex/www variants) for discovery.
    We keep variants that are reachable and (optionally) respond with expected HTTP/TLS semantics
    to avoid wasting crawl time on wrong-scheme endpoints.
    """
    raw = (target or "").strip()
    if not raw:
        return []
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").strip().lower()
    port = parsed.port
    path = parsed.path or "/"

    hosts = []
    if host:
        hosts.append(host)
        is_ip = re.match(r"^\\d{1,3}(?:\\.\\d{1,3}){3}$", host) is not None
        if (not is_ip) and host not in ("localhost",) and "." in host:
            if host.startswith("www."):
                hosts.append(host[4:])
            else:
                hosts.append(f"www.{host}")

    schemes = [scheme]
    alt_scheme = "https" if scheme == "http" else "http"
    if alt_scheme not in schemes:
        schemes.append(alt_scheme)

    candidates = []
    for sch in schemes:
        for h in hosts:
            netloc = h + (f":{port}" if port else "")
            candidates.append(urlunparse((sch, netloc, path, "", "", "")))

    # De-duplicate while preserving order.
    unique = []
    seen = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        unique.append(c)

    timeout_seconds = float(os.getenv("SQLMAP_PREFLIGHT_TIMEOUT", "3"))
    http_probe_enabled = str(os.getenv("SQLMAP_DISCOVERY_HTTP_PROBE", "1")).strip().lower() not in ("0", "false", "no", "off")
    def _status_score(code: int | None) -> int:
        if code is None:
            return 0
        if 200 <= code < 300:
            return 100
        if code in (401, 403, 404, 405, 406, 429):
            return 80
        if 300 <= code < 400:
            return 60
        if 500 <= code < 600:
            return 40
        return 50

    reachable: list[tuple[int, str]] = []
    for c in unique:
        try:
            p = urlparse(c)
            h = p.hostname
            if not h:
                continue
            prt = p.port or (443 if (p.scheme or "").lower() == "https" else 80)
            ok, _ = _probe_tcp_connectivity(h, prt, timeout_seconds)
            if not ok:
                continue
            status_code = None
            if http_probe_enabled:
                ok_proto, _, status_code = _probe_http_semantics(h, prt, (p.scheme or "http").lower(), timeout_seconds, path=path)
                if not ok_proto:
                    continue
            score = _status_score(status_code)
            if (p.scheme or "").lower() == "https":
                score += 5
            if h == host:
                score += 2
            reachable.append((score, c))
        except Exception:
            continue

    if reachable:
        reachable.sort(key=lambda item: item[0], reverse=True)
        return [c for _, c in reachable]
    return [raw]


def sqlmap_connection_failure_reason(output: str, err: str, timed_out: bool) -> str | None:
    combined = f"{output or ''}\n{err or ''}".strip()
    text = combined.lower()
    if not text:
        return None

    # If SQLMap clearly reached parameter testing, do not treat incidental HTTP errors
    # (e.g. intermittent 403s from WAF/CDN) as a full execution block.
    tested_vectors = any(
        marker in text
        for marker in (
            "testing for sql injection on",
            "does not seem to be injectable",
            "all tested parameters do not appear to be injectable",
            "is injectable",
            "is vulnerable",
            "back-end dbms",
        )
    )
    # sqlmap also reports technique probes as: "[INFO] testing '...'"
    # Treat those as "testing started" so connection warnings don't incorrectly fail the scan.
    if (not tested_vectors) and re.search(r"\\btesting\\s+'[^']+'", combined, re.IGNORECASE):
        tested_vectors = True

    # Prefer explicit SQLMap [ERROR] lines (sqlmap often prints these to stdout, not stderr).
    m = re.search(r"\\[error\\]\\s+(.+)", combined, re.IGNORECASE)
    if m:
        err_line = m.group(1).strip()
        lower_line = err_line.lower()
        # SQLMap uses [ERROR] for negative scan conclusions too; don't treat those as execution failures.
        if (
            "all tested parameters do not appear to be injectable" in lower_line
            or is_negative_injection_signal(lower_line)
        ):
            return None
        if "not authorized" in lower_line or "unauthorized" in lower_line or "(401" in lower_line or " 401" in lower_line:
            return "SQLMap received HTTP 401 Unauthorized from the target (authentication required or access blocked)."
        if "forbidden" in lower_line or "(403" in lower_line or " 403" in lower_line:
            return "SQLMap received HTTP 403 Forbidden from the target (access denied)."
        if "too many requests" in lower_line or "(429" in lower_line or " 429" in lower_line:
            return "SQLMap received HTTP 429 Too Many Requests from the target (rate limiting)."
        if "not found" in lower_line or "(404" in lower_line or " 404" in lower_line:
            return "SQLMap received HTTP 404 Not Found from the target (endpoint missing or blocked)."
        # If SQLMap progressed into testing, treat late [ERROR] lines as partial coverage.
        if tested_vectors and any(k in lower_line for k in ("unable to connect", "connection refused", "timed out")):
            return None
        return f"SQLMap reported a runtime error: {err_line[:180]}"

    known = [
        ("can't establish ssl connection", "SQLMap could not establish SSL/TLS connection to the target."),
        ("unable to connect to the target url", "SQLMap could not connect to the target URL."),
        ("connection timed out to the target url", "SQLMap connection to the target URL timed out."),
        ("connection refused", "SQLMap connection was refused by the target host."),
        ("name or service not known", "SQLMap could not resolve the target host."),
    ]
    for marker, reason in known:
        if marker in text:
            return None if tested_vectors else reason

    # Detect common HTTP failures surfaced as warnings/summary blocks.
    if (
        "http error codes detected" in text
        or "not authorized" in text
        or "unauthorized" in text
        or "forbidden" in text
        or "too many requests" in text
    ):
        # When payload tests ran, treat HTTP codes as partial coverage, not a hard block.
        if tested_vectors:
            return None
        codes = sorted(set(re.findall(r"\\b([45]\\d{2})\\b", text)))
        if "401" in codes or "not authorized" in text or "unauthorized" in text:
            return "SQLMap received HTTP 401 Unauthorized from the target (authentication required or access blocked)."
        if "403" in codes or "forbidden" in text:
            return "SQLMap received HTTP 403 Forbidden from the target (access denied)."
        if "429" in codes or "too many requests" in text:
            return "SQLMap received HTTP 429 Too Many Requests from the target (rate limiting)."
        server_codes = [c for c in codes if c.startswith("5")]
        if server_codes or "internal server error" in text:
            label = ", ".join(server_codes) if server_codes else "5xx"
            return f"SQLMap encountered server-side HTTP errors ({label}) while testing the target."
        if "404" in codes or "not found" in text:
            return "SQLMap received HTTP 404 Not Found from the target (endpoint missing or blocked)."
        if codes:
            return f"SQLMap encountered HTTP errors during execution (HTTP {', '.join(codes)})."

    if (
        ("testing connection to the target url" in text)
        and (
            timed_out
            or "scan timed out" in text
            or "timed out after" in text
        )
    ):
        return None if tested_vectors else "SQLMap timed out while testing initial target connectivity."
    return None


def _sqlmap_latest_results_csv(output_dir: Path) -> Path | None:
    """Locate the newest sqlmap multi-target results CSV (results-*.csv) within an output directory."""
    try:
        if not output_dir:
            return None
        output_dir = Path(str(output_dir))
        if not output_dir.exists() or not output_dir.is_dir():
            return None
        candidates = [p for p in output_dir.glob("results-*.csv") if p.is_file() and not p.name.startswith(".~lock.")]
        if not candidates:
            return None
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return candidates[0]
    except Exception:
        return None


def _sqlmap_parse_results_csv(path: Path) -> list[dict]:
    """Parse sqlmap multi-target results CSV into rows (dicts)."""
    rows: list[dict] = []
    try:
        p = Path(str(path))
        if not p.exists() or not p.is_file():
            return rows
        with p.open("r", newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for raw in reader:
                if not raw:
                    continue
                cleaned = {}
                for k, v in raw.items():
                    key = (k or "").strip()
                    if not key:
                        continue
                    cleaned[key] = (v or "").strip()
                if not any(cleaned.values()):
                    continue
                rows.append(cleaned)
    except Exception:
        return rows
    return rows


def update_scan_db(scan_id, status, results=None):
    db = get_db()
    cur = db.cursor()
    
    if status == "running":
        cur.execute(
            "UPDATE scans SET status=?, started_at=COALESCE(started_at, CURRENT_TIMESTAMP), completed_at=NULL WHERE id=?",
            (status, scan_id),
        )
    elif status == "completed" or status == "failed":
        cur.execute("UPDATE scans SET status=?, completed_at=CURRENT_TIMESTAMP WHERE id=?", (status, scan_id))
    else:
        cur.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    
    if results:
        cur.execute("UPDATE scans SET results=? WHERE id=?", (json.dumps(results), scan_id))
    
    db.commit()
    db.close()
    print(f"📊 Scan {scan_id} -> {status}")


def reconcile_orphaned_scans(max_age_minutes: int = 30) -> int:
    """
    Mark stale pending/running scans as failed after service interruptions.
    This avoids permanently stuck scans being shown as active.
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, tool, target, status, created_at, started_at, results "
        "FROM scans WHERE status IN ('pending', 'running')"
    )
    rows = cur.fetchall()
    now_dt = datetime.utcnow()
    fixed = 0

    for row in rows:
        started_or_created = row["started_at"] or row["created_at"]
        base_dt = parse_ts(started_or_created)
        if not base_dt:
            continue
        age_minutes = (now_dt - base_dt).total_seconds() / 60.0
        if age_minutes < max_age_minutes:
            continue

        status = str(row["status"] or "").lower()
        if status == "running":
            reason = (
                "Scan interrupted (service restart/worker stop). "
                "Marked failed by startup reconciliation."
            )
        else:
            reason = (
                "Scan remained pending past execution window. "
                "Marked failed by startup reconciliation."
            )

        try:
            results = json.loads(row["results"]) if row["results"] else {}
        except Exception:
            results = {}

        existing_error = str(results.get("error") or "").strip()
        if existing_error:
            if reason.lower() not in existing_error.lower():
                results["error"] = f"{existing_error} {reason}"
        else:
            results["error"] = reason
        results["success"] = False
        results["reconciled"] = True
        results["reconciled_at"] = now_dt.isoformat()

        cur.execute(
            "UPDATE scans SET status='failed', completed_at=CURRENT_TIMESTAMP, results=? WHERE id=?",
            (json.dumps(results), row["id"]),
        )
        fixed += 1

    db.commit()
    db.close()
    return fixed


async def run_scan_async(scan_id: int, target: str, tool: str):
    """Run security scan with proper error handling"""
    print(f"🚀 Starting scan {scan_id}: {tool} on {target}")
    update_scan_db(scan_id, "running")
    
    # Ensure target has protocol
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    log_file = LOG_DIR / f"scan_{scan_id}.log"
    start_ts = time.time()
    results = {
        "tool": tool,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "command": "",
        "output": "",
        "error": "",
        "success": False
    }
    
    try:
        # Preflight all web targets once so every scanner (katana/nikto/nuclei/sqlmap)
        # benefits from scheme + www/apex fallback before command execution.
        preflight_target, preflight_error, preflight_warning = prepare_sqlmap_target(target)
        if preflight_error:
            err_text = str(preflight_error).replace("for SQLMap", f"for {str(tool).upper()}")
            results["error"] = err_text
            update_scan_db(scan_id, "failed", results)
            return
        if preflight_warning:
            warn_text = str(preflight_warning)
            warn_text = warn_text.replace("SQLMap target preflight", f"{str(tool).upper()} target preflight")
            warn_text = warn_text.replace("SQLMap preflight", f"{str(tool).upper()} preflight")
            results["warning"] = warn_text
        target = preflight_target
        results["target"] = target
        try:
            update_scan_db(scan_id, "running", results)
        except Exception:
            pass

        # Build proper commands for each tool
        if tool == "nuclei":
            if not NUCLEI_TEMPLATES_DIR.exists() or not any(NUCLEI_TEMPLATES_DIR.rglob("*.yaml")):
                results["error"] = f"Nuclei templates not found. Install templates under {TOOLS_DIR / 'nuclei-templates'}."
                update_scan_db(scan_id, "failed", results)
                return
            nuclei_severity = os.getenv("NUCLEI_SEVERITY", "critical,high,medium")
            nuclei_rl = os.getenv("NUCLEI_RATE_LIMIT", "25")
            nuclei_conc = os.getenv("NUCLEI_CONCURRENCY", "8")
            nuclei_tags = os.getenv("NUCLEI_TAGS", "light,quick,probing,http,misconfiguration")
            nuclei_exclude_tags = os.getenv("NUCLEI_EXCLUDE_TAGS", "dns,headless,tcp,ssl,ssl-enum,smb,ftp,ssh,rdp,heavy")
            nuclei_protocol_type = os.getenv("NUCLEI_PROTOCOL_TYPE", "http").strip()
            cmd = [
                str(TOOLS_DIR / "nuclei"),
                "-u", target,
                "-silent",
                "-timeout", os.getenv("NUCLEI_REQUEST_TIMEOUT", "20"),
                "-severity", nuclei_severity,
                "-rate-limit", nuclei_rl,
                "-c", nuclei_conc,
                "-tags", nuclei_tags,
                "-etags", nuclei_exclude_tags,
                "-duc",
                "-stats",
                "-stats-interval", "2",
                "-t", str(NUCLEI_TEMPLATES_DIR)
            ]
            if nuclei_protocol_type:
                cmd.extend(["-pt", nuclei_protocol_type])
            results["command"] = " ".join(cmd)
            
        elif tool == "nikto":
            perl_bin = shutil.which("perl")
            if not perl_bin:
                results["error"] = "Perl not found in PATH. Install perl to run Nikto."
                update_scan_db(scan_id, "failed", results)
                return
            parsed = urlparse(target)
            target_for_nikto = target
            extra_flags = []
            if parsed.scheme == "https":
                extra_flags.append("-ssl")
            elif not parsed.scheme:
                target_for_nikto = f"http://{target}"
            nikto_request_timeout = os.getenv("NIKTO_TIMEOUT", "180")
            # Let nikto stop itself before outer watchdog timeout when possible.
            nikto_max_time = os.getenv("NIKTO_MAX_TIME", "15m")
            cmd = [perl_bin, str(TOOLS_DIR / "nikto/program/nikto.pl"),
                   "-h", target_for_nikto,
                   "-Tuning", "1234567890abcde",
                   "-timeout", nikto_request_timeout,
                   "-maxtime", nikto_max_time,
                   *extra_flags]
            results["command"] = " ".join(cmd)
            
        elif tool == "sqlmap":
            python_bin = sys.executable or shutil.which("python3")
            if not python_bin:
                results["error"] = "Python interpreter not found. Install python3 to run sqlmap."
                update_scan_db(scan_id, "failed", results)
                return
            # If the URL has no parameters, attempt to feed SQLMap with discovered parameterized URLs.
            sqlmap_targets = []
            try:
                parsed_target = urlparse(target)
                if parsed_target.query:
                    sqlmap_targets = [target]
            except Exception:
                parsed_target = None

            preferred_scheme = (parsed_target.scheme if parsed_target and parsed_target.scheme else "https").lower()
            preferred_host = (parsed_target.hostname if parsed_target and parsed_target.hostname else extract_host(target)).lower()
            preferred_port = parsed_target.port if parsed_target and parsed_target.port is not None else None
            base_domain = _base_domain(preferred_host)
            allow_subdomains = str(os.getenv("SQLMAP_ALLOW_SUBDOMAINS", "0")).strip().lower() not in ("0", "false", "no", "off")

            max_targets = int(os.getenv("SQLMAP_MAX_TARGETS", "25"))
            if not sqlmap_targets:
                # Prefer the full katana output artifact (if present) over truncated DB output.
                katana_file = _latest_katana_output_file_for_target(scan_id, target)
                if katana_file:
                    try:
                        with open(katana_file, "r", encoding="utf-8", errors="ignore") as f:
	                            sqlmap_targets = _extract_param_urls_from_lines(
	                                f,
	                                base_domain,
	                                max_urls=max_targets,
	                                preferred_scheme=preferred_scheme,
	                                preferred_host=preferred_host,
	                                preferred_port=preferred_port,
	                                allow_subdomains=allow_subdomains,
	                            )
                    except Exception:
                        sqlmap_targets = []
                katana_output = _latest_katana_output_for_target(scan_id, target)
                if (not sqlmap_targets) and katana_output:
	                    sqlmap_targets = _extract_param_urls(
	                        clean_scan_text(katana_output),
	                        base_domain,
	                        max_urls=max_targets,
	                        preferred_scheme=preferred_scheme,
	                        preferred_host=preferred_host,
	                        preferred_port=preferred_port,
	                        allow_subdomains=allow_subdomains,
	                        )

                # Fallback: harvest any parameterized paths/URLs Nikto already surfaced.
                nikto_output = _latest_nikto_output_for_target(scan_id, target)
                if (not sqlmap_targets) and nikto_output:
                    nikto_candidates = _extract_param_candidates_from_nikto_output(nikto_output)
                    if nikto_candidates:
	                        sqlmap_targets = _extract_param_urls_from_lines(
	                            nikto_candidates,
	                            base_domain,
	                            max_urls=max_targets,
	                            preferred_scheme=preferred_scheme,
	                            preferred_host=preferred_host,
	                            preferred_port=preferred_port,
	                            allow_subdomains=allow_subdomains,
	                        )

            # Resume support: if a previous attempt already ran katana seed for this scan_id,
            # reuse the existing output files to avoid re-crawling and reduce flakiness.
            if (not sqlmap_targets) and str(os.getenv("SQLMAP_SEED_WITH_KATANA", "1")).strip().lower() not in ("0", "false", "no", "off"):
                try:
                    seed_files_existing = sorted(LOG_DIR.glob(f"katana_seed_{scan_id}_*.txt"))
                    if seed_files_existing:
                        resumed: list[str] = []
                        seen_resumed: set[str] = set()
                        for sf in seed_files_existing[:12]:
                            try:
                                if sf.stat().st_size <= 0:
                                    continue
                            except Exception:
                                pass
                            try:
                                with sf.open("r", encoding="utf-8", errors="ignore") as f:
                                    urls = _extract_param_urls_from_lines(
                                        f,
                                        base_domain,
                                        max_urls=max_targets,
                                        preferred_scheme=preferred_scheme,
                                        preferred_host=preferred_host,
                                        preferred_port=preferred_port,
                                        allow_subdomains=allow_subdomains,
                                    )
                            except Exception:
                                urls = []
                            for u in urls:
                                if u in seen_resumed:
                                    continue
                                seen_resumed.add(u)
                                resumed.append(u)
                                if len(resumed) >= max_targets:
                                    break
                            if len(resumed) >= max_targets:
                                break
                        if resumed:
                            sqlmap_targets = resumed
                            results["sqlmap_katana_seed_resumed"] = True
                            results["sqlmap_katana_seed_resume_files"] = [str(p) for p in seed_files_existing]
                            results["sqlmap_katana_seed_param_urls_total"] = len(sqlmap_targets)
                            results["sqlmap_katana_seed_param_urls_sample"] = sqlmap_targets[:5]
                            try:
                                update_scan_db(scan_id, "running", results)
                            except Exception:
                                pass
                except Exception:
                    pass

            # If we still have no parameterized endpoints, run a short katana seed crawl specifically
            # for SQLMap to harvest query-string candidates from JS/routes.
            if not sqlmap_targets and str(os.getenv("SQLMAP_SEED_WITH_KATANA", "1")).strip().lower() not in ("0", "false", "no", "off"):
                try:
                    katana_bin = str(TOOLS_DIR / "katana")
                    seed_depth = str(os.getenv("SQLMAP_KATANA_SEED_DEPTH", "5")).strip() or "5"
                    seed_duration = str(os.getenv("SQLMAP_KATANA_SEED_DURATION", "60s")).strip() or "60s"
                    seed_ct_seconds = _parse_duration_seconds(seed_duration, default_seconds=60)
                    seed_rl = str(os.getenv("SQLMAP_KATANA_SEED_RATE_LIMIT", "20")).strip() or "20"
                    seed_conc = str(os.getenv("SQLMAP_KATANA_SEED_CONCURRENCY", "5")).strip() or "5"
                    seed_jsluice = str(os.getenv("SQLMAP_KATANA_SEED_JSLUICE", "1")).strip().lower() not in ("0", "false", "no", "off")
                    seed_known_files = str(os.getenv("SQLMAP_KATANA_SEED_KNOWN_FILES", "all")).strip() or "all"
                    # Katana requires a minimum depth of 3 for known-files crawling.
                    try:
                        seed_depth_int = int(str(seed_depth).strip())
                    except Exception:
                        seed_depth_int = 3

                    # Try multiple base variants (http/https + apex/www) to maximize discovery.
                    seed_with_variants = str(os.getenv("SQLMAP_SEED_VARIANTS", "1")).strip().lower() not in ("0", "false", "no", "off")
                    seed_targets = sqlmap_discovery_targets(target) if seed_with_variants else [target]
                    try:
                        max_seed_variants = int(str(os.getenv("SQLMAP_SEED_VARIANTS_MAX", "4")).strip() or "4")
                    except Exception:
                        max_seed_variants = 4
                    seed_targets = seed_targets[: max(1, max_seed_variants)]
                    results["sqlmap_katana_seed_targets"] = seed_targets

                    seed_timeout = int(os.getenv("SQLMAP_KATANA_SEED_TIMEOUT_SECONDS", "90"))
                    seed_commands = []
                    seed_files = []

                    def _merge_targets(existing: list[str], new_urls: list[str], limit: int) -> list[str]:
                        seen_local = set(existing)
                        for u in new_urls:
                            if u in seen_local:
                                continue
                            existing.append(u)
                            seen_local.add(u)
                            if len(existing) >= limit:
                                break
                        return existing

                    for idx, seed_target in enumerate(seed_targets, 1):
                        seed_file = LOG_DIR / f"katana_seed_{scan_id}_{idx}.txt"
                        seed_cmd = [
                            katana_bin,
                            "-u", seed_target,
                            "-jc",
                            "-silent",
                            "-duc",
                            "-timeout", str(os.getenv("KATANA_TIMEOUT", "20")),
                            "-ct", str(seed_ct_seconds),
                            "-d", seed_depth,
                            "-rl", seed_rl,
                            "-c", seed_conc,
                        ]
                        # Note: -kf requires depth >= 3
                        if seed_known_files and seed_depth_int >= 3:
                            seed_cmd += ["-kf", seed_known_files]
                        if seed_jsluice:
                            seed_cmd += ["-jsluice"]

                        seed_commands.append(" ".join(seed_cmd))
                        seed_files.append(str(seed_file))
                        if idx == 1:
                            results["sqlmap_katana_seed_command"] = " ".join(seed_cmd)

                        proc = await asyncio.create_subprocess_exec(
                            *seed_cmd,
                            # Stream stdout so we can harvest param URLs even if we terminate the crawl early.
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        found: list[str] = []
                        try:
                            seed_file.parent.mkdir(parents=True, exist_ok=True)
                            base_domain_norm = (base_domain or "").lower()

                            # Write raw katana stdout to a file for audit/debug while parsing in-memory.
                            with seed_file.open("w", encoding="utf-8", errors="ignore") as sf:
                                seen_local: set[str] = set()

                                async def _read_stdout():
                                    nonlocal found
                                    if not proc.stdout:
                                        return
                                    while True:
                                        line = await proc.stdout.readline()
                                        if not line:
                                            break
                                        text = line.decode("utf-8", errors="ignore").strip()
                                        if not text:
                                            continue
                                        try:
                                            sf.write(text + "\n")
                                        except Exception:
                                            pass

                                        cleaned = _normalize_discovered_url(
                                            text,
                                            preferred_scheme=preferred_scheme,
                                            preferred_host=preferred_host,
                                            preferred_port=preferred_port,
                                            base_domain=base_domain_norm,
                                            allow_subdomains=allow_subdomains,
                                        )
                                        if not cleaned:
                                            continue
                                        if cleaned in seen_local:
                                            continue
                                        seen_local.add(cleaned)
                                        found.append(cleaned)

                                        # Stop early if we already have enough candidates.
                                        if len(found) >= max_targets:
                                            try:
                                                proc.terminate()
                                            except Exception:
                                                pass
                                            break

                                reader_task = asyncio.create_task(_read_stdout())
                                try:
                                    await asyncio.wait_for(proc.wait(), timeout=seed_timeout)
                                except asyncio.TimeoutError:
                                    proc.kill()
                                    await proc.wait()
                                await reader_task
                        except Exception:
                            try:
                                proc.kill()
                                await proc.wait()
                            except Exception:
                                pass
                            found = []

                        if found:
                            sqlmap_targets = _merge_targets(sqlmap_targets or [], found, max_targets)
                            if len(sqlmap_targets) >= max_targets:
                                break

                    if seed_commands:
                        results["sqlmap_katana_seed_commands"] = seed_commands
                        results["sqlmap_katana_seed_output_files"] = seed_files

                    if sqlmap_targets:
                        results["sqlmap_katana_seed_param_urls_total"] = len(sqlmap_targets)
                        results["sqlmap_katana_seed_param_urls_sample"] = sqlmap_targets[:5]
                        try:
                            update_scan_db(scan_id, "running", results)
                        except Exception:
                            pass
                except Exception:
                    pass
            sqlmap_target_file = None
            if sqlmap_targets and len(sqlmap_targets) > 1:
                sqlmap_target_file = LOG_DIR / f"sqlmap_targets_{scan_id}.txt"
                sqlmap_target_file.write_text("\n".join(sqlmap_targets))
                results["sqlmap_targets_total"] = len(sqlmap_targets)
                results["sqlmap_targets_sample"] = sqlmap_targets[:5]
            elif sqlmap_targets:
                target = sqlmap_targets[0]
                results["target"] = target

            cmd = [python_bin, str(TOOLS_DIR / "sqlmap/sqlmap.py")]
            if sqlmap_target_file:
                cmd += ["-m", str(sqlmap_target_file)]
            else:
                cmd += ["-u", target]
            # SQLMap profile lets you tune coverage without changing API surface.
            sqlmap_profile = str(os.getenv("SQLMAP_PROFILE", "balanced") or "").strip().lower()
            profile_defaults = {
                "quick": {
                    "level": "1",
                    "risk": "1",
                    "crawl_depth": "1",
                    "threads": "2",
                    "check_sitemap": "0",
                    "technique": "BE",
                    "tamper": "",
                    "delay": "",
                },
                "balanced": {
                    "level": "2",
                    "risk": "1",
                    "crawl_depth": "2",
                    "threads": "4",
                    "check_sitemap": "1",
                    # Balanced default: faster multi-tech suite (boolean/error/union) to reduce timeouts.
                    # Use SQLMAP_PROFILE=deep or SQLMAP_TECHNIQUE=BEUSTQ for exhaustive checks.
                    "technique": "BEU",
                    "tamper": "",
                    "delay": "",
                },
                "deep": {
                    "level": "3",
                    "risk": "2",
                    "crawl_depth": "3",
                    "threads": "6",
                    "check_sitemap": "1",
                    "technique": "BEUSTQ",
                    "tamper": "",
                    "delay": "",
                },
                # WAF-oriented profile: slower, more evasive defaults (override with env vars).
                "waf": {
                    "level": "3",
                    "risk": "2",
                    "crawl_depth": "2",
                    "threads": "1",
                    "check_sitemap": "1",
                    "technique": "BEUSTQ",
                    "tamper": "space2comment,between,randomcase",
                    "delay": "0.3",
                },
            }
            defaults = profile_defaults.get(sqlmap_profile) or profile_defaults["balanced"]
            results["sqlmap_profile"] = sqlmap_profile or "balanced"

            sqlmap_level = os.getenv("SQLMAP_LEVEL", defaults["level"])
            sqlmap_risk = os.getenv("SQLMAP_RISK", defaults["risk"])
            sqlmap_threads = os.getenv("SQLMAP_THREADS", defaults["threads"])
            sqlmap_check_sitemap = os.getenv("SQLMAP_CHECK_SITEMAP", defaults["check_sitemap"])
            sqlmap_technique = (os.getenv("SQLMAP_TECHNIQUE", defaults.get("technique", "")) or "").strip()
            sqlmap_tamper = (os.getenv("SQLMAP_TAMPER", defaults.get("tamper", "")) or "").strip()
            sqlmap_delay = (os.getenv("SQLMAP_DELAY", defaults.get("delay", "")) or "").strip()
            sqlmap_ignore_code = (os.getenv("SQLMAP_IGNORE_CODE", "") or "").strip()
            sqlmap_time_sec = (os.getenv("SQLMAP_TIME_SEC", "") or "").strip()
            sqlmap_extra_answers = (os.getenv("SQLMAP_ANSWERS", "") or "").strip()
            sqlmap_retries = os.getenv("SQLMAP_RETRIES", "2")
            sqlmap_flush_session = str(os.getenv("SQLMAP_FLUSH_SESSION", "0")).strip().lower() not in ("0", "false", "no", "off")
            cmd += [
                "--batch",
                f"--level={sqlmap_level}",
                f"--risk={sqlmap_risk}",
                f"--timeout={os.getenv('SQLMAP_REQUEST_TIMEOUT', '30')}",
                f"--retries={sqlmap_retries}",
                "--fresh-queries",
                "--random-agent",
            ]
            if sqlmap_technique:
                cmd += [f"--technique={sqlmap_technique}"]
            if sqlmap_tamper:
                cmd += [f"--tamper={sqlmap_tamper}"]
            if sqlmap_ignore_code:
                cmd += [f"--ignore-code={sqlmap_ignore_code}"]
            if sqlmap_time_sec and str(sqlmap_time_sec).strip().isdigit():
                cmd += [f"--time-sec={sqlmap_time_sec}"]
            if sqlmap_delay:
                try:
                    delay_val = float(str(sqlmap_delay).strip())
                except Exception:
                    delay_val = 0.0
                if delay_val > 0:
                    cmd += [f"--delay={delay_val}"]
            # Keep SQLMap artifacts per scan for auditability and to avoid cross-scan state bleed.
            sqlmap_out_dir = LOG_DIR / "sqlmap_output" / str(scan_id)
            try:
                sqlmap_out_dir.mkdir(parents=True, exist_ok=True)
                cmd += [f"--output-dir={sqlmap_out_dir}"]
                results["sqlmap_output_dir"] = str(sqlmap_out_dir)
            except Exception:
                pass
            if sqlmap_flush_session:
                cmd += ["--flush-session"]
            if str(sqlmap_threads or "").strip().isdigit():
                threads_val = int(str(sqlmap_threads).strip())
                if threads_val > 1:
                    cmd += [f"--threads={threads_val}"]

            # Force deterministic answers for sitemap parsing and other prompts (still runs in batch mode).
            answers_bits = []
            if str(sqlmap_check_sitemap).strip().lower() not in ("0", "false", "no", "off"):
                answers_bits.append("sitemap=Y")
            # Reduce unwanted interactive behavior and keep scans coverage-oriented.
            # - Don't exploit post-detection (avoid data extraction behavior).
            # - Skip other-DBMS payload suites after fingerprinting (faster, less noisy).
            # - In multi-target mode, do not skip remaining URLs after first injection.
            # - Keep testing other parameters/targets when prompted.
            answers_bits.append("exploit=N")
            answers_bits.append("skip test payloads=Y")
            answers_bits.append("keep testing=Y")
            answers_bits.append("skip further tests=N")
            if sqlmap_extra_answers:
                answers_bits.append(sqlmap_extra_answers)
            if answers_bits:
                # De-dupe while preserving order.
                seen_ans = set()
                deduped = []
                for bit in answers_bits:
                    b = str(bit or "").strip()
                    if not b or b in seen_ans:
                        continue
                    seen_ans.add(b)
                    deduped.append(b)
                if deduped:
                    cmd += [f"--answers={','.join(deduped)}"]

            auto_crawl_enabled = str(os.getenv("SQLMAP_AUTO_CRAWL", "1")).strip().lower() not in ("0", "false", "no", "off")
            always_crawl = str(os.getenv("SQLMAP_ALWAYS_CRAWL", "0")).strip().lower() not in ("0", "false", "no", "off")
            if auto_crawl_enabled and (always_crawl or not sqlmap_targets):
                crawl_depth = os.getenv("SQLMAP_CRAWL_DEPTH", defaults["crawl_depth"])
                cmd += [f"--crawl={crawl_depth}"]
                if str(os.getenv("SQLMAP_FORMS", "1")).strip().lower() not in ("0", "false", "no", "off"):
                    cmd += ["--forms"]
            results["command"] = " ".join(cmd)
            # Checkpoint the final SQLMap command/targets so a later reconciliation has full context.
            try:
                update_scan_db(scan_id, "running", results)
            except Exception:
                pass
            
        elif tool == "katana":
            katana_out_file = LOG_DIR / f"katana_{scan_id}.txt"
            katana_depth = str(os.getenv("KATANA_DEPTH", "3")).strip() or "3"
            katana_rate_limit = str(os.getenv("KATANA_RATE_LIMIT", "20")).strip() or "20"
            katana_concurrency = str(os.getenv("KATANA_CONCURRENCY", "5")).strip() or "5"
            katana_duration = str(os.getenv("KATANA_CRAWL_DURATION", "90s")).strip() or "90s"
            katana_ct_seconds = _parse_duration_seconds(katana_duration, default_seconds=90)
            katana_known_files = str(os.getenv("KATANA_KNOWN_FILES", "sitemapxml")).strip()
            katana_jsluice = str(os.getenv("KATANA_JSLUICE", "0")).strip().lower() not in ("0", "false", "no", "off")
            cmd = [
                str(TOOLS_DIR / "katana"),
                "-u", target,
                "-jc",
                "-silent",
                "-duc",
                "-o", str(katana_out_file),
                "-timeout", os.getenv("KATANA_TIMEOUT", "20"),
                "-ct", str(katana_ct_seconds),
                "-d", katana_depth,
                "-rl", katana_rate_limit,
                "-c", katana_concurrency,
            ]
            # -kf requires a minimum depth of 3 per katana help text.
            try:
                depth_int = int(katana_depth)
            except Exception:
                depth_int = 3
            if katana_known_files and depth_int >= 3:
                cmd += ["-kf", katana_known_files]
            if katana_jsluice:
                cmd += ["-jsluice"]
            results["command"] = " ".join(cmd)
            results["katana_output_file"] = str(katana_out_file)
            
        else:
            results["error"] = f"Unknown tool: {tool}"
            update_scan_db(scan_id, "failed", results)
            return
        
        # Resolve binaries safely (some environments may provide just the program name, e.g. "python3").
        exe0 = str(cmd[0] or "")
        exe_ok = False
        try:
            if exe0 and (Path(exe0).exists() or Path(exe0).is_file()):
                exe_ok = True
            elif exe0:
                resolved = shutil.which(exe0)
                if resolved and Path(resolved).exists():
                    cmd[0] = resolved
                    exe_ok = True
                    # Keep the recorded command accurate when we auto-resolve PATH executables.
                    if results.get("command"):
                        try:
                            results["command"] = " ".join(cmd)
                        except Exception:
                            pass
        except Exception:
            exe_ok = False

        if not exe_ok:
            results["error"] = f"Tool binary not found: {cmd[0]}"
            update_scan_db(scan_id, "failed", results)
            return
        
        # Tool-specific timeout (seconds)
        timeout_seconds = int(os.getenv("SCAN_TIMEOUT_DEFAULT", "120"))
        if tool == "nuclei":
            timeout_seconds = int(os.getenv("NUCLEI_TIMEOUT", "900"))
        elif tool == "sqlmap":
            timeout_seconds = int(os.getenv("SQLMAP_TIMEOUT", "900"))
        elif tool == "nikto":
            timeout_seconds = int(os.getenv("NIKTO_SCAN_TIMEOUT", "1200"))
        elif tool == "katana":
            timeout_seconds = int(os.getenv("KATANA_SCAN_TIMEOUT", "600"))

        # Run the command with streaming output for live progress
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        running_processes[scan_id] = process

        # Keep bounded in-memory logs; long sqlmap/nikto runs can otherwise exhaust RAM.
        try:
            output_max_lines = int(str(os.getenv("SCAN_OUTPUT_MAX_LINES", "5000")).strip() or "5000")
        except Exception:
            output_max_lines = 5000
        try:
            error_max_lines = int(str(os.getenv("SCAN_ERROR_MAX_LINES", "2000")).strip() or "2000")
        except Exception:
            error_max_lines = 2000
        output_lines = deque(maxlen=max(200, output_max_lines))
        error_lines = deque(maxlen=max(100, error_max_lines))
        last_progress_update = 0.0

        def update_progress_from_line(line: str):
            nonlocal last_progress_update
            if tool != "nuclei":
                return
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            # Example: [0:00:00] | Templates: 1 | Hosts: 1 | RPS: 2 | Matched: 1 | Errors: 0 | Requests: 1/1 (100%)
            match = re.search(
                r"\[(\d+:\d+:\d+)\]\s+\|\s+Templates:\s+(\d+)\s+\|\s+Hosts:\s+(\d+)\s+\|\s+RPS:\s+([\d.]+)\s+\|\s+Matched:\s+(\d+)\s+\|\s+Errors:\s+(\d+)\s+\|\s+Requests:\s+(\d+)/(\d+)(?:\s+\((\d+)%\))?",
                clean_line
            )
            if not match:
                return
            elapsed, templates, hosts, rps, matched, errors, done, total, percent = match.groups()
            if percent is None and int(total) > 0:
                percent = str(int((int(done) / int(total)) * 100))
            results["progress"] = {
                "elapsed": elapsed,
                "elapsed_seconds": int(time.time() - start_ts),
                "templates": int(templates),
                "hosts": int(hosts),
                "rps": float(rps),
                "matched": int(matched),
                "errors": int(errors),
                "requests_done": int(done),
                "requests_total": int(total),
                "percent": int(percent)
            }
            now = time.time()
            if now - last_progress_update > 0.5:
                update_scan_db(scan_id, "running", results)
                last_progress_update = now

        async def read_stream(stream, is_stderr=False):
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="ignore").rstrip()
                if not text:
                    continue
                if is_stderr:
                    error_lines.append(text)
                else:
                    output_lines.append(text)
                update_progress_from_line(text)

        stdout_task = asyncio.create_task(read_stream(process.stdout, is_stderr=False))
        stderr_task = asyncio.create_task(read_stream(process.stderr, is_stderr=True))
        timed_out = False

        try:
            await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            process.kill()
            await process.wait()
            results["error"] = f"Scan timed out after {timeout_seconds} seconds"
            results["success"] = False
        except asyncio.CancelledError:
            process.kill()
            await process.wait()
            results["error"] = "Scan stopped by user."
            results["success"] = False
        finally:
            await stdout_task
            await stderr_task

        # Persist a reasonable amount of output. SQLMap needs more context than other tools for reliable
        # classification, especially when running in multi-target mode.
        try:
            output_char_limit = int(str(os.getenv("SCAN_OUTPUT_CHAR_LIMIT", "8000")).strip() or "8000")
        except Exception:
            output_char_limit = 8000
        try:
            error_char_limit = int(str(os.getenv("SCAN_ERROR_CHAR_LIMIT", "2000")).strip() or "2000")
        except Exception:
            error_char_limit = 2000
        if tool == "sqlmap":
            try:
                output_char_limit = int(str(os.getenv("SQLMAP_OUTPUT_CHAR_LIMIT", "40000")).strip() or "40000")
            except Exception:
                output_char_limit = 40000
            try:
                error_char_limit = int(str(os.getenv("SQLMAP_ERROR_CHAR_LIMIT", "8000")).strip() or "8000")
            except Exception:
                error_char_limit = 8000

        output_text = "\n".join(output_lines)
        error_text = "\n".join(error_lines)
        results["output"] = output_text[-max(1000, output_char_limit):]
        results["error"] = (results["error"] or error_text)[-max(200, error_char_limit):].strip()

        # If the scan process was terminated by signal (e.g. service restart), surface it explicitly.
        if (not timed_out) and (not results["error"]) and (process.returncode is not None) and (process.returncode < 0):
            sig_num = -int(process.returncode)
            try:
                sig_name = signal.Signals(sig_num).name
            except Exception:
                sig_name = f"SIG{sig_num}"
            results["error"] = f"Scan process terminated by {sig_name}."
        results["error"], tool_warning = sanitize_tool_error(tool, results["error"], results["output"])
        if tool_warning:
            existing_warning = str(results.get("warning", "")).strip()
            if existing_warning and tool_warning not in existing_warning:
                results["warning"] = f"{existing_warning} {tool_warning}"
            elif not existing_warning:
                results["warning"] = tool_warning
        # Nikto can provide actionable findings before max-time/timeout; preserve those as completed partial results.
        if timed_out and tool == "nikto" and output_lines:
            results["warning"] = f"Nikto reached timeout after {timeout_seconds} seconds; partial findings were captured."
            results["error"] = ""
            results["success"] = True
        default_success = process.returncode in (0, 1)
        if tool == "sqlmap":
            def _sqlmap_has_test_progress(text: str) -> bool:
                low = (text or "").lower()
                if not low:
                    return False
                # Strong indicators that sqlmap moved beyond connectivity/crawling into payload testing.
                if re.search(r"\\btesting\\s+'[^']+'", text, re.IGNORECASE):
                    return True
                if any(
                    marker in low
                    for marker in (
                        "testing for sql injection on",
                        "heuristic test",
                        "payload:",
                        "back-end dbms",
                        "is injectable",
                        "is vulnerable",
                        "does not seem to be injectable",
                        "all tested parameters do not appear to be injectable",
                    )
                ):
                    return True
                return False

            sqlmap_has_progress = _sqlmap_has_test_progress(results.get("output", ""))
            sqlmap_reason = sqlmap_connection_failure_reason(results["output"], results["error"], timed_out)

            def _is_soft_sqlmap_block(reason: str) -> bool:
                low = (reason or "").lower()
                # Treat access/rate/endpoint restrictions as completed scans with a coverage warning,
                # not a hard platform failure.
                soft_markers = (
                    "http 401",
                    "http 403",
                    "http 404",
                    "http 429",
                    "encountered http errors",
                    "server-side http errors",
                    "rate limiting",
                    "access denied",
                    "authentication required",
                )
                return any(m in low for m in soft_markers)

            if sqlmap_reason:
                existing_error = str(results.get("error", "")).strip()
                results["error"] = (
                    f"{sqlmap_reason} {existing_error}".strip()
                    if existing_error and sqlmap_reason.lower() not in existing_error.lower()
                    else (existing_error or sqlmap_reason)
                )

                # If SQLMap exited cleanly, surface this as a coverage warning instead of failing the scan.
                if default_success and _is_soft_sqlmap_block(sqlmap_reason) and not timed_out:
                    existing_warning = str(results.get("warning", "")).strip()
                    if existing_warning and sqlmap_reason.lower() not in existing_warning.lower():
                        results["warning"] = f"{existing_warning} {sqlmap_reason}".strip()
                    elif not existing_warning:
                        results["warning"] = sqlmap_reason
                    # Avoid marking a completed scan as failed just because access was restricted.
                    results["error"] = ""
                    results["success"] = True
                # If SQLMap timed out but clearly progressed into testing, treat as completed with warning.
                elif timed_out and sqlmap_has_progress:
                    existing_warning = str(results.get("warning", "")).strip()
                    warn_bits = [
                        b
                        for b in [
                            existing_warning,
                            sqlmap_reason,
                            f"SQLMap reached timeout after {timeout_seconds} seconds; partial results were captured.",
                        ]
                        if b
                    ]
                    results["warning"] = " ".join(warn_bits).strip()
                    results["error"] = ""
                    results["success"] = True
                else:
                    results["success"] = False
            elif timed_out:
                if sqlmap_has_progress:
                    existing_warning = str(results.get("warning", "")).strip()
                    timeout_warn = f"SQLMap reached timeout after {timeout_seconds} seconds; partial results were captured."
                    results["warning"] = f"{existing_warning} {timeout_warn}".strip() if existing_warning else timeout_warn
                    results["error"] = ""
                    results["success"] = True
                else:
                    results["error"] = f"SQLMap timed out after {timeout_seconds} seconds."
                    results["success"] = False
            else:
                results["success"] = default_success
        else:
            results["success"] = results["success"] or default_success
        results["return_code"] = process.returncode
        results["timed_out"] = timed_out
        if tool == "sqlmap":
            out_dir = results.get("sqlmap_output_dir")
            if out_dir:
                csv_path = _sqlmap_latest_results_csv(Path(str(out_dir)))
                if csv_path:
                    csv_rows = _sqlmap_parse_results_csv(csv_path)
                    results["sqlmap_results_csv_path"] = str(csv_path)
                    results["sqlmap_results_csv_total"] = len(csv_rows)
                    # Keep a small excerpt in the scan record for UI/debugging.
                    results["sqlmap_results_csv_rows"] = csv_rows[:50]
        # Save log
        log_file.write_text(json.dumps(results, indent=2))
        
        # Update database
        if results["success"]:
            update_scan_db(scan_id, "completed", results)
            print(f"✅ Scan {scan_id} completed successfully")
        else:
            update_scan_db(scan_id, "failed", results)
            print(f"❌ Scan {scan_id} failed: {results.get('error', 'Unknown error')}")

        # Generate reports even for failed scans so operators can see the actual failure reason/coverage gap.
        try:
            await generate_scan_reports(scan_id)
        except Exception as e:
            print(f"⚠️  Could not generate auto-reports: {e}")
        running_processes.pop(scan_id, None)
            
    except Exception as e:
        results["error"] = str(e)
        log_file.write_text(json.dumps(results, indent=2))
        update_scan_db(scan_id, "failed", results)
        print(f"❌ Scan {scan_id} failed with exception: {e}")
    finally:
        # If all tools for the same target are done, generate consolidated report
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT user_id, target FROM scans WHERE id=?", (scan_id,))
            row = cur.fetchone()
            db.close()
            if row:
                user_id, tgt = row["user_id"], row["target"]
                if user_id and tgt:
                    await maybe_generate_consolidated(user_id, tgt)
        except Exception:
            pass

async def run_multi_scan_async(scan_ids_tools, target: str):
    """Run scans sequentially for multiple tools"""
    for scan_id, tool in scan_ids_tools:
        await run_scan_async(scan_id, target, tool)

async def maybe_generate_consolidated(user_id: int, target: str):
    """Generate consolidated report when all 4 tool scans finished for target."""
    valid_tools = SUPPORTED_TOOLS
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, tool, status FROM scans WHERE user_id=? AND target=? ORDER BY id DESC",
        (user_id, target)
    )
    rows = cur.fetchall()
    db.close()
    # Use latest status per tool to avoid historical scans skewing consolidation gating.
    tool_status: dict[str, str] = {}
    seen = set()
    for r in rows:
        tool_id = str(r["tool"] or "").strip().lower()
        if not tool_id or tool_id in seen:
            continue
        seen.add(tool_id)
        tool_status[tool_id] = str(r["status"] or "").strip().lower()
        if len(seen) >= len(valid_tools):
            break
    if not all(t in tool_status for t in [t.lower() for t in valid_tools]):
        return
    if not all(tool_status[t.lower()] in ("completed", "failed") for t in valid_tools):
        return
    await generate_consolidated_reports(user_id, target)

# ========== AI REPORT GENERATION ==========

async def generate_scan_reports(scan_id: int):
    """Generate executive and technical reports for a single scan."""
    print(f"🤖 Generating reports for scan {scan_id}")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT target, tool, results, created_at, completed_at FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    if not row:
        return {"error": "Scan not found"}

    target, tool, results_json, created_at, completed_at = row
    created_dt = parse_ts(created_at) or datetime.now()
    completed_dt = parse_ts(completed_at) or datetime.now()

    results = {}
    raw_output = ""
    error = ""
    warning = ""
    command_used = ""
    if results_json:
        try:
            results = json.loads(results_json) or {}
            raw_output = results.get("output", "")
            error = results.get("error", "")
            warning = results.get("warning", "")
            command_used = results.get("command", "")
        except Exception:
            results = {}
    progress = results.get("progress") if isinstance(results, dict) else None

    # Include non-fatal warnings (e.g. WAF/403/404 coverage gaps) in the report evidence.
    warning = (warning or "").strip()
    if warning:
        error = (error or "").strip()
        if error:
            error = f"{error}\nWARNING: {warning}"
        else:
            error = f"WARNING: {warning}"

    raw_output_clean = clean_scan_text(raw_output)
    error_clean, tool_warning = sanitize_tool_error(tool, error, raw_output_clean)
    if tool_warning and not raw_output_clean:
        raw_output_clean = tool_warning
    if not raw_output_clean and progress:
        raw_output_clean = (
            f"Templates executed: {progress.get('templates')}; "
            f"Requests: {progress.get('requests_done')}/{progress.get('requests_total')}; "
            f"Matched: {progress.get('matched')}; "
            f"Elapsed: {progress.get('elapsed', progress.get('elapsed_seconds'))}"
        )

    findings_list = build_findings_from_output(tool, raw_output, error, target, progress, command=command_used)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_list:
        sev = str(f.get("severity", "info")).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1

    if counts["critical"] > 0:
        overall_risk = "Critical"
    elif counts["high"] > 0:
        overall_risk = "High"
    elif counts["medium"] > 0:
        overall_risk = "Medium"
    elif counts["low"] > 0:
        overall_risk = "Low"
    else:
        overall_risk = "Informational"

    tool_methods = {
        "nuclei": "Template-based vulnerability scanning for CVEs and security misconfigurations.",
        "nikto": "Web server assessment for insecure files, outdated components, and weak HTTP headers.",
        "sqlmap": "Automated SQL injection validation against identified HTTP parameters.",
        "katana": "Attack surface discovery through crawling and endpoint enumeration."
    }
    tested_scope = {
        "nuclei": "HTTP endpoints in scope using selected light templates.",
        "nikto": "HTTP service behavior, default files, dangerous paths, and header controls.",
        "sqlmap": "Input vectors and request parameters exposed by the provided target URL.",
        "katana": "Reachable links, scripts, and endpoint paths discoverable from the base URL."
    }

    executive_summary = ai_summarize_findings(tool, target, findings_list, audience="executive")
    technical_summary = ai_summarize_findings(tool, target, findings_list, audience="technical")

    def remediation_plan(findings):
        immediate = []
        short_term = []
        long_term = [
            "Implement recurring authenticated and unauthenticated security testing in CI/CD.",
            "Track remediation SLAs by severity and re-validate fixes through retesting.",
            "Align control coverage with OWASP, NIST SP 800-115, and organizational policy baselines."
        ]
        for f in findings[:8]:
            sev = str(f.get("severity", "info")).lower()
            rec = f.get("recommendation", "Apply targeted remediation and re-test.")
            if sev in ("critical", "high"):
                immediate.append(rec)
            elif sev == "medium":
                short_term.append(rec)
            else:
                if len(short_term) < 4:
                    short_term.append(rec)
        if not immediate:
            immediate.append("No critical/high findings in current scope; validate results with targeted retest.")
        if not short_term:
            short_term.append("Harden baseline configurations and validate controls with periodic scans.")
        immediate = list(dict.fromkeys(immediate))[:5]
        short_term = list(dict.fromkeys(short_term))[:5]
        long_term = list(dict.fromkeys(long_term))[:4]
        return immediate, short_term, long_term

    immediate_actions, short_actions, long_actions = remediation_plan(findings_list)

    sorted_findings = sorted(findings_list, key=lambda x: severity_order.get(str(x.get("severity", "info")).lower(), 4))

    detailed_finding_blocks = []
    for idx, finding in enumerate(sorted_findings, 1):
        sev = str(finding.get("severity", "info")).upper()
        title = finding.get("title", "Finding")
        location = finding.get("location", target)
        evidence = finding.get("evidence", "No direct evidence captured")
        impact = finding.get("impact", "Impact to be validated")
        poc = finding.get("poc", "Reproduce with the same scanner command and compare output.")
        remediation = finding.get("recommendation", "Apply secure configuration and verify with re-scan.")
        repro_steps = finding.get("reproduction_steps") or []
        repro_md = "\n".join([f"  {i+1}. {step}" for i, step in enumerate(repro_steps)])
        if not repro_md:
            repro_md = "  1. Re-run scan with the same parameters and capture evidence."

        detailed_finding_blocks.append(
            f"""
### {idx}. {title}
- **Severity**: {sev}
- **Affected Asset**: {location}
- **Evidence**: {evidence}
- **Technical Impact**: {impact}
- **PoC**: {poc}
- **Reproduction Steps**:
{repro_md}
- **Remediation**: {remediation}
""".strip()
        )

    detailed_findings_markdown = "\n\n".join(detailed_finding_blocks) if detailed_finding_blocks else "No findings were recorded in this scan scope."

    executive_report = f"""
# Executive Security Report (CISO and Senior Management)

## Assessment Objective and Scope
- **Organization**: {PRODUCT_COMPANY_NAME}
- **Target**: {target}
- **Assessment Date (Asia/Dubai)**: {format_abu_dhabi(created_at) or created_at}
- **Scan Tool**: {tool}
- **Report ID**: {scan_id}
- **Assessment Type**: Automated focused validation aligned to OWASP testing guidance, NIST SP 800-115 execution methodology, ISO 27001 governance, and UAE IAS expectations.

## Risk Posture Snapshot
- **Overall Risk Rating**: {overall_risk}
- **Critical**: {counts['critical']}
- **High**: {counts['high']}
- **Medium**: {counts['medium']}
- **Low**: {counts['low']}
- **Informational**: {counts['info']}

## High-Level Executive Summary
{executive_summary}

## Priority Remediation Roadmap
### Immediate (0-7 Days)
{chr(10).join([f"- {a}" for a in immediate_actions])}

### Short Term (8-30 Days)
{chr(10).join([f"- {a}" for a in short_actions])}

### Programmatic (30-90 Days)
{chr(10).join([f"- {a}" for a in long_actions])}

## Governance and Assurance Notes
- Track closure by severity and evidence of validation.
- Perform re-test after remediation and before production change closure.
- Map outcomes to ISO 27001 control ownership, OWASP risk categories, and UAE IAS obligations where relevant.

*Prepared by: {PRODUCT_BRAND_NAME}*
"""

    technical_report = f"""
# Technical Security Assessment Report (Engineering and SOC)

## Assessment Context
- **Target**: {target}
- **Tool**: {tool}
- **Tool Purpose**: {tool_methods.get(tool, 'Automated security testing')}
- **Tested Scope**: {tested_scope.get(tool, 'Target URL and reachable endpoints')}
- **Scan Window (Asia/Dubai)**: {format_abu_dhabi(created_at) or created_at} to {format_abu_dhabi(completed_at) or completed_at or format_abu_dhabi(created_at) or created_at}
- **Duration**: {max(int((completed_dt - created_dt).total_seconds()), 0)} seconds
- **Command Used**: {command_used or 'Command not recorded'}

## Methodology
1. Recon and validation of in-scope target accessibility.
2. Tool-specific testing based on {tool} behavior and output evidence.
3. Finding triage with severity, impact, and exploitability context.
4. Remediation mapping and verification guidance per finding.

## Technical Summary (AI Assisted)
{technical_summary}

## Detailed Findings, PoC, Reproduction, and Remediation
{detailed_findings_markdown}

## Raw Evidence Excerpts
### Output
{(raw_output_clean or 'No direct scanner output captured.')[:3000]}

### Errors
{error_clean if error_clean else 'No scan errors reported.'}

## Validation Checklist
- Confirm each remediation in non-production first.
- Re-run identical scan command and compare evidence before/after.
- Record change ticket IDs, closure owner, and date for audit trail.

*Technical Security Team | {PRODUCT_BRAND_NAME}*
"""

    meta = {
        "tools_used": [tool],
        "created_at": created_at,
        "completed_at": completed_at,
        "target_system": "Web Application",
        "assessment_type": "Automated security assessment",
        "report_id": f"ASH-PENTEST-{report_id_target_label(target)}",
        "ai_executive_summary": executive_summary,
        "ai_technical_summary": technical_summary,
    }
    if tool == "nuclei":
        meta["nuclei_templates_executed"] = int(progress.get("templates", 0)) if isinstance(progress, dict) and progress.get("templates") is not None else None
        meta["nuclei_tags"] = extract_cli_option(command_used, "-tags")
        meta["nuclei_severity"] = extract_cli_option(command_used, "-severity")

    html_report = generate_html_report(executive_report, technical_report, scan_id, target, tool, mode="combined", findings=sorted_findings, meta=meta)
    executive_html = generate_html_report(executive_report, technical_report, scan_id, target, tool, mode="executive", findings=sorted_findings, meta=meta)
    technical_html = generate_html_report(executive_report, technical_report, scan_id, target, tool, mode="technical", findings=sorted_findings, meta=meta)

    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        UPDATE scans
        SET report_executive=?, report_technical=?, report_html=?
        WHERE id=?
        """,
        (executive_report, technical_report, html_report, scan_id),
    )
    db.commit()
    db.close()

    report_file = REPORTS_DIR / f"report_scan_{scan_id}.html"
    report_exec_file = REPORTS_DIR / f"report_scan_{scan_id}_executive.html"
    report_tech_file = REPORTS_DIR / f"report_scan_{scan_id}_technical.html"
    write_text_atomic(report_file, html_report)
    write_text_atomic(report_exec_file, executive_html)
    write_text_atomic(report_tech_file, technical_html)

    return {
        "executive": executive_report,
        "technical": technical_report,
        "html_path": str(report_file),
        "html_executive_path": str(report_exec_file),
        "html_technical_path": str(report_tech_file),
    }

async def generate_consolidated_reports(user_id: int, target: str):
    """Generate consolidated executive/technical reports for all scans of the same target.

    IMPORTANT:
    Targets may be stored with different schemes/variants (e.g. `example.com` vs `https://example.com`).
    Consolidated reports must group scans by stable `target_report_ref()` so posture/compliance and reports stay consistent.
    """
    target_ref = target_report_ref(target)

    # Pull all scans for the user (newest-first) and filter by stable target_ref.
    all_rows = _db_fetch_scans_for_user(user_id)
    matching_rows: list[sqlite3.Row] = []
    latest_target = None
    for r in all_rows:
        t = str(r["target"] or "").strip()
        if not t:
            continue
        if target_report_ref(t) != target_ref:
            continue
        if latest_target is None:
            latest_target = t
        matching_rows.append(r)

    if not matching_rows:
        return {"error": "No scans found for target"}

    # Select the latest finished scan per tool (completed/failed), fallback to newest record if none finished.
    finished: dict[str, sqlite3.Row] = {}
    fallback: dict[str, sqlite3.Row] = {}
    for r in matching_rows:
        tool_id = str(r["tool"] or "").strip().lower()
        if not tool_id:
            continue
        if tool_id not in fallback:
            fallback[tool_id] = r
        if tool_id in finished:
            continue
        status = str(r["status"] or "").strip().lower()
        if status in ("completed", "failed"):
            finished[tool_id] = r

    selected_rows: list[sqlite3.Row] = []
    for tool_id in REPORT_FINDINGS_ORDER:
        r = finished.get(tool_id) or fallback.get(tool_id)
        if r is not None:
            selected_rows.append(r)
    for tool_id, r in (finished | fallback).items():
        if tool_id in [str(x["tool"] or "").strip().lower() for x in selected_rows]:
            continue
        selected_rows.append(r)

    rows = selected_rows
    # Prefer displaying the most recent stored target string for this ref.
    target = latest_target or target

    report_rank = {name: idx for idx, name in enumerate(REPORT_FINDINGS_ORDER)}
    rows = sorted(
        rows,
        key=lambda row: (
            report_rank.get(str(row["tool"]).strip().lower(), len(report_rank)),
            -int(row["id"]),
        ),
    )

    tools_list = []
    tool_methods = {
        "nuclei": "Template-based vulnerability scanning (CVE and misconfiguration checks).",
        "nikto": "Web server misconfiguration and known issue checks.",
        "sqlmap": "Automated SQL injection testing against input parameters.",
        "katana": "Crawling and endpoint discovery to enumerate reachable URLs."
    }
    tested_scope = {
        "nuclei": "HTTP endpoints discovered from the base URL using available templates.",
        "nikto": "HTTP server headers, common misconfigurations, and risky paths.",
        "sqlmap": "HTTP parameters and endpoints supplied by the target URL.",
        "katana": "Linked resources and endpoints reachable from the base URL."
    }

    def summarize_tool_findings(tool_name: str, output: str, err: str, progress: dict | None = None, command: str | None = None) -> str:
        err, _ = sanitize_tool_error(tool_name, err, output)
        if err and tool_name != "sqlmap":
            return f"Scan error: {err}"
        if not output:
            if tool_name == "nuclei" and progress:
                return (
                    f"Nuclei executed {progress.get('templates', 'configured')} template(s); "
                    f"matched {progress.get('matched', 0)}."
                )
            return "No scan output available."
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if tool_name == "katana":
            urls = [l for l in lines if l.startswith("http")]
            if urls:
                return f"Discovered {len(urls)} endpoints. Sample: " + ", ".join(urls[:5])
            return "No endpoints discovered."
        if tool_name == "nuclei":
            matches = []
            severities = {}
            for l in lines:
                m = re.match(r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)", l)
                if m:
                    tpl, sev, proto, rest = m.groups()
                    matches.append(f"{tpl} ({sev})")
                    key = sev.lower()
                    severities[key] = severities.get(key, 0) + 1
            if matches:
                sev_summary = ", ".join(f"{k}:{v}" for k, v in severities.items())
                return f"Matched {len(matches)} nuclei findings ({sev_summary})."
            return "Nuclei scan completed without matched templates."
        if tool_name == "nikto":
            issues = [l for l in lines if l.startswith("+")]
            if issues:
                return f"Nikto reported {len(issues)} findings. Sample: {issues[0][:120]}"
            return "Nikto scan completed without reported findings."
        if tool_name == "sqlmap":
            combined = f"{output}\n{err}".lower()
            non_injectable = is_negative_injection_signal(combined) or "all tested parameters do not appear to be injectable" in combined
            conn_issue = sqlmap_connection_failure_reason(output or "", err or "", timed_out=False)
            if conn_issue:
                return f"Scan error: {conn_issue}"
            level = extract_cli_option(command or "", "--level") or "1"
            risk = extract_cli_option(command or "", "--risk") or "1"
            multi_target = extract_cli_option(command or "", "-m")
            crawl_flag = extract_cli_option(command or "", "--crawl")
            forms_enabled = "--forms" in (command or "")
            method_bits = []
            if multi_target:
                method_bits.append("multi-target")
            if crawl_flag:
                method_bits.append(f"crawl {crawl_flag}")
            if forms_enabled:
                method_bits.append("forms")
            method_suffix = f" ({', '.join(method_bits)})" if method_bits else ""

            if any(
                marker in combined
                for marker in (
                    "no usable links found",
                    "no parameter(s) found for testing",
                )
            ):
                extra = " Potential CAPTCHA/WAF protection was detected." if "captcha" in combined or "waf/ips" in combined else ""
                return (
                    f"SQLMap did not discover testable parameters/forms, so injection tests were not executed{extra} "
                    f"Method: level {level}/risk {risk}{method_suffix}."
                )

            techniques = []
            for line in output.splitlines():
                m = re.search(r"testing\s+'([^']+)'", line, re.IGNORECASE)
                if m:
                    label = m.group(1).strip()
                    if label and label not in techniques:
                        techniques.append(label)
            vuln = [l for l in lines if any(k in l.lower() for k in ["is injectable", "is vulnerable", "sql injection"])]
            if vuln:
                return "SQLMap indicated possible injection evidence."
            not_inj = [l for l in lines if "not injectable" in l.lower()]
            if not_inj:
                tech_text = f"Techniques tested: {', '.join(techniques[:3])}" if techniques else "Techniques tested: standard SQLMap suite"
                return f"SQLMap did not find injectable parameters. Method: level {level}/risk {risk}{method_suffix}. {tech_text}."
            if non_injectable:
                tech_text = f"Techniques tested: {', '.join(techniques[:3])}" if techniques else "Techniques tested: standard SQLMap suite"
                return f"No SQL injection detected in tested inputs. Method: level {level}/risk {risk}{method_suffix}. {tech_text}."
            if err:
                return f"Scan error: {err}"
            return "SQLMap completed without confirmed injection evidence."
        return "Security scan completed without critical findings."

    tool_summaries = []
    combined_findings = []
    key_findings_list = []
    all_findings = []
    tool_list = []
    created_times = []
    completed_times = []
    nuclei_contexts = []
    for row in rows:
        scan_id = row["id"]
        tool_raw = row["tool"]
        tool = (str(tool_raw).strip().lower() if tool_raw is not None else "unknown")
        status = row["status"]
        created = format_abu_dhabi(row["created_at"]) or row["created_at"]
        created_times.append(row["created_at"])
        if row["completed_at"]:
            completed_times.append(row["completed_at"])
        error = ""
        output = ""
        warning = ""
        progress = None
        command_used = ""
        if row["results"]:
            try:
                results = json.loads(row["results"])
                output = results.get("output", "")
                error = results.get("error", "")
                warning = results.get("warning", "") or ""
                progress = results.get("progress")
                command_used = results.get("command", "")
            except Exception:
                output = ""
        warning = (warning or "").strip()
        if warning:
            error = (error or "").strip()
            error = f"{error}\nWARNING: {warning}".strip() if error else f"WARNING: {warning}"
        output_clean = clean_scan_text(output)
        error_clean = clean_scan_text(error)
        status_display = status
        if status == "failed" and "timed out" in error_clean.lower() and output_clean:
            status_display = "completed (partial timeout)"
        if not output_clean and progress:
            output_clean = (
                f"Templates executed: {progress.get('templates')}; "
                f"Requests: {progress.get('requests_done')}/{progress.get('requests_total')}; "
                f"Matched: {progress.get('matched')}; "
                f"Elapsed: {progress.get('elapsed', progress.get('elapsed_seconds'))}"
            )
        if tool == "nuclei":
            templates_executed = None
            if isinstance(progress, dict) and progress.get("templates") is not None:
                try:
                    templates_executed = int(progress.get("templates"))
                except Exception:
                    templates_executed = None
            nuclei_contexts.append({
                "scan_id": scan_id,
                "templates_executed": templates_executed,
                "tags": extract_cli_option(command_used, "-tags"),
                "severity": extract_cli_option(command_used, "-severity"),
            })
        tool_list.append(tool)
        all_findings.extend(build_findings_from_output(tool, output_clean, error_clean, target, progress, command=command_used))
        summary = summarize_tool_findings(tool, output_clean, error_clean, progress, command_used)
        tool_summaries.append(f"- {tool} (Scan #{scan_id}, {status_display}, {created})")
        key_findings_list.append(f"- {tool} (Scan #{scan_id}): {summary}")
        combined_findings.append(
            "## {tool} (Scan #{scan_id})\nStatus: {status}\nMethodology: {method}\nWhat Was Tested: {tested}\nFindings: {summary}\n".format(
                tool=tool,
                scan_id=scan_id,
                status=status_display,
                method=tool_methods.get(tool, "Automated scanning."),
                tested=tested_scope.get(tool, "Target URL and reachable endpoints."),
                summary=summary
            )
        )

    tools_list = [tool_id for tool_id in REPORT_FINDINGS_ORDER if tool_id in tool_list]
    tools_list.extend([tool_id for tool_id in tool_list if tool_id not in tools_list])
    coverage_lines = "\n".join(tool_summaries)
    key_findings_lines = "\n".join(key_findings_list)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = str(f.get("severity", "info")).lower()
        sev_counts[sev if sev in sev_counts else "info"] += 1

    consolidated_exec_summary = ai_summarize_findings("all tools", target, all_findings, audience="executive")
    consolidated_tech_summary = ai_summarize_findings("all tools", target, all_findings, audience="technical")

    detailed_blocks = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for idx, finding in enumerate(sorted(all_findings, key=lambda x: severity_order.get(str(x.get("severity", "info")).lower(), 4))[:20], 1):
        steps = finding.get("reproduction_steps") or []
        steps_md = "\n".join([f"  {i+1}. {s}" for i, s in enumerate(steps)]) if steps else "  1. Re-run with same command and capture evidence."
        detailed_blocks.append(
            f"""
### {idx}. {finding.get('title', 'Finding')}
- **Severity**: {str(finding.get('severity', 'info')).upper()}
- **Tool**: {finding.get('tool', 'n/a')}
- **Affected Asset**: {finding.get('location', target)}
- **Evidence**: {finding.get('evidence', 'No direct evidence captured')}
- **Impact**: {finding.get('impact', 'Impact to be validated')}
- **PoC**: {finding.get('poc', 'Not provided')}
- **Reproduction Steps**:
{steps_md}
- **Remediation**: {finding.get('recommendation', 'Apply secure remediation and retest')}
""".strip()
        )
    detailed_findings = "\n\n".join(detailed_blocks) if detailed_blocks else "No findings captured across the scanned tools."

    executive_report = f"""
# Consolidated Executive Security Report (CISO and Senior Management)

## Assessment Overview
- **Target**: {target}
- **Tools**: {", ".join([t.upper() for t in tools_list]) if tools_list else "N/A"}
- **Total Scans**: {len(rows)}
- **Generated**: {format_abu_dhabi(datetime.utcnow())}

## Risk Snapshot
- **Critical**: {sev_counts['critical']}
- **High**: {sev_counts['high']}
- **Medium**: {sev_counts['medium']}
- **Low**: {sev_counts['low']}
- **Informational**: {sev_counts['info']}

## Summary of Scan Coverage
{coverage_lines}

## Tool Overview
{chr(10).join([f"- {t.upper()}: {tool_methods.get(t, 'Automated scanning.')} Tested: {tested_scope.get(t, 'Target URL and reachable endpoints.')}" for t in tools_list])}

## High-Level Executive Summary (AI Assisted)
{consolidated_exec_summary}

## Key Findings by Tool
{key_findings_lines}

## Executive Recommendations
1. Prioritize critical/high findings for immediate remediation and risk acceptance decisions.
2. Validate all fixes with focused retest before production closure.
3. Maintain continuous attack-surface monitoring and quarterly assurance reporting.

## Standards Alignment
Report style aligns to OWASP testing guidance, NIST SP 800-115 execution structure, ISO 27001 remediation governance, and UAE IAS expectations (PCI DSS included only for payment-scope systems).
"""

    technical_report = f"""
# Consolidated Technical Security Report (Operations and Engineering)

## Scope and Tool Coverage
- **Target**: {target}
- **Total Scans**: {len(rows)}
- **Generated**: {format_abu_dhabi(datetime.utcnow())}

## Methodology and What Was Tested
{chr(10).join([f"- {t}: {tool_methods.get(t, 'Automated scanning.')} Tested: {tested_scope.get(t, 'Target URL and reachable endpoints.')}" for t in tools_list])}

## Technical Summary (AI Assisted)
{consolidated_tech_summary}

## Tool-by-Tool Findings
{chr(10).join(combined_findings)}

## Detailed Findings with PoC, Reproduction, and Remediation
{detailed_findings}
"""

    meta = {
        "tools_used": tools_list,
        "created_at": min(created_times) if created_times else datetime.now().isoformat(),
        "completed_at": max(completed_times) if completed_times else (min(created_times) if created_times else datetime.now().isoformat()),
        "target_system": "Web Application",
        "assessment_type": "Automated security assessment",
        "report_id": f"ASH-PENTEST-{report_id_target_label(target)}",
        "nuclei_contexts": nuclei_contexts,
        "ai_executive_summary": consolidated_exec_summary,
        "ai_technical_summary": consolidated_tech_summary,
    }

    html_combined = generate_html_report(executive_report, technical_report, rows[0]["id"], target, "All Tools", mode="combined", findings=all_findings, meta=meta)
    html_exec = generate_html_report(executive_report, technical_report, rows[0]["id"], target, "All Tools", mode="executive", findings=all_findings, meta=meta)
    html_tech = generate_html_report(executive_report, technical_report, rows[0]["id"], target, "All Tools", mode="technical", findings=all_findings, meta=meta)

    safe = target_report_ref(target)
    report_file = REPORTS_DIR / f"report_target_{safe}.html"
    report_exec_file = REPORTS_DIR / f"report_target_{safe}_executive.html"
    report_tech_file = REPORTS_DIR / f"report_target_{safe}_technical.html"
    write_text_atomic(report_file, html_combined)
    write_text_atomic(report_exec_file, html_exec)
    write_text_atomic(report_tech_file, html_tech)

    return {
        "executive": executive_report,
        "technical": technical_report,
        "html_path": str(report_file),
        "html_executive_path": str(report_exec_file),
        "html_technical_path": str(report_tech_file)
    }

def generate_html_report(executive, technical, scan_id, target, tool, mode="combined", findings=None, meta=None):
    """Generate HTML reports using newreports templates and live scan findings."""
    findings = findings or []
    meta = meta or {}

    def normalize_severity(value: str) -> str:
        if not value:
            return "info"
        value = value.lower()
        if "critical" in value:
            return "critical"
        if "high" in value:
            return "high"
        if "medium" in value:
            return "medium"
        if "low" in value:
            return "low"
        if "info" in value or "informational" in value:
            return "info"
        return "info"

    def severity_label(value: str) -> str:
        return normalize_severity(value).upper()

    def severity_rank(value: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(normalize_severity(value), 4)

    def build_counts(items):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in items:
            counts[effective_severity(item)] += 1
        return counts

    def parse_cvss_numeric(value) -> float | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", text)
        if not matches:
            return None
        try:
            # Use the trailing numeric token to avoid picking the version number from strings like "CVSS v4.0 6.5".
            return max(0.0, min(float(matches[-1]), 10.0))
        except Exception:
            return None

    def cvss_band(score: float | None) -> str:
        if score is None:
            return "info"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"

    _sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def effective_severity(item) -> str:
        """Return the severity used for reporting.

        Some scan adapters historically set severity=INFO while still attaching a CVSS score
        (e.g. CVSS 9.1). Reports should not show contradictory outputs (INFO vs CRITICAL CVSS).

        We only *escalate* based on CVSS; we never downgrade a tool-provided severity.
        """
        declared = normalize_severity(str(item.get("severity", "")))
        derived = cvss_band(parse_cvss_numeric(item.get("cvss")))
        if _sev_rank.get(derived, 0) > _sev_rank.get(declared, 0):
            return derived
        return declared

    def severity_rank_item(item) -> int:
        return severity_rank(effective_severity(item))

    def calculate_overall_score(items, counts) -> float:
        scores = [parse_cvss_numeric(item.get("cvss")) for item in items]
        scores = [s for s in scores if s is not None]
        if scores:
            # Executive score follows peak observed exposure (CVSS v4.0 aligned).
            return round(max(0.0, min(max(scores), 10.0)), 1)
        # Fallback when numeric CVSS is unavailable.
        if counts["critical"] > 0:
            return 9.5
        if counts["high"] > 0:
            return 8.0
        if counts["medium"] > 0:
            return 5.5
        if counts["low"] > 0:
            return 2.5
        if counts["info"] > 0:
            return 0.5
        return 0.0

    def risk_level_from_score(score: float, counts):
        if score >= 9.0 or counts["critical"] > 0:
            return ("CRITICAL", "critical")
        if score >= 7.0 or counts["high"] > 0:
            return ("HIGH", "high")
        if score >= 4.0 or counts["medium"] > 0:
            return ("MEDIUM", "medium")
        if score > 0.0 or counts["low"] > 0:
            return ("LOW", "low")
        return ("INFO", "info")

    def bar_width(count, max_count):
        if max_count <= 0:
            return "2%"
        pct = int((count / max_count) * 100)
        pct = max(pct, 2 if count == 0 else 8)
        pct = min(pct, 100)
        return f"{pct}%"

    def load_template(name: str) -> str:
        path = BASE_DIR / "newreports" / name
        return path.read_text()

    def inline_css(html: str) -> str:
        css = (BASE_DIR / "newreports" / "report.css").read_text()
        return html.replace('<link rel="stylesheet" href="report-styles.css">', f"<style>{css}</style>")

    def apply_placeholders(html: str, mapping: dict) -> str:
        for key, value in mapping.items():
            html = html.replace(f"{{{{{key}}}}}", str(value))
        return html

    def esc(value: str) -> str:
        return (
            str(value or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def normalize_tool_id(value: str) -> str:
        text = str(value or "").strip().lower()
        aliases = {
            "all": "all tools",
            "alltools": "all tools",
            "all tools": "all tools",
            "all_tools": "all tools",
        }
        return aliases.get(text, text)

    def classify_nuclei_template(template_id: str) -> str:
        text = (template_id or "").lower()
        if not text:
            return "general security validation"
        if re.search(r"cve[-_]\d{4}-\d+", text):
            return "CVE vulnerability check"
        if any(k in text for k in ["xss", "sqli", "sql-injection", "rce", "lfi", "ssrf", "xxe", "ssti", "csrf", "redirect"]):
            return "web vulnerability check"
        if any(k in text for k in ["misconfig", "misconfiguration", "header", "hsts", "csp", "clickjacking", "cors"]):
            return "security misconfiguration check"
        if any(k in text for k in ["exposure", "exposed", "panel", "default-login", "unauth", "takeover"]):
            return "exposure and attack-surface check"
        if any(k in text for k in ["tech", "fingerprint", "detect"]):
            return "technology and fingerprint check"
        return "general security validation"

    def infer_nuclei_focus_from_tags(tags_value: str | None) -> str:
        tags_text = (tags_value or "").strip().lower()
        if not tags_text:
            return "general vulnerability and exposure"
        tags = {tag.strip() for tag in tags_text.split(",") if tag.strip()}
        focuses = []
        if {"cve", "vuln", "vulnerability"} & tags:
            focuses.append("CVE vulnerability")
        if {"misconfig", "misconfiguration", "headers", "header", "csp", "hsts"} & tags:
            focuses.append("security misconfiguration")
        if {"http", "web", "probing", "light", "quick"} & tags:
            focuses.append("lightweight HTTP exposure")
        if {"tech", "fingerprint", "detect"} & tags:
            focuses.append("technology fingerprint")
        if not focuses:
            return "general vulnerability and exposure"
        return ", ".join(focuses)

    def collect_nuclei_templates(items) -> list[str]:
        templates = []
        for item in items:
            if normalize_tool_id(item.get("tool", "")) != "nuclei":
                continue
            raw = str(item.get("raw_title") or "").strip()
            title = str(item.get("title") or "").strip()
            candidate = raw or title
            if not candidate:
                continue
            lowered = candidate.lower()
            if any(marker in lowered for marker in ["completed without", "no output", "scan error", "no actionable"]):
                continue
            candidate = re.sub(r"\s+", "-", candidate.lower())
            candidate = re.sub(r"[^a-z0-9._-]", "", candidate)
            if not candidate:
                continue
            if candidate not in templates:
                templates.append(candidate)
        return templates

    def build_nuclei_tool_context(items) -> dict | None:
        template_ids = collect_nuclei_templates(items)
        contexts = meta.get("nuclei_contexts") if isinstance(meta.get("nuclei_contexts"), list) else []
        executed_count = meta.get("nuclei_templates_executed")
        tags = meta.get("nuclei_tags")
        severity_scope = meta.get("nuclei_severity")
        if executed_count is None and contexts:
            for ctx in contexts:
                if ctx.get("templates_executed") is not None:
                    executed_count = ctx.get("templates_executed")
                    break
        if not tags and contexts:
            tags = next((ctx.get("tags") for ctx in contexts if ctx.get("tags")), None)
        if not severity_scope and contexts:
            severity_scope = next((ctx.get("severity") for ctx in contexts if ctx.get("severity")), None)

        if not template_ids and executed_count is None:
            return None

        inferred_focus = infer_nuclei_focus_from_tags(tags)
        executed_label = executed_count if executed_count is not None else len(template_ids) if template_ids else None
        if executed_label is not None:
            activity = f"Executed {executed_label} templates for {inferred_focus} checks."
        else:
            activity = f"Executed targeted templates for {inferred_focus} checks."

        deliverable = "Template-level evidence mapped to CVE/misconfiguration exposure themes and remediation priorities."
        return {
            "purpose": "Runs targeted Nuclei templates to validate known CVEs, exposure patterns, and security misconfigurations.",
            "activity": activity,
            "deliverable": deliverable,
        }

    tool_catalog = {
        "katana": {
            "display": "Katana",
            "category": "Attack Surface Discovery",
            "purpose": "Crawls the target to discover reachable endpoints, parameters, and linked assets.",
            "activity": "Run crawler with in-scope URL discovery and endpoint enumeration.",
            "deliverable": "Endpoint inventory with candidate attack surface paths.",
        },
        "sqlmap": {
            "display": "SQLMap",
            "category": "Injection Testing",
            "purpose": "Tests request parameters for SQL injection behavior and database exposure risk.",
            "activity": "Run automated SQL injection probes on detected/requested parameters.",
            "deliverable": "Injection validation evidence and parameter-level risk notes.",
        },
        "nuclei": {
            "display": "Nuclei",
            "category": "Vulnerability Validation",
            "purpose": "Runs lightweight vulnerability templates to detect known CVEs and misconfigurations.",
            "activity": "Execute selected light templates against reachable HTTP endpoints.",
            "deliverable": "Template matches with severity and remediation priority.",
        },
        "nikto": {
            "display": "Nikto",
            "category": "Web Server Hardening",
            "purpose": "Checks web server security headers, exposed files, and baseline misconfigurations.",
            "activity": "Enumerate web server controls, risky files, and common weakness indicators.",
            "deliverable": "Configuration findings with corrective hardening guidance.",
        },
    }

    nuclei_context = build_nuclei_tool_context(findings)
    if nuclei_context:
        tool_catalog["nuclei"].update(nuclei_context)
    tool_order = REPORT_FINDINGS_ORDER

    def resolve_tools_used() -> list[str]:
        raw_tools = meta.get("tools_used") or [tool]
        normalized = []
        for item in raw_tools:
            tool_id = normalize_tool_id(item)
            if tool_id and tool_id not in normalized:
                normalized.append(tool_id)

        # Some legacy records use "All Tools". Expand using finding evidence when available.
        if "all tools" in normalized:
            inferred = []
            for item in findings:
                inferred_id = normalize_tool_id(item.get("tool", ""))
                if inferred_id in tool_catalog and inferred_id not in inferred:
                    inferred.append(inferred_id)
            normalized = inferred or [name for name in tool_order if name in tool_catalog]

        # Add any tool that appeared in findings but not in metadata.
        for item in findings:
            inferred_id = normalize_tool_id(item.get("tool", ""))
            if inferred_id in tool_catalog and inferred_id not in normalized:
                normalized.append(inferred_id)

        known = [name for name in tool_order if name in normalized]
        extras = [name for name in normalized if name not in known]
        return known + extras

    def bool_from_meta(value) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "y", "on", "payment", "pci"}:
            return True
        if text in {"0", "false", "no", "n", "off", "core", "non-payment", "nonpayment"}:
            return False
        return None

    def detect_payment_scope(items) -> bool:
        profile = str(meta.get("compliance_profile", "")).strip().lower()
        if profile in {"payment", "pci", "payment-profile", "payment_scope"}:
            return True
        if profile in {"core", "default", "non-payment", "nonpayment"}:
            return False

        for flag_key in ("payment_scope", "is_payment_scope", "pci_scope", "cardholder_data_scope"):
            explicit = bool_from_meta(meta.get(flag_key))
            if explicit is not None:
                return explicit

        corpus_parts = [target]
        for item in items:
            corpus_parts.extend(
                [
                    str(item.get("title", "")),
                    str(item.get("raw_title", "")),
                    str(item.get("location", "")),
                    str(item.get("evidence", "")),
                    str(item.get("impact", "")),
                ]
            )
        corpus = " ".join(corpus_parts).lower()
        payment_markers = (
            "payment", "checkout", "cardholder", "credit card", "debit card", "pan", "cvv",
            "3ds", "3d secure", "pos", "point of sale", "merchant", "gateway",
            "visa", "mastercard", "amex", "mada", "apple pay", "google pay"
        )
        for marker in payment_markers:
            pattern = r"\b" + re.escape(marker).replace(r"\ ", r"\s+") + r"\b"
            if re.search(pattern, corpus):
                return True
        return False

    selected_tools = resolve_tools_used()

    def tool_display_name(tool_id: str) -> str:
        return tool_catalog.get(tool_id, {}).get("display", tool_id.title() or "Tool")

    def tool_version(tool_id: str) -> str:
        version_map = meta.get("tool_versions") or {}
        if isinstance(version_map, dict) and version_map.get(tool_id):
            return str(version_map.get(tool_id))
        return "Installed local build"

    def cvss_class_for_item(item) -> str:
        score = parse_cvss_numeric(item.get("cvss"))
        return cvss_band(score)

    def finding_corpus(item) -> str:
        return " ".join(
            [
                str(item.get("title", "")),
                str(item.get("raw_title", "")),
                str(item.get("evidence", "")),
                str(item.get("impact", "")),
                str(item.get("recommendation", "")),
                str(item.get("tool", "")),
            ]
        ).lower()

    def is_non_actionable_observation(item) -> bool:
        text = finding_corpus(item)
        markers = (
            "no sql injection evidence detected",
            "scan completed without actionable output",
            "completed without matched templates",
            "completed with no output",
            "no actionable",
            "no endpoints discovered",
            "scanner runtime error",
        )
        return any(marker in text for marker in markers)

    def extract_finding_signals(items) -> dict:
        signals = {
            "header_hardening": False,
            "transport_hardening": False,
            "endpoint_exposure": False,
            "sensitive_file_exposure": False,
            "injection_positive": False,
            "injection_negative": False,
            "runtime_gap": False,
            "cve_exposure": False,
        }
        for item in items:
            text = finding_corpus(item)
            if any(k in text for k in ["x-content-type-options", "x-frame-options", "frame-ancestors", "clickjacking", "content-security-policy", "mime-sniff"]):
                signals["header_hardening"] = True
            if any(k in text for k in ["strict-transport-security", " hsts", "hsts "]):
                signals["transport_hardening"] = True
            if any(k in text for k in ["endpoint discovery", "externally reachable endpoints discovered", "katana", "discovered endpoint", "discovered urls", "attack surface"]):
                signals["endpoint_exposure"] = True
            if any(k in text for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive", "exposed artifact"]):
                signals["sensitive_file_exposure"] = True
            if is_negative_injection_signal(text):
                signals["injection_negative"] = True
            elif any(k in text for k in ["sql injection vulnerability detected", "potential sql injection indicator", "sql injection evidence detected", "injectable"]):
                signals["injection_positive"] = True
            if any(k in text for k in ["runtime error", "timed out", "partial timeout", "scan error"]):
                signals["runtime_gap"] = True
            if "cve-" in text:
                signals["cve_exposure"] = True
        return signals

    def dedupe_lines(lines: list[str]) -> list[str]:
        result = []
        seen = set()
        for line in lines:
            text = " ".join(str(line).split()).strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(text)
        return result

    def build_key_findings(items):
        """Executive high-level overview (no deep PoC/evidence detail)."""
        ranked = sorted(items, key=severity_rank_item)

        # Report must be internally consistent: if the severity counters say there are N findings,
        # the executive "High-Level Findings Overview" should not silently drop findings.
        #
        # We still prefer to show "material" findings first, but we keep assurance/coverage outcomes
        # (e.g. "no matched templates", "no SQLi detected") in the table so executives see the full picture.
        material = [item for item in ranked if not is_non_actionable_observation(item)]
        non_material = [item for item in ranked if is_non_actionable_observation(item)]

        ordered = (material + non_material) if (material or non_material) else ranked

        # Avoid huge executive tables: always show full findings for small totals (prevents "7 findings shown as 4"),
        # otherwise cap with a clear note.
        try:
            max_rows = int(str(os.getenv("EXEC_FINDINGS_OVERVIEW_MAX", "80")).strip() or "80")
        except Exception:
            max_rows = 80
        max_rows = max(10, min(max_rows, 200))

        always_full_under = 25
        if len(ordered) <= always_full_under:
            truncated = False
            highlights = ordered
        else:
            truncated = len(ordered) > max_rows
            highlights = ordered if not truncated else ordered[:max_rows]
        if not highlights:
            return (
                "<div class=\"summary-box\">"
                "<h3>High-Level Findings Overview</h3>"
                "<p>No material findings were identified in this assessment scope.</p>"
                "</div>"
            )

        rows = []
        for idx, item in enumerate(highlights, 1):
            sev = effective_severity(item)
            title = esc(item.get("title", "Finding"))
            impact = esc(item.get("impact", "Business impact requires contextual validation."))
            tool_name = esc(item.get("tool", "tool"))
            cvss_value = format_cvss(item.get("cvss"))
            cvss_class = cvss_class_for_item(item)
            rows.append(
                "<tr>"
                f"<td>{idx:02d}</td>"
                f"<td><span class=\"severity-badge {sev}\">{sev.upper()}</span></td>"
                f"<td>{title}</td>"
                f"<td><span class=\"cvss-score cvss-{cvss_class}\">{esc(cvss_value)}</span></td>"
                f"<td>{tool_name}</td>"
                f"<td>{impact[:180]}</td>"
                "</tr>"
            )
        note = (
            f"<p class=\"risk-context-footnote\">Showing {len(highlights)} of {len(ordered)} findings. "
            "Refer to the technical report for the complete finding list and supporting evidence.</p>"
            if truncated
            else ""
        )
        return (
            "<div class=\"summary-box\">"
            "<h3>High-Level Findings Overview</h3>"
            "<table class=\"tools-table high-level-findings-table\">"
            "<thead><tr><th>#</th><th>Severity</th><th>Observation</th><th>CVSS v4.0</th><th>Source</th><th>Business Relevance</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            f"{note}"
            "</div>"
        )

    def build_coverage_rows(items):
        def resolve_nuclei_context_value(key: str):
            direct = meta.get(key)
            if direct not in (None, ""):
                return direct
            contexts = meta.get("nuclei_contexts") if isinstance(meta.get("nuclei_contexts"), list) else []
            for ctx in contexts:
                value = ctx.get(key.replace("nuclei_", "")) if isinstance(ctx, dict) else None
                if value not in (None, ""):
                    return value
            return None

        def tests_performed_for_tool(tool_id: str) -> str:
            if tool_id == "katana":
                return "URL crawl and endpoint discovery requests."
            if tool_id == "sqlmap":
                return "SQL injection payload validation on tested parameters."
            if tool_id == "nikto":
                return "HTTP header, server fingerprint, and risky path checks."
            if tool_id == "nuclei":
                executed = resolve_nuclei_context_value("nuclei_templates_executed")
                tags = resolve_nuclei_context_value("nuclei_tags")
                if executed not in (None, "") and tags:
                    return f"{executed} template checks ({tags})."
                if executed not in (None, ""):
                    return f"{executed} template checks."
                if tags:
                    return f"Template checks with tags: {tags}."
                return "Template-based vulnerability validation checks."
            return "Automated security validation checks."

        def coverage_scope_for_tool(tool_id: str) -> str:
            if tool_id == "katana":
                return "Attack-surface endpoint discovery."
            if tool_id == "sqlmap":
                return "Parameter-level injection coverage."
            if tool_id == "nikto":
                return "Web-server hardening control review."
            if tool_id == "nuclei":
                return "Template-driven vulnerability exposure validation."
            return "Automated in-scope validation."

        tool_map = {tool_id: 0 for tool_id in selected_tools}
        for item in items:
            tool_id = normalize_tool_id(item.get("tool", "tool"))
            tool_map.setdefault(tool_id, 0)
            tool_map[tool_id] += 1
        if not tool_map:
            return (
                "<tr><td>Automated scan</td><td>Baseline security checks</td>"
                "<td>Limited in-scope validation</td><td>0</td></tr>"
            )
        rows = []
        ordered_tools = [tool_id for tool_id in selected_tools if tool_id in tool_map]
        ordered_tools.extend([tool_id for tool_id in tool_map if tool_id not in ordered_tools])
        for tool_id in ordered_tools:
            tool_name = tool_display_name(tool_id)
            tests_performed = tests_performed_for_tool(tool_id)
            coverage_scope = coverage_scope_for_tool(tool_id)
            count = tool_map.get(tool_id, 0)
            rows.append(
                f"<tr><td>{esc(tool_name)}</td><td>{esc(tests_performed)}</td>"
                f"<td>{esc(coverage_scope)}</td><td>{count}</td></tr>"
            )
        return "\n".join(rows)

    def build_tools_rows():
        tool_rows = []
        for tool_id in selected_tools:
            info = tool_catalog.get(tool_id)
            if not info:
                continue
            tool_rows.append((info["category"], info["display"], tool_version(tool_id), info["purpose"]))
        if not tool_rows:
            return "<tr><td>Tools</td><td>Automated Scanner</td><td>Installed local build</td><td>Automated vulnerability and exposure checks.</td></tr>"
        rows = []
        for category, tool_name, version, purpose in tool_rows:
            rows.append(
                f"<tr><td>{esc(category)}</td><td>{esc(tool_name)}</td><td>{esc(version)}</td><td>{esc(purpose)}</td></tr>"
            )
        return "\n".join(rows)

    def build_tools_appendix_rows():
        rows = []
        for tool_id in selected_tools:
            info = tool_catalog.get(tool_id)
            if not info:
                continue
            rows.append(
                f"<tr><td>{esc(info['display'])}</td><td>{esc(tool_version(tool_id))}</td><td>{esc(info['purpose'])}</td></tr>"
            )
        if not rows:
            return (
                "<tr><td>Automated Scanner</td><td>Installed local build</td>"
                "<td>No in-scope tool metadata was available for this report.</td></tr>"
            )
        return "\n".join(rows)

    def build_testing_phase_rows():
        rows = [
            (
                "1. Scope Validation",
                "Automated pre-check",
                "Validate target availability, protocol, and in-scope configuration.",
                "Confirmed test scope and reachable target baseline.",
            )
        ]
        phase_map = {
            "katana": (
                "Endpoint Discovery (Katana)",
                "Automated scan window",
                tool_catalog["katana"]["activity"],
                tool_catalog["katana"]["deliverable"],
            ),
            "sqlmap": (
                "Injection Validation (SQLMap)",
                "Automated scan window",
                tool_catalog["sqlmap"]["activity"],
                tool_catalog["sqlmap"]["deliverable"],
            ),
            "nuclei": (
                "Template Validation (Nuclei)",
                "Automated scan window",
                tool_catalog["nuclei"]["activity"],
                tool_catalog["nuclei"]["deliverable"],
            ),
            "nikto": (
                "Server Hardening Review (Nikto)",
                "Automated scan window",
                tool_catalog["nikto"]["activity"],
                tool_catalog["nikto"]["deliverable"],
            ),
        }
        for tool_id in selected_tools:
            phase = phase_map.get(tool_id)
            if not phase:
                continue
            rows.append(phase)
        rows.append(
            (
                f"{len(rows) + 1}. Evidence Correlation & Reporting",
                "Post-scan analysis",
                "Correlate scan outputs, prioritize risk, and document remediation guidance.",
                "Executive and technical reports with actionable remediation items.",
            )
        )
        rendered = []
        for phase_name, duration, activities, deliverables in rows:
            rendered.append(
                "<tr>"
                f"<td><strong>{esc(phase_name)}</strong></td>"
                f"<td>{esc(duration)}</td>"
                f"<td>{esc(activities)}</td>"
                f"<td>{esc(deliverables)}</td>"
                "</tr>"
            )
        return "\n".join(rendered)

    def build_glossary_block(items):
        corpus_parts = []
        for item in items:
            corpus_parts.append(str(item.get("title", "")))
            corpus_parts.append(str(item.get("raw_title", "")))
            corpus_parts.append(str(item.get("evidence", "")))
            corpus_parts.append(str(item.get("impact", "")))
            corpus_parts.append(str(item.get("recommendation", "")))
            corpus_parts.append(str(item.get("tool", "")))
        corpus = " ".join(corpus_parts).lower()

        def has_any(*keywords):
            return any(k in corpus for k in keywords)

        entries = []
        seen = set()

        def add(term: str, definition: str):
            key = term.lower()
            if key in seen:
                return
            seen.add(key)
            entries.append((term, definition))

        if items:
            add(
                "CVSS v4.0 (Common Vulnerability Scoring System)",
                "Industry standard used to score vulnerability severity and prioritize remediation."
            )
        if has_any("sql injection", "injectable", "sqlmap"):
            add(
                "SQL Injection",
                "A flaw where untrusted input alters SQL queries, potentially exposing or modifying database data."
            )
        if has_any("xss", "cross-site scripting"):
            add(
                "XSS (Cross-Site Scripting)",
                "A vulnerability that allows script execution in a victim browser within the trusted application context."
            )
        if has_any("remote code execution", " rce ", "rce vulnerability"):
            add(
                "RCE (Remote Code Execution)",
                "A critical condition where an attacker can execute arbitrary code on a target system."
            )
        if has_any("cve-"):
            add(
                "CVE (Common Vulnerabilities and Exposures)",
                "A standardized identifier used to reference publicly disclosed security vulnerabilities."
            )
        if has_any("x-frame-options", "frame-ancestors", "clickjacking"):
            add(
                "Clickjacking",
                "A UI-redress risk where users are tricked into unintended actions through hidden/overlaid frames."
            )
        if has_any("x-content-type-options", "mime-sniff", "nosniff"):
            add(
                "MIME Sniffing",
                "Browser content-type guessing behavior that can increase script execution risk when protection headers are missing."
            )
        if has_any("strict-transport-security", " hsts", "hsts "):
            add(
                "HSTS (HTTP Strict Transport Security)",
                "A policy header that forces browsers to use HTTPS and helps prevent downgrade and interception attacks."
            )
        if has_any(".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive", "exposed file"):
            add(
                "Sensitive File Exposure",
                "Unintended access to backup, archive, or credential-related artifacts that may disclose internal data."
            )
        if has_any("endpoint discovery", "katana", "crawl", "discovered endpoint", "discovered url"):
            add(
                "Endpoint Discovery",
                "Identification of reachable URLs and assets that expand attack-surface visibility for testing."
            )
        if has_any("waf", "connection reset"):
            add(
                "WAF (Web Application Firewall)",
                "A security control that filters HTTP traffic and may block automated attack payloads."
            )
        if has_any("scan error", "runtime error"):
            add(
                "Scan Reliability",
                "Operational scan quality context indicating where runtime issues may reduce assessment completeness."
            )

        if not entries:
            return (
                "<dt>In-Scope Security Terminology</dt>"
                "<dd>No specialized vulnerability terms were triggered by the observed findings in this report scope.</dd>"
            )
        return "\n".join([f"<dt>{esc(term)}</dt><dd>{esc(defn)}</dd>" for term, defn in entries])

    def build_detailed_findings(items):
        blocks = []
        if not items:
            return "<p>No findings available.</p>"
        for idx, item in enumerate(sorted(items, key=severity_rank_item), 1):
            sev = effective_severity(item)
            title = esc(item.get("title", "Finding"))
            location = esc(item.get("location", item.get("endpoint", "N/A")))
            evidence = item.get("evidence", "")
            tool_name = esc(item.get("tool", "tool"))
            impact = item.get("impact", "Impact requires technical validation.")
            poc = item.get("poc", "Re-run tool command and capture request/response proof.")
            remediation = item.get("recommendation", "Apply hardening and validate with retest.")
            reproduction_steps = item.get("reproduction_steps") or []
            steps_html = "".join([f"<li>{esc(step)}</li>" for step in reproduction_steps]) or "<li>Re-run scan with identical options and compare evidence before/after remediation.</li>"
            notes = item.get("notes")
            notes_html = f"<p><strong>Notes:</strong> {esc(notes)}</p>" if notes else ""
            cvss_class = cvss_class_for_item(item)
            blocks.append(
                f'''
                <div class="vulnerability-detail">
                    <div class="finding-header">
                        <div class="severity-badge {sev}">{sev.upper()}</div>
                        <div class="cvss-score cvss-{cvss_class}">{format_cvss(item.get("cvss"))}</div>
                    </div>
                    <h2 style="font-size: 20px; margin: 1rem 0;">{idx}. {title}</h2>
                    <div class="info-grid" style="margin: 1rem 0;">
                        <div class="info-item"><span class="info-label">Tool:</span><span class="info-value">{tool_name}</span></div>
                        <div class="info-item"><span class="info-label">Location:</span><span class="info-value">{location}</span></div>
                        <div class="info-item"><span class="info-label">Severity:</span><span class="info-value">{sev.upper()}</span></div>
                    </div>
                    <h3>Evidence</h3>
                    <div class="code-block">{esc(evidence or 'No evidence captured')}</div>
                    <h3>Technical Impact</h3>
                    <p>{esc(impact)}</p>
                    <h3>Proof of Concept</h3>
                    <div class="code-block">{esc(poc)}</div>
                    <h3>Reproduction Steps</h3>
                    <ol>{steps_html}</ol>
                    <h3>Remediation</h3>
                    <p>{esc(remediation)}</p>
                    {notes_html}
                </div>
                '''
            )
        return "\n".join(blocks)

    def build_remediation_block(items, counts):
        if not items:
            return (
                "<div class=\"summary-box\">"
                "<h3>Recommended Actions</h3>"
                "<ul><li>No actionable findings were observed in this scope. Maintain monitoring and scheduled validation.</li></ul>"
                f"<p>Findings summary: Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, Low {counts['low']}, Info {counts['info']}.</p>"
                "</div>"
            )

        ranked = sorted(items, key=severity_rank_item)
        actionable = [f for f in ranked if effective_severity(f) in ("critical", "high", "medium")]
        immediate_actions = []
        if not actionable:
            immediate_actions.append(
                "No critical/high/medium weaknesses were identified in this assessment window; continue preventive hardening and validation."
            )
            top_info = ranked[:2]
            for finding in top_info:
                title = str(finding.get("title", "Finding")).strip()
                rec = str(finding.get("recommendation", "Apply remediation and validate closure with retest.")).strip()
                immediate_actions.append(f"{title}: {rec}")
        else:
            for finding in actionable[:3]:
                title = str(finding.get("title", "Finding")).strip()
                location = str(finding.get("location", finding.get("endpoint", "N/A"))).strip()
                rec = str(finding.get("recommendation", "Apply remediation and validate closure with retest.")).strip()
                immediate_actions.append(
                    f"{title} at {location}: {rec}"
                )

        corpus = " ".join(
            [str(i.get("title", "")) + " " + str(i.get("evidence", "")) + " " + str(i.get("tool", "")) for i in items]
        ).lower()
        short_term = []
        has_negative_injection = is_negative_injection_signal(corpus)
        if (not has_negative_injection) and any(k in corpus for k in ["sql injection", "injectable", "sqlmap"]):
            short_term.append("Harden database access patterns with parameterized queries, input validation, and least-privilege roles.")
        if any(k in corpus for k in ["x-frame-options", "x-content-type-options", "hsts", "header", "csp", "clickjacking"]):
            short_term.append("Standardize and enforce security headers (CSP, HSTS, X-Content-Type-Options, and framing policy) across web responses.")
        if any(k in corpus for k in [".jks", ".tar", ".tgz", ".war", ".zip", "backup", "archive"]):
            short_term.append("Remove exposed artifacts from web-accessible paths and rotate any potentially impacted secrets or certificates.")
        if any(k in corpus for k in ["katana", "endpoint discovery", "discovered"]):
            short_term.append("Review discovered endpoints, decommission unused routes, and enforce authentication/authorization controls.")
        if not short_term:
            short_term.append("Complete corrective changes for observed findings and verify closure using focused follow-up scans.")

        long_term = [
            "Implement continuous vulnerability management with recurring scans, ownership tracking, and SLA-based closure.",
            "Run formal re-test after remediation completion and attach before/after evidence for audit and governance review.",
        ]

        def render_list(title: str, entries: list[str]) -> str:
            lis = "".join([f"<li>{esc(entry)}</li>" for entry in entries])
            return f"<div class=\"summary-box\"><h3>{esc(title)}</h3><ul>{lis}</ul></div>"

        return (
            render_list("Immediate (1-7 Days)", immediate_actions) +
            render_list("Short Term (8-30 Days)", short_term) +
            render_list("Long Term (31-90 Days)", long_term) +
            f"<div class=\"summary-box\"><p>Findings summary: Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, Low {counts['low']}, Info {counts['info']}.</p></div>"
        )

    def build_recommendations_block(items):
        if not items:
            return (
                "<div class=\"summary-box\">"
                "<h3>Immediate (0-7 Days)</h3>"
                "<ul><li>No findings detected. Confirm with manual validation and monitoring.</li></ul>"
                "</div>"
            )
        signals = extract_finding_signals(items)
        ranked = sorted(
            items,
            key=lambda x: (
                severity_rank_item(x),
                -(parse_cvss_numeric(x.get("cvss")) or 0.0),
            ),
        )
        actionable = [item for item in ranked if not is_non_actionable_observation(item)]
        priority_items = [
            item for item in actionable
            if effective_severity(item) in ("critical", "high", "medium")
        ] or actionable

        recs_immediate = []
        recs_short = []
        recs_long = []

        for item in priority_items[:3]:
            title = str(item.get("title", "Finding")).strip()
            recommendation = str(item.get("recommendation", "Apply remediation and verify closure with retesting.")).strip()
            recs_immediate.append(f"{title}: {recommendation}")

        if not recs_immediate:
            recs_immediate.append("No exploitable critical/high/medium findings were confirmed; preserve current controls and run focused revalidation.")

        if signals["header_hardening"] or signals["transport_hardening"]:
            recs_short.append("Standardize web response security headers across all production routes and validate via automated header checks in CI.")
        if signals["endpoint_exposure"]:
            recs_short.append("Review discovered externally reachable endpoints, remove unused routes, and enforce authentication/authorization on sensitive paths.")
        if signals["injection_positive"]:
            recs_short.append("Expand SQL injection validation to authenticated and parameter-rich flows after remediation to confirm absence of exploitable paths.")
        elif signals["injection_negative"]:
            recs_short.append("Maintain parameterized query controls and broaden test coverage to additional inputs/APIs to preserve assurance over time.")
        if signals["runtime_gap"]:
            recs_short.append("Address scan runtime constraints and schedule targeted retesting to close any residual coverage gaps.")
        if signals["sensitive_file_exposure"]:
            recs_short.append("Audit web-accessible file paths for build, backup, and credential artifacts; remove exposures and rotate potentially affected secrets.")
        if not recs_short:
            recs_short.append("Consolidate remediation tasks into an owner-tracked backlog and validate closure with targeted re-scans.")

        if signals["header_hardening"] or signals["transport_hardening"]:
            recs_long.append("Enforce a centralized web security baseline (headers/TLS controls) with drift monitoring and periodic control validation.")
        if signals["endpoint_exposure"]:
            recs_long.append("Maintain a governed endpoint inventory from recurring discovery scans and tie each route to ownership and access-control review.")
        if signals["injection_positive"] or signals["injection_negative"]:
            recs_long.append("Embed secure database coding checks and parameter validation controls into SDLC gates, then revalidate through scheduled injection testing.")
        if signals["sensitive_file_exposure"]:
            recs_long.append("Implement artifact publishing controls and secret-rotation workflows to prevent recurrence of exposed backup or build files.")
        if signals["cve_exposure"]:
            recs_long.append("Establish patch intelligence and emergency remediation playbooks for components flagged by vulnerability template matches.")
        if signals["runtime_gap"]:
            recs_long.append("Improve scan execution reliability (timeouts/resources) and schedule compensating retests for partially assessed scope.")
        if not recs_long:
            recs_long.append("Run continuous vulnerability management with severity-based SLAs and periodic executive reporting on risk trend reduction.")
        recs_long.append("Map closure evidence to ISO 27001 risk treatment records and maintain traceable testing evidence per NIST SP 800-115 and UAE IAS.")
        if detect_payment_scope(items):
            recs_long.append("For payment-scope assets, execute PCI DSS v4.0.1 Requirement 11.4 penetration testing and post-change retesting.")

        recs_immediate = dedupe_lines(recs_immediate)
        recs_short = dedupe_lines(recs_short)
        recs_long = dedupe_lines(recs_long)

        def section(title, items_list):
            lis = "".join([f"<li>{esc(i)}</li>" for i in items_list])
            return f"<div class=\"summary-box\"><h3>{esc(title)}</h3><ul>{lis}</ul></div>"
        return section("Immediate (0-7 Days)", recs_immediate) + section("Short Term (7-30 Days)", recs_short) + section("Long Term (30-90 Days)", recs_long)

    def build_compliance_badges(payment_scope: bool) -> str:
        labels = ["ISO 27001", "OWASP", "NIST SP 800-115", "UAE IAS"]
        if payment_scope:
            labels.append("PCI DSS")
        return "".join([f"<div class=\"badge\">{esc(label)}</div>" for label in labels])

    def build_compliance_alignment_block(payment_scope: bool, items, counts) -> str:
        signals = extract_finding_signals(items)
        evidence_totals = (
            f"Critical {counts['critical']}, High {counts['high']}, "
            f"Medium {counts['medium']}, Low/Info {counts['low'] + counts['info']}"
        )

        owasp_tags = []
        if signals["injection_positive"]:
            owasp_tags.append("A03:2021 Injection")
        elif signals["injection_negative"]:
            owasp_tags.append("A03:2021 Injection (no confirmed exploit in tested scope)")
        if signals["header_hardening"] or signals["transport_hardening"]:
            owasp_tags.append("A05:2021 Security Misconfiguration")
        if signals["endpoint_exposure"]:
            owasp_tags.append("A01:2021 Broken Access Control validation required for discovered routes")
        if signals["sensitive_file_exposure"]:
            owasp_tags.append("A05:2021 Security Misconfiguration (artifact exposure)")
        owasp_text = (
            "Mapped findings: " + "; ".join(owasp_tags) + "."
            if owasp_tags
            else "No OWASP Top 10 category exceeded baseline risk in this scan window."
        )

        iso_points = []
        if counts["critical"] + counts["high"] + counts["medium"] > 0:
            iso_points.append("Confirmed findings require tracked risk treatment and accountable remediation ownership.")
        if signals["header_hardening"] or signals["transport_hardening"]:
            iso_points.append("Web hardening baseline controls require improvement for externally exposed services.")
        if signals["runtime_gap"]:
            iso_points.append("Assessment limitations must be documented with targeted retest evidence.")
        if not iso_points:
            iso_points.append("Current observations support baseline control effectiveness; continue periodic assurance testing.")

        tested_with = ", ".join(tools_used) if tools_used else "in-scope platform scanners"
        nist_text = (
            f"Testing evidence was gathered using {tested_with}; outputs support reproducible validation and retesting workflow. "
            f"Observed severity distribution: {evidence_totals}."
        )
        if signals["endpoint_exposure"]:
            nist_text += " Discovery results should be fed into next-cycle scope expansion."
        if signals["runtime_gap"]:
            nist_text += " Runtime constraints indicate a focused follow-up test is required."

        uae_text = (
            "Findings and remediation tracking support UAE IAS expectations for periodic vulnerability assessment, "
            "risk-based remediation, and documented closure evidence."
        )
        if signals["header_hardening"]:
            uae_text += " Header hardening gaps should be prioritized as internet-facing control weaknesses."

        rows = [
            ("ISO 27001", " ".join(iso_points)),
            ("OWASP Testing Guide / ASVS", owasp_text),
            ("NIST SP 800-115", nist_text),
            ("UAE IAS", uae_text),
        ]
        if payment_scope:
            pci_text = (
                "For payment-scope components, map assessment evidence to PCI DSS v4.0.1 Requirement 11.4 "
                "(penetration testing methodology, segmentation validation, and post-change retesting)."
            )
            if signals["injection_positive"] or signals["header_hardening"] or signals["endpoint_exposure"]:
                pci_text += " Current findings should feed directly into PCI remediation and retest evidence packs."
            rows.append(("PCI DSS v4.0.1", pci_text))

        lis = "".join([f"<li><strong>{esc(name)}:</strong> {esc(desc)}</li>" for name, desc in rows])
        return f"<ul>{lis}</ul>"

    def build_methodology_standards_block(payment_scope: bool) -> str:
        rows = [
            (
                "ISO/IEC 27001",
                "ISMS risk treatment and governance alignment for remediation ownership."
            ),
            (
                "OWASP Testing Guide v4.2 / ASVS",
                "Web application and API security testing methodology and control verification references."
            ),
            (
                "NIST SP 800-115",
                "Technical guide for planning, executing, and reporting information security assessments."
            ),
            (
                "UAE IAS",
                "UAE Information Assurance baseline for local regulatory and governance alignment."
            ),
        ]
        if payment_scope:
            rows.append(
                (
                    "PCI DSS v4.0.1",
                    "Payment Card Industry requirements for penetration testing, segmentation checks, and retesting."
                )
            )
        rows.append(
            (
                "CVSS v4.0",
                "Common Vulnerability Scoring System used to normalize severity and remediation prioritization."
            )
        )
        lis = "".join([f"<li><strong>{esc(name)}</strong> - {esc(desc)}</li>" for name, desc in rows])
        return f"<ul>{lis}</ul>"

    def build_business_impact_block(items, counts):
        signals = extract_finding_signals(items)
        themes = []
        if signals["injection_positive"]:
            themes.append("Potential data confidentiality/integrity impact if injection paths emerge in adjacent or untested inputs.")
        elif signals["injection_negative"]:
            themes.append("No confirmed SQL injection in tested scope; residual risk remains tied to untested input paths and future code changes.")
        if signals["header_hardening"] or signals["transport_hardening"]:
            themes.append("Browser-layer protection gaps increase exploitation probability for client-side attack scenarios.")
        if signals["sensitive_file_exposure"]:
            themes.append("Exposed artifacts may disclose sensitive internal material and accelerate attacker reconnaissance.")
        if signals["endpoint_exposure"]:
            themes.append("Attack surface expansion indicates additional routes that require control validation and ownership mapping.")
        if signals["runtime_gap"]:
            themes.append("Assessment completeness risk: scanner runtime constraints can reduce visibility and require targeted retesting.")
        if not themes:
            themes.append("No material business-impact themes were observed beyond baseline security hygiene improvements.")

        stats = (
            f"Critical {counts['critical']} | High {counts['high']} | "
            f"Medium {counts['medium']} | Low/Info {counts['low'] + counts['info']}"
        )
        lis = "".join([f"<li>{esc(theme)}</li>" for theme in themes[:5]])
        return (
            "<div class=\"summary-box\">"
            "<h3>Business Impact Themes</h3>"
            f"<ul>{lis}</ul>"
            f"<p><strong>Finding Distribution:</strong> {esc(stats)}</p>"
            "</div>"
        )

    def build_executive_context_block():
        scope_items = [
            f"Assessment window: {assessment_period}",
            f"In-scope target: {target}",
            f"Executed tooling: {', '.join(tools_used) if tools_used else 'Not recorded'}",
            f"Report reference: {meta.get('report_id', f'ASH-PENTEST-{scan_id}')}",
        ]
        lis = "".join([f"<li>{esc(item)}</li>" for item in scope_items])
        return (
            "<div class=\"summary-box\">"
            "<h3>Assessment Context</h3>"
            f"<ul>{lis}</ul>"
            "</div>"
        )

    def build_toc_block(report_mode: str) -> str:
        if report_mode == "executive":
            sections = [
                "EXECUTIVE SUMMARY",
                "OVERALL RISK ASSESSMENT",
                "HIGH-LEVEL FINDINGS OVERVIEW",
                "BUSINESS IMPACT SUMMARY",
                "RECOMMENDATIONS",
                "COMPLIANCE ALIGNMENT",
                "CONCLUSION",
                "APPENDIX",
            ]
        else:
            sections = [
                "EXECUTIVE SUMMARY",
                "ASSESSMENT METHODOLOGY",
                "SCOPE & LIMITATIONS",
                "VULNERABILITY SUMMARY",
                "DETAILED FINDINGS",
                "REMEDIATION ROADMAP",
                "TECHNICAL APPENDICES",
            ]
        rows = []
        for idx, title in enumerate(sections, 1):
            rows.append(
                f"""
                <div class="toc-item">
                    <span class="toc-number">{idx}</span>
                    <span class="toc-title">{title}</span>
                    <span class="toc-dots"></span>
                    <span class="toc-page-number">{idx + 2}</span>
                </div>
                """.strip()
            )
        return "\n".join(rows)

    counts = build_counts(findings)
    overall_score = calculate_overall_score(findings, counts)
    overall_level, overall_class = risk_level_from_score(overall_score, counts)
    chart_counts = [
        counts.get("critical", 0),
        counts.get("high", 0),
        counts.get("medium", 0),
        counts.get("low", 0) + counts.get("info", 0),
    ]
    max_count = max(chart_counts) if chart_counts else 0
    tools_used = [tool_display_name(tool_id) for tool_id in selected_tools] or [tool_display_name(normalize_tool_id(tool))]
    created_at = meta.get("created_at")
    completed_at = meta.get("completed_at") or created_at
    created_display = format_abu_dhabi(created_at) or created_at or datetime.now().strftime("%Y-%m-%d")
    completed_display = format_abu_dhabi(completed_at) or completed_at or created_display
    try:
        base_dt = parse_ts(created_at) or datetime.now()
        retest_default = add_months(base_dt, 6).strftime("%B %d, %Y")
        next_review = (base_dt + timedelta(days=90)).strftime("%B %d, %Y")
    except Exception:
        retest_default = "TBD"
        next_review = "TBD"
    assessment_period = format_assessment_period(created_at, completed_at) or (
        created_display if created_display == completed_display else f"{created_display} - {completed_display}"
    )
    report_date = format_report_datetime(created_at) or created_display
    payment_scope_enabled = detect_payment_scope(findings)
    compliance_profile_name = (
        "Payment Profile (PCI DSS in scope)"
        if payment_scope_enabled
        else "Core Portfolio Profile (Non-payment assets)"
    )
    logo_src = resolve_report_logo_src()

    def build_risk_summary_paragraph(items, counts, level: str, score: float) -> str:
        if not items:
            return "Summary: No material findings were identified in current scope."

        ai_text = str(meta.get("ai_executive_summary") or "").strip()
        if not ai_text:
            ai_text = ai_summarize_findings("overall assessment", target, items, audience="executive")
        insight_lines = []
        for raw_line in ai_text.splitlines():
            line = raw_line.strip(" -*\t")
            if not line:
                continue
            line = re.sub(r"^(critical|high|medium|low|informational|info)\s*:\s*", "", line, flags=re.IGNORECASE)
            line = re.sub(r"\s+-\s+", ": ", line, count=1)
            lowered = line.lower()
            if lowered.startswith("risk profile for"):
                continue
            if lowered.startswith("priority action"):
                continue
            insight_lines.append(line.rstrip("."))
            if len(insight_lines) >= 2:
                break

        if not insight_lines:
            signals = extract_finding_signals(items)
            fallback = []
            if signals["header_hardening"] or signals["transport_hardening"]:
                fallback.append("Header hardening gaps remain on externally exposed web responses")
            if signals["endpoint_exposure"]:
                fallback.append("endpoint discovery indicates additional routes requiring control validation")
            if signals["injection_positive"]:
                fallback.append("injection risk requires immediate remediation and retesting")
            elif signals["injection_negative"]:
                fallback.append("no SQL injection was confirmed in the tested parameters")
            if signals["runtime_gap"]:
                fallback.append("scan runtime constraints indicate targeted follow-up validation is needed")
            insight_lines = fallback[:2] if fallback else ["findings indicate targeted hardening and retesting priorities"]

        insight_text = ". ".join(insight_lines)
        if insight_text and not insight_text.endswith("."):
            insight_text += "."

        return (
            f"Summary: {insight_text} "
            f"Overall rating: {level.title()} (CVSS v4.0 reference {score:.1f}/10; "
            f"Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, "
            f"Low/Info {counts['low'] + counts['info']})."
        )

    mapping = {
        "COMPANY_NAME": PRODUCT_COMPANY_NAME,
        "SECURITY_DIVISION": PRODUCT_SECURITY_DIVISION,
        "PRODUCT_BRAND_NAME": PRODUCT_BRAND_NAME,
        "TARGET_SYSTEM": meta.get("target_system", "Web Application"),
        "TARGET_URL": target,
        "TARGET_IP": meta.get("target_ip", "N/A"),
        "ASSESSMENT_PERIOD": assessment_period,
        "REPORT_DATE": report_date,
        "TOOLS_USED": ", ".join(tools_used),
        "DURATION_TEXT": meta.get("duration_text", "Automated scan"),
        "ASSESSMENT_TYPE": meta.get("assessment_type", "Automated security assessment"),
        "CRITICAL_COUNT": counts["critical"],
        "HIGH_COUNT": counts["high"],
        "MEDIUM_COUNT": counts["medium"],
        "LOW_COUNT": counts["low"] + counts["info"],
        "TOTAL_FINDINGS": sum(counts.values()),
        "OVERALL_RISK_LEVEL": overall_level,
        "OVERALL_RISK_CLASS": overall_class,
        "RISK_SCORE": f"{overall_score:.1f}/10",
        "RISK_METER_PERCENT": f"{int(round(overall_score * 10, 0))}%",
        "CRITICAL_BAR_WIDTH": bar_width(counts["critical"], max_count),
        "HIGH_BAR_WIDTH": bar_width(counts["high"], max_count),
        "MEDIUM_BAR_WIDTH": bar_width(counts["medium"], max_count),
        "LOW_BAR_WIDTH": bar_width(counts["low"] + counts["info"], max_count),
        "RISK_SUMMARY_PARAGRAPH": build_risk_summary_paragraph(findings, counts, overall_level, overall_score),
        "COMPLIANCE_BADGES": build_compliance_badges(payment_scope_enabled),
        "COMPLIANCE_PROFILE_INTRO": (
            f"This report uses the {PRODUCT_COMPANY_NAME} compliance baseline: {compliance_profile_name}. "
            "PCI DSS controls are included only when payment data environments are in scope."
        ),
        "COMPLIANCE_ALIGNMENT_BLOCK": build_compliance_alignment_block(payment_scope_enabled, findings, counts),
        "METHODOLOGY_STANDARDS_BLOCK": build_methodology_standards_block(payment_scope_enabled),
        "RECOMMENDATIONS_BLOCK": build_recommendations_block(findings),
        "KEY_FINDINGS_BLOCK": build_key_findings(findings),
        "BUSINESS_IMPACT_BLOCK": build_business_impact_block(findings, counts),
        "EXECUTIVE_CONTEXT_BLOCK": build_executive_context_block(),
        "COVERAGE_ROWS": build_coverage_rows(findings),
        "TOOLS_ROWS": build_tools_rows(),
        "TOOLS_APPENDIX_ROWS": build_tools_appendix_rows(),
        "GLOSSARY_BLOCK": build_glossary_block(findings),
        "TESTING_PHASE_ROWS": build_testing_phase_rows(),
        "DETAILED_FINDINGS_BLOCK": build_detailed_findings(findings),
        "REMEDIATION_BLOCK": build_remediation_block(findings, counts),
        "REPORT_ID": meta.get("report_id", f"ASH-PENTEST-{scan_id}"),
        "RETEST_DATE": meta.get("retest_date") or retest_default,
        "EXPIRY_DATE": meta.get("expiry_date", "TBD"),
        "NEXT_REVIEW_DATE": meta.get("next_review_date", next_review),
        "LOGO_SRC": logo_src
    }

    def render_exec():
        html = load_template("exerpt.html")
        html = inline_css(html)
        mapping_exec = dict(mapping)
        mapping_exec["TOC_BLOCK"] = build_toc_block("executive")
        html = apply_placeholders(html, mapping_exec)
        html = html.replace("Wapiti", "Nikto").replace("Nmap", "Katana")
        return html

    def render_tech():
        html = load_template("techrpt.html")
        html = inline_css(html)
        mapping_tech = dict(mapping)
        mapping_tech["TOC_BLOCK"] = build_toc_block("technical")
        html = apply_placeholders(html, mapping_tech)
        html = html.replace("Wapiti", "Nikto").replace("Nmap", "Katana")
        return html

    if mode == "executive":
        return render_exec()
    if mode == "technical":
        return render_tech()

    exec_html = render_exec()
    tech_html = render_tech()
    def extract_body(content: str) -> str:
        start = content.find("<body")
        if start == -1:
            return content
        start = content.find(">", start) + 1
        end = content.rfind("</body>")
        return content[start:end].strip()

    def extract_print_controls(body: str) -> str:
        match = re.search(r'(<div class="print-controls no-print">.*?</div>)', body, flags=re.S)
        return match.group(1) if match else ""

    def remove_print_controls(body: str) -> str:
        return re.sub(r'<div class="print-controls no-print">.*?</div>', "", body, count=1, flags=re.S).strip()

    def remove_inline_scripts(body: str) -> str:
        return re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.S | re.I).strip()

    exec_body = extract_body(exec_html)
    tech_body = extract_body(tech_html)

    primary_controls = extract_print_controls(exec_body)
    exec_body = remove_print_controls(exec_body)
    tech_body = remove_print_controls(tech_body)

    # In combined mode, keep the technical narrative sections and avoid duplicate cover/TOC blocks.
    tech_start_marker = "<!-- Executive Summary -->"
    marker_index = tech_body.find(tech_start_marker)
    if marker_index != -1:
        tech_body = tech_body[marker_index:]
    tech_body = remove_inline_scripts(tech_body)

    combined_divider = (
        '<div class="report-page page-break combined-divider">'
        '<div class="page-header"><h1 class="section-number">T</h1>'
        '<h1 class="section-title">TECHNICAL ASSESSMENT ADDENDUM</h1></div>'
        '<div class="content-section"><p class="section-intro">'
        'The following pages provide technical evidence, detailed findings, and remediation verification guidance.'
        "</p></div></div>"
    )

    technical_block = f'<div class="combined-technical-section technical-report">{tech_body}</div>'
    combined_body = "\n".join(
        [part for part in [primary_controls, exec_body, combined_divider, technical_block] if part]
    )
    head_start = exec_html.find("<head>")
    head_end = exec_html.find("</head>")
    head = exec_html[head_start:head_end + len("</head>")] if head_start != -1 and head_end != -1 else ""
    combined = (
        "<!DOCTYPE html><html lang=\"en\">"
        f"{head}<body class=\"combined-report executive-report\">"
        f"{combined_body}</body></html>"
    )
    return combined

# ========== API ENDPOINTS ==========
@app.on_event("startup")
def startup():
    init_database()
    reconciled = reconcile_orphaned_scans(max_age_minutes=int(os.getenv("SCAN_STALE_MINUTES", "30")))
    print(f"✅ {PRODUCT_BRAND_NAME} v4.0 READY!")
    print("📡 http://localhost:8000")
    print(f"🤖 AI Analysis Engine: {'Online' if LLAMA_MODEL.exists() else 'Unavailable'}")
    print("🤖 AI Reports: Enabled")
    print("📊 Professional Reporting: Enabled")
    if reconciled:
        print(f"🧹 Reconciled stale scans at startup: {reconciled}")

# Serve frontend
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_frontend():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": f"{PRODUCT_BRAND_NAME} v4.0"}

@app.get("/api/health")
def health(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Enhanced health check with AI status"""
    user = verify_user(credentials)
    log_audit_event(request, "health_check", "success", user)
    try:
        # Check AI model
        ai_model = LLAMA_MODEL.name if LLAMA_MODEL.exists() else None
        ai_status = "Not installed"
        if LLAMA_MODEL.exists():
            ai_status = "Ready"
        
        # Check llama.cpp
        llama_path = BASE_DIR / "llama.cpp" / "build" / "bin" / "llama-cli"
        llama_available = llama_path.exists()
        
        # Check tools
        tools_status = {
            "nuclei": (TOOLS_DIR / "nuclei").exists(),
            "nikto": (TOOLS_DIR / "nikto/program/nikto.pl").exists(),
            "sqlmap": (TOOLS_DIR / "sqlmap/sqlmap.py").exists(),
            "katana": (TOOLS_DIR / "katana").exists()
        }
        cpu_usage = round(get_cpu_usage_percent(), 1)
        memory_usage = round(get_memory_usage_percent(), 1)
        
        return {
            "status": "online",
            "platform": "NVIDIA Jetson Orin Nano",
            "system": {
                "cpu_percent": cpu_usage,
                "memory_percent": memory_usage
            },
            "ai": {
                "model": ai_model,
                "status": ai_status,
                "llama_available": llama_available
            },
            "tools": tools_status,
            "reports_available": True,
            "time": datetime.now().isoformat()
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/auth/login")
def auth_login(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Primary login endpoint used by frontend to capture audit telemetry and user profile context."""
    username = (credentials.username or "").strip()
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    db.close()

    if not user:
        log_audit_event(
            request,
            "auth_login",
            "failure",
            severity="warning",
            details={"reason": "invalid_username"},
            username_override=username or "unknown",
        )
        time.sleep(0.2)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_dict = dict(user)
    if not user_dict.get("is_active"):
        log_audit_event(
            request,
            "auth_login",
            "failure",
            user_dict,
            severity="warning",
            details={"reason": "user_disabled"},
        )
        raise HTTPException(status_code=403, detail="User account is disabled")

    if not bcrypt.checkpw(credentials.password.encode(), str(user_dict["password"]).encode()):
        log_audit_event(
            request,
            "auth_login",
            "failure",
            user_dict,
            severity="warning",
            details={"reason": "invalid_password"},
        )
        time.sleep(0.2)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?", (user_dict["id"],))
    db.commit()
    db.close()

    log_audit_event(
        request,
        "auth_login",
        "success",
        user_dict,
        details={"must_change_password": bool(user_dict.get("must_change_password"))},
    )
    return {
        "status": "success",
        "user": {
            "id": user_dict["id"],
            "username": user_dict["username"],
            "role": user_dict.get("role", "user"),
            "is_admin": is_admin_user(user_dict),
            "must_change_password": bool(user_dict.get("must_change_password")),
        },
    }


@app.get("/api/auth/status")
def auth_status(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    log_audit_event(request, "auth_status", "success", user)
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user.get("role", "user"),
        "must_change_password": bool(user.get("must_change_password")),
        "is_admin": is_admin_user(user),
    }


@app.get("/api/news/cyber")
def cyber_news(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Latest cyber-attack oriented one-line headlines for dashboard ticker."""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    log_audit_event(request, "cyber_news", "success", user)
    items = get_cached_cyber_news(limit=8)
    return {
        "status": "ok",
        "items": items,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


@app.post("/api/auth/change-password")
def change_password(
    request: Request,
    username: str = Form(...),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Allow password change directly from login console with current password verification."""
    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if not current_password:
        raise HTTPException(status_code=400, detail="Current password is required.")
    if not new_password:
        raise HTTPException(status_code=400, detail="New password is required.")
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match.")
    if current_password == new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password.")

    policy_error = validate_new_password(new_password)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        db.close()
        log_audit_event(
            request,
            "password_change",
            "failure",
            severity="warning",
            details={"username": username, "reason": "invalid_username"},
            username_override=username,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(current_password.encode(), user["password"].encode()):
        db.close()
        log_audit_event(
            request,
            "password_change",
            "failure",
            {"id": user["id"], "username": username},
            severity="warning",
            details={"reason": "invalid_current_password"},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "UPDATE users SET password = ?, must_change_password = 0, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_hash, user["id"]),
    )
    db.commit()
    db.close()
    log_audit_event(
        request,
        "password_change",
        "success",
        {"id": user["id"], "username": username},
        details={"must_change_password_cleared": True},
    )
    return {"status": "success", "message": "Password updated successfully. Please login with your new password."}


def build_audit_report_html(events: list[dict], generated_by: str) -> str:
    """Generate a professional audit activity report for governance and compliance reviews."""
    total = len(events)
    failed = sum(1 for e in events if str(e.get("event_status", "")).lower() != "success")
    login_attempts = sum(1 for e in events if str(e.get("event_type", "")).startswith("auth_login"))
    scan_actions = sum(1 for e in events if "scan" in str(e.get("event_type", "")))
    report_actions = sum(1 for e in events if "report" in str(e.get("event_type", "")))
    stepup_denied = sum(1 for e in events if str(e.get("event_type", "")) == "stepup_denied")

    rows = []
    for item in events[:500]:
        rows.append(
            "<tr>"
            f"<td>{esc_html(format_abu_dhabi(item.get('created_at')) or item.get('created_at') or '')}</td>"
            f"<td>{esc_html(item.get('username') or 'unknown')}</td>"
            f"<td>{esc_html(item.get('event_type') or '')}</td>"
            f"<td>{esc_html(item.get('event_status') or '')}</td>"
            f"<td>{esc_html(item.get('source_ip') or '')}</td>"
            f"<td>{esc_html(item.get('details_json') or '')[:220]}</td>"
            "</tr>"
        )

    standards_rows = [
        ("ISO/IEC 27001:2022", "A.5, A.8, A.12", "Identity governance, logging, monitoring, and access control accountability."),
        ("NIST SP 800-53 Rev.5", "AU-2, AU-3, AU-6, AC-2, IA-2", "Audit event capture, review, correlation, account lifecycle, and authentication controls."),
        ("OWASP ASVS v4", "V2, V3, V7", "Authentication hardening, session/access controls, and error/logging security posture."),
        ("UAE IAS / NESA", "Information Security Monitoring & IAM control families", "Operational monitoring, privileged access control, and traceability for governance."),
    ]
    standards_html = "".join(
        f"<tr><td>{esc_html(name)}</td><td>{esc_html(control)}</td><td>{esc_html(desc)}</td></tr>"
        for name, control, desc in standards_rows
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Platform Audit Activity Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #162127; }}
    h1 {{ margin: 0 0 8px; color: #0f5132; }}
    h2 {{ margin-top: 28px; color: #1b4332; }}
    .meta, .cards {{ margin: 14px 0; }}
    .cards {{ display: grid; grid-template-columns: repeat(5, minmax(140px, 1fr)); gap: 10px; }}
    .card {{ border: 1px solid #cfe7d8; border-radius: 8px; padding: 10px; background: #f6fbf8; }}
    .card b {{ font-size: 18px; display: block; color: #0b3d2a; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; table-layout: fixed; }}
    th, td {{ border: 1px solid #d7e2dc; padding: 8px; vertical-align: top; font-size: 12px; word-break: break-word; }}
    th {{ background: #184e37; color: #fff; }}
    .note {{ background: #f3f8f5; border-left: 4px solid #2d6a4f; padding: 10px 12px; margin-top: 10px; }}
  </style>
</head>
<body>
  <h1>Security Platform Application Audit Activity Report</h1>
  <div class="meta">
    <div><b>Generated:</b> {esc_html(format_abu_dhabi(datetime.utcnow()) or datetime.utcnow().isoformat())}</div>
    <div><b>Generated By:</b> {esc_html(generated_by)}</div>
    <div><b>Coverage:</b> Application login events, user activity, step-up verifications, scan/report operations</div>
  </div>
  <div class="cards">
    <div class="card"><span>Total Events</span><b>{total}</b></div>
    <div class="card"><span>Failed Events</span><b>{failed}</b></div>
    <div class="card"><span>Login Attempts</span><b>{login_attempts}</b></div>
    <div class="card"><span>Scan Actions</span><b>{scan_actions}</b></div>
    <div class="card"><span>Report Actions</span><b>{report_actions}</b></div>
  </div>
  <div class="note">
    Step-up denied attempts observed: <b>{stepup_denied}</b>. Each denied event should be reviewed for misuse, account sharing, or brute-force behavior.
  </div>

  <h2>Compliance Alignment</h2>
  <table>
    <thead><tr><th>Standard</th><th>Control Focus</th><th>Alignment Summary</th></tr></thead>
    <tbody>{standards_html}</tbody>
  </table>

  <h2>Detailed Activity Log</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 17%">Time (Asia/Dubai)</th>
        <th style="width: 11%">User</th>
        <th style="width: 16%">Event Type</th>
        <th style="width: 9%">Status</th>
        <th style="width: 12%">Source IP</th>
        <th style="width: 35%">Details</th>
      </tr>
    </thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="6">No audit events captured.</td></tr>'}</tbody>
  </table>
</body>
</html>"""


def load_company_onboarding_profile(db: sqlite3.Connection) -> dict:
    cur = db.cursor()
    cur.execute(
        """
        SELECT
            company_legal_name,
            brand_display_name,
            platform_title,
            primary_domain,
            additional_domains,
            primary_contact_name,
            primary_contact_email,
            primary_contact_phone,
            industry_sector,
            compliance_scope,
            logo_dark_url,
            logo_light_url,
            mark_dark_url,
            mark_light_url,
            avatar_url,
            onboarding_notes,
            updated_by,
            updated_at
        FROM company_onboarding
        WHERE id = 1
        """
    )
    row = cur.fetchone()
    profile = normalize_company_onboarding_profile(dict(row) if row else None)
    profile["updated_by"] = str((dict(row) if row else {}).get("updated_by") or "").strip()
    profile["updated_at"] = str((dict(row) if row else {}).get("updated_at") or "").strip()
    return profile


@app.get("/api/admin/company-onboarding")
def admin_get_company_onboarding(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db = get_db()
    profile = load_company_onboarding_profile(db)
    db.close()

    log_audit_event(request, "admin_company_onboarding_view", "success", user)
    return {"status": "success", "profile": profile}


@app.put("/api/admin/company-onboarding")
def admin_update_company_onboarding(
    request: Request,
    payload: dict = Body(...),
    credentials: HTTPBasicCredentials = Depends(security),
):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload format")

    db = get_db()
    cur = db.cursor()
    current = load_company_onboarding_profile(db)

    updates = {}
    for key in COMPANY_ONBOARDING_FIELDS:
        if key not in payload:
            continue
        raw = payload.get(key, "")
        text = str(raw or "").strip()
        if len(text) > 4000:
            db.close()
            raise HTTPException(status_code=400, detail=f"Field '{key}' exceeds maximum length")
        updates[key] = text

    email = updates.get("primary_contact_email", current.get("primary_contact_email", ""))
    if email and (not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)):
        db.close()
        raise HTTPException(status_code=400, detail="Invalid primary contact email format")

    domain = updates.get("primary_domain", current.get("primary_domain", ""))
    if domain and re.search(r"\s", domain):
        db.close()
        raise HTTPException(status_code=400, detail="Primary domain cannot contain spaces")

    merged = {**normalize_company_onboarding_profile(current), **updates}
    cur.execute("SELECT id FROM company_onboarding WHERE id = 1")
    exists = cur.fetchone() is not None
    if not exists:
        defaults = default_company_onboarding_profile()
        cur.execute(
            """
            INSERT INTO company_onboarding (
                id,
                company_legal_name,
                brand_display_name,
                platform_title,
                primary_domain,
                additional_domains,
                primary_contact_name,
                primary_contact_email,
                primary_contact_phone,
                industry_sector,
                compliance_scope,
                logo_dark_url,
                logo_light_url,
                mark_dark_url,
                mark_light_url,
                avatar_url,
                onboarding_notes,
                updated_by,
                updated_at
            ) VALUES (
                1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
            )
            """,
            (
                defaults["company_legal_name"],
                defaults["brand_display_name"],
                defaults["platform_title"],
                defaults["primary_domain"],
                defaults["additional_domains"],
                defaults["primary_contact_name"],
                defaults["primary_contact_email"],
                defaults["primary_contact_phone"],
                defaults["industry_sector"],
                defaults["compliance_scope"],
                defaults["logo_dark_url"],
                defaults["logo_light_url"],
                defaults["mark_dark_url"],
                defaults["mark_light_url"],
                defaults["avatar_url"],
                defaults["onboarding_notes"],
                user.get("username"),
            ),
        )

    cur.execute(
        """
        UPDATE company_onboarding
        SET
            company_legal_name = ?,
            brand_display_name = ?,
            platform_title = ?,
            primary_domain = ?,
            additional_domains = ?,
            primary_contact_name = ?,
            primary_contact_email = ?,
            primary_contact_phone = ?,
            industry_sector = ?,
            compliance_scope = ?,
            logo_dark_url = ?,
            logo_light_url = ?,
            mark_dark_url = ?,
            mark_light_url = ?,
            avatar_url = ?,
            onboarding_notes = ?,
            updated_by = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        """,
        (
            merged["company_legal_name"],
            merged["brand_display_name"],
            merged["platform_title"],
            merged["primary_domain"],
            merged["additional_domains"],
            merged["primary_contact_name"],
            merged["primary_contact_email"],
            merged["primary_contact_phone"],
            merged["industry_sector"],
            merged["compliance_scope"],
            merged["logo_dark_url"],
            merged["logo_light_url"],
            merged["mark_dark_url"],
            merged["mark_light_url"],
            merged["avatar_url"],
            merged["onboarding_notes"],
            user.get("username"),
        ),
    )
    db.commit()
    refreshed = load_company_onboarding_profile(db)
    db.close()

    log_audit_event(
        request,
        "admin_company_onboarding_update",
        "success",
        user,
        details={"updated_fields": sorted(list(updates.keys()))},
    )
    return {"status": "success", "message": "Company onboarding profile updated.", "profile": refreshed}


@app.get("/api/admin/users")
def admin_list_users(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT id, username, role, must_change_password, is_active, created_at, last_login_at, password_changed_at
        FROM users
        ORDER BY lower(username)
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    log_audit_event(request, "admin_list_users", "success", user, details={"count": len(rows)})
    return rows


@app.post("/api/admin/users")
def admin_create_user(
    request: Request,
    username: str = Form(...),
    temp_password: str = Form(""),
    role: str = Form("user"),
    credentials: HTTPBasicCredentials = Depends(security),
):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    username = (username or "").strip()
    role = (role or "user").strip().lower()
    if role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")
    if not username or not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        raise HTTPException(status_code=400, detail="Username must be 3-40 chars: letters, numbers, . _ -")

    temp_password = (temp_password or "").strip() or "ChangeMe@123"
    policy_error = validate_new_password(temp_password)
    if policy_error:
        raise HTTPException(status_code=400, detail=f"Temporary password does not meet policy: {policy_error}")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE lower(username)=lower(?)", (username,))
    if cur.fetchone():
        db.close()
        raise HTTPException(status_code=409, detail="User already exists")

    hashed = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt()).decode()
    must_change = 1
    cur.execute(
        """
        INSERT INTO users (username, password, role, must_change_password, is_active)
        VALUES (?, ?, ?, ?, 1)
        """,
        (username, hashed, role, must_change),
    )
    db.commit()
    db.close()

    log_audit_event(
        request,
        "admin_create_user",
        "success",
        user,
        details={"created_username": username, "role": role, "must_change_password": bool(must_change)},
    )
    return {
        "status": "success",
        "message": f"User '{username}' created successfully.",
        "username": username,
        "role": role,
        "temporary_password": temp_password,
        "must_change_password": bool(must_change),
    }


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(
    request: Request,
    user_id: int,
    credentials: HTTPBasicCredentials = Depends(security),
):
    actor = verify_user(credentials)
    if not is_admin_user(actor):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,))
    target_row = cur.fetchone()
    if not target_row:
        db.close()
        log_audit_event(
            request,
            "admin_delete_user",
            "failure",
            actor,
            severity="warning",
            details={"target_user_id": user_id, "reason": "user_not_found"},
        )
        raise HTTPException(status_code=404, detail="User not found")

    target = dict(target_row)
    target_username = str(target.get("username") or "")
    target_role = str(target.get("role") or "user").strip().lower()

    if int(target.get("id") or 0) == int(actor.get("id") or -1):
        db.close()
        log_audit_event(
            request,
            "admin_delete_user",
            "failure",
            actor,
            severity="warning",
            details={"target_user_id": user_id, "target_username": target_username, "reason": "self_delete_blocked"},
        )
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    if target_username.strip().lower() == "admin":
        db.close()
        log_audit_event(
            request,
            "admin_delete_user",
            "failure",
            actor,
            severity="warning",
            details={"target_user_id": user_id, "target_username": target_username, "reason": "protected_admin"},
        )
        raise HTTPException(status_code=400, detail="Built-in admin account cannot be deleted")

    if target_role == "admin":
        cur.execute("SELECT COUNT(*) AS count FROM users WHERE lower(role)='admin' AND is_active=1")
        active_admin_count = int((cur.fetchone() or {"count": 0})["count"] or 0)
        if active_admin_count <= 1:
            db.close()
            log_audit_event(
                request,
                "admin_delete_user",
                "failure",
                actor,
                severity="warning",
                details={"target_user_id": user_id, "target_username": target_username, "reason": "last_admin_blocked"},
            )
            raise HTTPException(status_code=400, detail="Cannot delete the last active admin account")

    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()

    log_audit_event(
        request,
        "admin_delete_user",
        "success",
        actor,
        details={"target_user_id": user_id, "target_username": target_username, "target_role": target_role},
    )
    return {
        "status": "success",
        "message": f"User '{target_username}' deleted successfully.",
        "deleted_user_id": int(user_id),
        "deleted_username": target_username,
    }


@app.get("/api/admin/audit/events")
def admin_audit_events(
    request: Request,
    limit: int = Query(500, ge=1, le=5000),
    credentials: HTTPBasicCredentials = Depends(security),
):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT id, user_id, username, event_type, event_status, severity, source_ip, user_agent, details_json, created_at
        FROM audit_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    log_audit_event(request, "admin_audit_events", "success", user, details={"limit": limit, "returned": len(rows)})
    return rows


@app.get("/api/admin/audit/report/html")
def admin_audit_report_html(
    request: Request,
    limit: int = Query(2000, ge=100, le=10000),
    credentials: HTTPBasicCredentials = Depends(security),
):
    user = verify_user(credentials)
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT id, user_id, username, event_type, event_status, severity, source_ip, user_agent, details_json, created_at
        FROM audit_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    html = build_audit_report_html(rows, generated_by=user["username"])
    log_audit_event(request, "admin_audit_report_generated", "success", user, details={"limit": limit, "events": len(rows)})
    return HTMLResponse(html)

@app.post("/api/scan")
async def start_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    target: str = Form(...),
    tool: str = Form(...),
    credentials: HTTPBasicCredentials = Depends(security)
):
    """Start a new scan"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "scan_start")
    
    # Validate tool
    valid_tools = SUPPORTED_TOOLS
    if tool not in valid_tools:
        log_audit_event(
            request,
            "scan_start",
            "failure",
            user,
            severity="warning",
            details={"target": target, "tool": tool, "reason": "invalid_tool"},
        )
        raise HTTPException(status_code=400, detail=f"Invalid tool. Choose from: {', '.join(valid_tools)}")

    target = clean_target((target or "").strip())
    if not is_valid_target(target):
        log_audit_event(
            request,
            "scan_start",
            "failure",
            user,
            severity="warning",
            details={"target": target, "tool": tool, "reason": "invalid_target"},
        )
        raise HTTPException(status_code=400, detail="Invalid target. Provide a domain or full URL.")
    if is_excluded_target(target):
        log_audit_event(
            request,
            "scan_start",
            "failure",
            user,
            severity="warning",
            details={"target": target, "tool": tool, "reason": "excluded_target"},
        )
        raise HTTPException(status_code=400, detail="This target is blocked (test placeholder).")
    
    # Create scan
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'pending')",
        (user["id"], target, tool)
    )
    scan_id = cur.lastrowid
    db.commit()
    db.close()
    
    # Start scan
    background_tasks.add_task(run_scan_async, scan_id, target, tool)
    log_audit_event(request, "scan_start", "success", user, details={"scan_id": scan_id, "target": target, "tool": tool})

    
    return JSONResponse({
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scanning {target} with {tool}",
        "estimated_time": "30-60 seconds",
        "auto_report": True
    })

@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Stop a running scan."""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    scan = get_scan_for_user(scan_id, user["id"])
    if not scan:
        log_audit_event(request, "scan_stop", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "scan_not_found"})
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] == "pending":
        update_scan_db(scan_id, "failed", {"error": "Scan stopped before execution by user request", "success": False})
        log_audit_event(request, "scan_stop", "success", user, details={"scan_id": scan_id, "status_before": "pending"})
        return {"message": f"Scan {scan_id} stopped."}
    if scan["status"] in ("completed", "failed"):
        log_audit_event(request, "scan_stop", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "already_finished"})
        raise HTTPException(status_code=404, detail="Scan is not running or already finished.")
    process = running_processes.get(scan_id)
    if not process:
        log_audit_event(request, "scan_stop", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "process_missing"})
        raise HTTPException(status_code=404, detail="Scan is not running or already finished.")
    try:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
        running_processes.pop(scan_id, None)
        update_scan_db(scan_id, "failed", {
            "error": "Scan stopped by user request",
            "success": False
        })
        log_audit_event(request, "scan_stop", "success", user, details={"scan_id": scan_id, "status_before": "running"})
        return {"message": f"Scan {scan_id} stopped."}
    except Exception as e:
        log_audit_event(request, "scan_stop", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": str(e)[:160]})
        raise HTTPException(status_code=500, detail=f"Could not stop scan: {e}")

@app.get("/api/scans")
def list_scans(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, target, tool, status, created_at, started_at, completed_at, results FROM scans WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    )
    scans = []
    for row in cur.fetchall():
        scan = dict(row)
        if is_excluded_target(scan.get("target")):
            continue
        scan["duration"] = compute_scan_duration_seconds(scan)
        if scan.get("results"):
            try:
                parsed = json.loads(scan["results"])
                if isinstance(parsed, dict) and parsed.get("progress"):
                    scan["progress"] = parsed["progress"]
            except Exception:
                pass
        scans.append(scan)
    
    db.close()
    log_audit_event(request, "scan_list", "success", user, details={"count": len(scans)})
    return JSONResponse(scans)

@app.get("/api/posture/summary")
def get_posture_summary(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Aggregate security posture + compliance alignment across targets for the dashboard."""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    data = compute_posture_summary(user["id"])
    log_audit_event(request, "posture_summary", "success", user, details={"targets": data.get("stats", {}).get("targets", 0)})
    return JSONResponse(data)

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM scans WHERE id=? AND user_id=?",
        (scan_id, user["id"])
    )
    scan = cur.fetchone()
    db.close()
    
    if not scan:
        log_audit_event(request, "scan_view", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "scan_not_found"})
        raise HTTPException(status_code=404, detail="Scan not found")
    
    log_audit_event(request, "scan_view", "success", user, details={"scan_id": scan_id})
    return JSONResponse(dict(scan))

@app.get("/api/scan/{scan_id}/logs")
def get_scan_logs(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "scan_logs", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "scan_not_found"})
        raise HTTPException(status_code=404, detail="Scan not found")
    
    log_file = LOG_DIR / f"scan_{scan_id}.log"
    if not log_file.exists():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT status, results FROM scans WHERE id=? AND user_id=?", (scan_id, user["id"]))
        row = cur.fetchone()
        db.close()
        if row and row["results"]:
            try:
                live = json.loads(row["results"])
                log_audit_event(request, "scan_logs", "success", user, details={"scan_id": scan_id, "source": "database"})
                return JSONResponse({
                    "status": row["status"],
                    "source": "database",
                    "log": live
                })
            except Exception:
                pass
        log_audit_event(request, "scan_logs", "success", user, details={"scan_id": scan_id, "source": "none"})
        return {"log": "No logs available"}
    
    try:
        log_data = json.loads(log_file.read_text())
        log_audit_event(request, "scan_logs", "success", user, details={"scan_id": scan_id, "source": "file_json"})
        return JSONResponse(log_data)
    except:
        log_audit_event(request, "scan_logs", "success", user, details={"scan_id": scan_id, "source": "file_text"})
        return {"log": log_file.read_text()}

@app.post("/api/scan/{scan_id}/report")
async def create_report(
    scan_id: int,
    request: Request,
    report_type: str = Query("executive", pattern="^(executive|technical|both)$"),
    force: bool = Query(False),
    credentials: HTTPBasicCredentials = Depends(security)
):
    """Generate professional reports"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_generate")
    owner_scan = get_scan_for_user(scan_id, user["id"])
    if not owner_scan:
        log_audit_event(request, "report_generate", "failure", user, severity="warning", details={"scan_id": scan_id, "report_type": report_type, "reason": "scan_not_found"})
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        # If all 4 tools exist for the same target, generate consolidated report for report_type=both
        if report_type == "both":
            row = owner_scan
            if row:
                target = row["target"]
                user_id = row["user_id"]
                # Check if all 4 tools completed/failed for this target
                valid_tools = SUPPORTED_TOOLS
                db = get_db()
                cur = db.cursor()
                cur.execute(
                    "SELECT id, tool, status FROM scans WHERE user_id=? AND target=? ORDER BY id DESC",
                    (user_id, target),
                )
                rows = cur.fetchall()
                db.close()
                tool_status: dict[str, str] = {}
                seen = set()
                for r in rows:
                    tool_id = str(r["tool"] or "").strip().lower()
                    if not tool_id or tool_id in seen:
                        continue
                    seen.add(tool_id)
                    tool_status[tool_id] = str(r["status"] or "").strip().lower()
                    if len(seen) >= len(valid_tools):
                        break
                if all(t in tool_status for t in [t.lower() for t in valid_tools]) and all(
                    tool_status[t.lower()] in ("completed", "failed") for t in valid_tools
                ):
                    if (not force) and target_report_files_ready(target):
                        links = build_target_report_links(target)
                        target_html = REPORTS_DIR / f"report_target_{target_report_ref(target)}.html"
                        log_audit_event(
                            request,
                            "report_generate",
                            "success",
                            user,
                            details={"scan_id": scan_id, "report_type": report_type, "mode": "consolidated_cached", "target": target},
                        )
                        return JSONResponse({
                            "scan_id": scan_id,
                            "type": "both",
                            "executive": "Cached consolidated executive report is ready.",
                            "technical": "Cached consolidated technical report is ready.",
                            "html_report": str(target_html),
                            "message": "Consolidated report ready (cached)",
                            "downloads": links
                        })
                    consolidated = await generate_consolidated_reports(user_id, target)
                    if not consolidated.get("error"):
                        links = build_target_report_links(target)
                        log_audit_event(
                            request,
                            "report_generate",
                            "success",
                            user,
                            details={"scan_id": scan_id, "report_type": report_type, "mode": "consolidated_generated", "target": target},
                        )
                        return JSONResponse({
                            "scan_id": scan_id,
                            "type": "both",
                            "executive": consolidated["executive"][:1000] + "...",
                            "technical": consolidated["technical"][:1000] + "...",
                            "html_report": consolidated["html_path"],
                            "message": "Consolidated report generated for target",
                            "downloads": links
                        })

        if (not force) and scan_report_files_ready(scan_id):
            if report_type == "executive":
                log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type, "mode": "cached"})
                return JSONResponse({
                    "scan_id": scan_id,
                    "type": "executive",
                    "report": owner_scan["report_executive"] or "",
                    "message": "Executive report ready (cached)",
                    "download": f"/api/report/{scan_id}/executive_html"
                })
            elif report_type == "technical":
                log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type, "mode": "cached"})
                return JSONResponse({
                    "scan_id": scan_id,
                    "type": "technical",
                    "report": owner_scan["report_technical"] or "",
                    "message": "Technical report ready (cached)",
                    "download": f"/api/report/{scan_id}/technical_html"
                })
            else:
                log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type, "mode": "cached"})
                return JSONResponse({
                    "scan_id": scan_id,
                    "type": "both",
                    "executive": (owner_scan["report_executive"] or "")[:1000] + "...",
                    "technical": (owner_scan["report_technical"] or "")[:1000] + "...",
                    "html_report": str(REPORTS_DIR / f"report_scan_{scan_id}.html"),
                    "message": "Both reports ready (cached)",
                    "downloads": {
                        "combined_html": f"/api/report/{scan_id}/html",
                        "executive_html": f"/api/report/{scan_id}/executive_html",
                        "technical_html": f"/api/report/{scan_id}/technical_html",
                        "combined_markdown": f"/api/report/{scan_id}/markdown",
                        "executive_text": f"/api/report/{scan_id}/executive",
                        "technical_text": f"/api/report/{scan_id}/technical"
                    }
                })

        reports = await generate_scan_reports(scan_id)
        if not reports or reports.get("error"):
            log_audit_event(
                request,
                "report_generate",
                "failure",
                user,
                severity="warning",
                details={"scan_id": scan_id, "report_type": report_type, "reason": reports.get("error", "unknown")},
            )
            raise HTTPException(status_code=404, detail=reports.get("error", "Report generation failed"))
        
        if report_type == "executive":
            log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type, "mode": "generated"})
            return JSONResponse({
                "scan_id": scan_id,
                "type": "executive",
                "report": reports.get("executive", ""),
                "message": "Executive report generated",
                "download": f"/api/report/{scan_id}/executive_html"
            })
        elif report_type == "technical":
            log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type, "mode": "generated"})
            return JSONResponse({
                "scan_id": scan_id,
                "type": "technical",
                "report": reports.get("technical", ""),
                "message": "Technical report generated",
                "download": f"/api/report/{scan_id}/technical_html"
            })
        else:
            response = JSONResponse({
                "scan_id": scan_id,
                "type": "both",
                "executive": reports.get("executive", "")[:1000] + "...",
                "technical": reports.get("technical", "")[:1000] + "...",
                "html_report": reports.get("html_path"),
                "message": "Both reports generated",
                "downloads": {
                    "combined_html": f"/api/report/{scan_id}/html",
                    "executive_html": f"/api/report/{scan_id}/executive_html",
                    "technical_html": f"/api/report/{scan_id}/technical_html",
                    "combined_markdown": f"/api/report/{scan_id}/markdown",
                    "executive_text": f"/api/report/{scan_id}/executive",
                    "technical_text": f"/api/report/{scan_id}/technical"
                }
            })
            log_audit_event(request, "report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type})
            return response
            
    except HTTPException:
        raise
    except Exception as e:
        log_audit_event(request, "report_generate", "failure", user, severity="warning", details={"scan_id": scan_id, "report_type": report_type, "reason": str(e)[:180]})
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/api/report/{scan_id}/html")
def get_html_report(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get HTML report"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Report not found")
    
    ensure_scan_report_file(scan_id, "combined")
    report_file = REPORTS_DIR / f"report_scan_{scan_id}.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "html", "source": "file"})
        return HTMLResponse(report_file.read_text())
    
    # Generate on the fly
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT report_html FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    
    if row and row["report_html"]:
        log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "html", "source": "database"})
        return HTMLResponse(row["report_html"])
    
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/api/report/{scan_id}/executive_html")
def get_executive_html_report(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get Executive HTML report"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "executive_html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Executive report not found")
    ensure_scan_report_file(scan_id, "executive")
    report_file = REPORTS_DIR / f"report_scan_{scan_id}_executive.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "executive_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "executive_html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Executive report not found")

@app.get("/api/report/{scan_id}/technical_html")
def get_technical_html_report(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get Technical HTML report"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "technical_html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Technical report not found")
    ensure_scan_report_file(scan_id, "technical")
    report_file = REPORTS_DIR / f"report_scan_{scan_id}_technical.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "technical_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "technical_html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Technical report not found")

@app.get("/api/report/target/{target:path}/html")
def get_target_combined_html(target: str, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    target_ref = target_report_ref(target)
    if not user_owns_target_ref(user["id"], target_ref):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Target report not found")
    ensure_target_report_file(user["id"], target_ref, "combined")
    report_file = REPORTS_DIR / f"report_target_{target_ref}.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"target_ref": target_ref, "format": "target_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Target report not found")

@app.get("/api/report/target/{target:path}/executive_html")
def get_target_executive_html(target: str, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    target_ref = target_report_ref(target)
    if not user_owns_target_ref(user["id"], target_ref):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_executive_html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Target executive report not found")
    ensure_target_report_file(user["id"], target_ref, "executive")
    report_file = REPORTS_DIR / f"report_target_{target_ref}_executive.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"target_ref": target_ref, "format": "target_executive_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_executive_html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Target executive report not found")

@app.get("/api/report/target/{target:path}/technical_html")
def get_target_technical_html(target: str, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    target_ref = target_report_ref(target)
    if not user_owns_target_ref(user["id"], target_ref):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_technical_html", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Target technical report not found")
    ensure_target_report_file(user["id"], target_ref, "technical")
    report_file = REPORTS_DIR / f"report_target_{target_ref}_technical.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"target_ref": target_ref, "format": "target_technical_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(request, "report_download", "failure", user, severity="warning", details={"target_ref": target_ref, "format": "target_technical_html", "reason": "report_not_found"})
    raise HTTPException(status_code=404, detail="Target technical report not found")

@app.get("/api/report/target/{target:path}/compliance_html")
def get_target_compliance_html(target: str, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get per-target compliance + posture summary report (HTML)."""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    target_ref = target_report_ref(target)
    if not user_owns_target_ref(user["id"], target_ref):
        log_audit_event(
            request,
            "report_download",
            "failure",
            user,
            severity="warning",
            details={"target_ref": target_ref, "format": "target_compliance_html", "reason": "report_not_found"},
        )
        raise HTTPException(status_code=404, detail="Target compliance report not found")
    ensure_target_compliance_report_file(user["id"], target_ref)
    report_file = REPORTS_DIR / f"report_target_{target_ref}_compliance.html"
    if report_file.exists():
        log_audit_event(request, "report_download", "success", user, details={"target_ref": target_ref, "format": "target_compliance_html"})
        return HTMLResponse(report_file.read_text())
    log_audit_event(
        request,
        "report_download",
        "failure",
        user,
        severity="warning",
        details={"target_ref": target_ref, "format": "target_compliance_html", "reason": "report_not_found"},
    )
    raise HTTPException(status_code=404, detail="Target compliance report not found")

@app.get("/api/report/{scan_id}/markdown")
def get_markdown_report(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get markdown report"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "markdown", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Report not found")
    
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT report_executive, report_technical FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    
    if not row:
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "markdown", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Report not found")
    
    markdown_content = f"""# Security Assessment Report - Scan {scan_id}

## Executive Summary
{row['report_executive']}

## Technical Details
{row['report_technical']}

---
*Generated by {PRODUCT_BRAND_NAME}*
"""
    
    log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "markdown"})
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report_scan_{scan_id}.md"}
    )

@app.get("/api/report/{scan_id}/executive")
def get_executive_text(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get executive report text"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "executive_text", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Executive report not found")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT report_executive FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    if not row or not row["report_executive"]:
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "executive_text", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Executive report not found")
    log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "executive_text"})
    return Response(
        content=row["report_executive"],
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=report_scan_{scan_id}_executive.txt"}
    )

@app.get("/api/report/{scan_id}/technical")
def get_technical_text(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Get technical report text"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "technical_text", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Technical report not found")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT report_technical FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    if not row or not row["report_technical"]:
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "technical_text", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Technical report not found")
    log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "technical_text"})
    return Response(
        content=row["report_technical"],
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=report_scan_{scan_id}_technical.txt"}
    )

@app.get("/api/report/{scan_id}/raw_summary")
def get_raw_summary_report(scan_id: int, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Raw tool output + AI summary as text."""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    require_action_password(user, request, "report_download")
    if not get_scan_for_user(scan_id, user["id"]):
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "raw_summary", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Report not found")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT target, tool, status, created_at, completed_at, results FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    if not row:
        log_audit_event(request, "report_download", "failure", user, severity="warning", details={"scan_id": scan_id, "format": "raw_summary", "reason": "report_not_found"})
        raise HTTPException(status_code=404, detail="Report not found")
    target = row["target"]
    tool = row["tool"]
    status = row["status"]
    created = format_abu_dhabi(row["created_at"]) or row["created_at"]
    completed = format_abu_dhabi(row["completed_at"]) or row["completed_at"]
    output = ""
    error = ""
    command_used = ""
    if row["results"]:
        try:
            results = json.loads(row["results"])
            output = results.get("output", "")
            error = results.get("error", "")
            command_used = results.get("command", "")
        except Exception:
            output = ""
            error = ""

    findings_summary = summarize_findings_basic(tool, output, error, target, command=command_used)
    ai_summary = ""
    if llama_available() and is_port_open("127.0.0.1", 8080):
        prompt = (
            f"{AI_AGENT_ROLE} Summarize the following scan results for {tool} on {target} in 6-10 bullet points. "
            "Focus on findings, evidence, and severity.\n\n"
            f"Findings:\n{findings_summary}\n\nRaw Output (truncated):\n{output[:2000]}\n\nSummary:"
        )
        try:
            ai_summary = llama_server_request(prompt, max_tokens=200)
        except Exception:
            ai_summary = ""
    if not ai_summary or any(bad in ai_summary.lower() for bad in ["llm", "not available", "not responding", "timed out", "error"]):
        ai_summary = findings_summary

    text = (
        f"Raw Scan Report (AI Summary)\n"
        f"Scan ID: {scan_id}\n"
        f"Target: {target}\n"
        f"Tool: {tool}\n"
        f"Status: {status}\n"
        f"Created: {created}\n"
        f"Completed: {completed}\n\n"
        f"AI Summary:\n{ai_summary}\n\n"
        f"Findings Summary:\n{findings_summary}\n\n"
        f"Errors:\n{error or 'None'}\n\n"
        f"Raw Output:\n{output or 'No output captured.'}\n"
    )
    log_audit_event(request, "report_download", "success", user, details={"scan_id": scan_id, "format": "raw_summary"})
    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=report_scan_{scan_id}_raw.txt"}
    )

# ========== AI ASSISTANT ENDPOINTS ==========
@app.get("/api/ai/status")
def ai_status():
    """Check AI model status"""
    llama_path = LLAMA_CLI
    model_path = LLAMA_MODEL

    status = {
        "llama_installed": llama_path.exists(),
        "model_present": model_path.exists(),
        "model_size": model_path.stat().st_size if model_path.exists() else 0,
        "ready": llama_path.exists() and model_path.exists(),
        "model": model_path.name if model_path.exists() else None
    }
    
    return JSONResponse(status)

@app.post("/api/ai/ask")
async def ai_assistant(
    question: str = Form(...),
    context: str = Form(None),
    credentials: HTTPBasicCredentials = Depends(security)
):
    """AI security assistant"""
    verify_user(credentials)
    
    llama_path = LLAMA_CLI
    model_path = LLAMA_MODEL
    
    if not (llama_path.exists() and model_path.exists()):
        return JSONResponse({
            "answer": f"⚠️ AI Assistant requires llama.cpp and a compatible GGUF model in {MODELS_DIR}.",
            "ai_available": False
        })
    
    # Create prompt
    prompt = f"""{AI_AGENT_ROLE}
You provide professional, concise, actionable guidance for penetration testing, reporting, and remediation.
You can:
- show scan status (use: status <scan_id>)
- list scan history (use: history)
- generate reports for a scan (use: report <scan_id>)
- generate consolidated reports for a target (use: report target <domain>)
- explain findings from a scan (use: explain <scan_id> or logs <scan_id>)
- provide executive summaries for management and deep technical guidance with PoC/reproduction/remediation for engineers

If a scan/report is requested without a target or scan ID, ask one clarifying question.
When running a scan, use: scan <target> with <katana|nikto|nuclei|sqlmap|all tools>.
Use only these tools when giving commands: katana, nikto, nuclei, sqlmap.
Do not include the word 'Response:' in your reply.

Question: {question}

Context: {context if context else "General cybersecurity question"}

Answer in a clear, executive-friendly style."""
    
    ai_response = run_llama_prompt(prompt, max_tokens=256)
    if (not ai_response) or any(key in ai_response.lower() for key in [
        "llm is not available", "llm server", "not responding", "llm error", "timed out"
    ]):
        ai_response = build_fallback_reply(question, [])

    return JSONResponse({
        "question": question,
        "answer": ai_response,
        "ai_available": True,
        "model": model_path.name,
        "timestamp": datetime.now().isoformat()
    })

# ========== CHAT COMMANDS ==========
async def handle_chat_command(cmd, params, user, request: Request, background_tasks: BackgroundTasks):
    sensitive_cmd_actions = {
        "scan": "scan_start",
        "scan_tool": "scan_start",
        "report_choice": "report_generate",
        "report_target": "report_generate",
    }
    action_label = sensitive_cmd_actions.get(cmd)
    if action_label:
        enforce_password_rotation(user, request)
        require_action_password(user, request, action_label)

    if cmd == "empty":
        return JSONResponse({"reply": "Please provide a command. Example: scan example.com with katana"})

    if cmd == "help":
        return JSONResponse({
            "reply": (
                "Available commands:\n"
                "- scan <target> [with katana|nikto|nuclei|sqlmap]\n"
                "- report target <domain>\n"
                "- report <scan_id>\n"
                "- explain <scan_id>\n"
                "- status <scan_id>\n"
                "- logs <scan_id>\n"
                "- history"
            ),
            "actions": {"type": "help"}
        })

    if cmd == "scan_prompt":
        target = params.get("target", "")
        display_target = normalize_target_display(target)
        pending_scan_target[user["id"]] = display_target
        return JSONResponse({
            "reply": (
                f"Which tool should I use for {display_target}?\n"
                "Options: katana, nikto, nuclei, sqlmap, or 'all tools' to run all sequentially."
            ),
            "actions": {"type": "scan_prompt", "target": target}
        })

    if cmd == "scan_tool":
        tool = params.get("tool", "katana")
        tool_aliases = {
            "all": "all tools",
            "all tools please": "all tools"
        }
        tool = tool_aliases.get(tool, tool)
        target = pending_scan_target.get(user["id"])
        if not target:
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "missing_pending_target"})
            return JSONResponse({"reply": "Which target should I scan? Example: scan example.com with katana"})
        target = normalize_target(target)
        if not is_valid_target(target):
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "invalid_target", "target": target})
            return JSONResponse({"reply": "Please provide a valid target domain or IP. Example: scan example.com with katana"})
        if is_excluded_target(target):
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "excluded_target", "target": target})
            return JSONResponse({"reply": "This target is blocked (test placeholder)."})
        if "all tools" in tool:
            started = []
            scan_ids_tools = []
            for t in ALL_TOOLS_SCAN_ORDER:
                db = get_db()
                cur = db.cursor()
                cur.execute(
                    "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'pending')",
                    (user["id"], target, t)
                )
                scan_id = cur.lastrowid
                db.commit()
                db.close()
                scan_ids_tools.append((scan_id, t))
                started.append(f"{t} (ID {scan_id})")
            background_tasks.add_task(run_multi_scan_async, scan_ids_tools, target)
            pending_scan_target.pop(user["id"], None)
            log_audit_event(
                request,
                "chat_scan_start",
                "success",
                user,
                details={"mode": "all_tools", "target": target, "scan_ids": [scan_id for scan_id, _ in scan_ids_tools]},
            )
            return JSONResponse({
                "reply": f"Queued sequential scans for {target}: {', '.join(started)}.",
                "actions": {"type": "scan_started"}
            })
        valid_tools = SUPPORTED_TOOLS
        if tool not in valid_tools:
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "invalid_tool", "tool": tool})
            return JSONResponse({"reply": f"Invalid tool '{tool}'. Choose: {', '.join(valid_tools)} or 'all tools'."})
        last_scan_target[user["id"]] = target
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'pending')",
            (user["id"], target, tool)
        )
        scan_id = cur.lastrowid
        db.commit()
        db.close()
        background_tasks.add_task(run_scan_async, scan_id, target, tool)
        pending_scan_target.pop(user["id"], None)
        log_audit_event(request, "chat_scan_start", "success", user, details={"scan_id": scan_id, "target": target, "tool": tool})
        return JSONResponse({
            "reply": f"Scan {scan_id} started: {tool} on {target}.",
            "actions": {"type": "scan_started", "scan_id": scan_id}
        })

    if cmd == "report_choice":
        scan_id = params.get("scan_id")
        report_type = params.get("report_type")
        if not scan_id or report_type not in ("executive", "technical", "both"):
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"reason": "invalid_report_choice"})
            return JSONResponse({"reply": "Which report type? Reply: executive, technical, or both."})
        if not get_scan_for_user(scan_id, user["id"]):
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"scan_id": scan_id, "reason": "scan_not_found"})
            return JSONResponse({"reply": f"Scan {scan_id} not found."})
        try:
            reports = await generate_scan_reports(scan_id)
            if not reports or reports.get("error"):
                log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"scan_id": scan_id, "report_type": report_type, "reason": reports.get("error", "unknown")})
                return JSONResponse({"reply": f"Report generation failed: {reports.get('error', 'unknown error')}"})
            if report_type == "executive":
                log_audit_event(request, "chat_report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type})
                return JSONResponse({
                    "reply": f"Executive report generated for scan {scan_id}.",
                    "actions": {"type": "report"},
                    "data": {
                        "scan_id": scan_id,
                        "executive": reports.get("executive", "")[:1500],
                        "html": f"/api/report/{scan_id}/executive_html"
                    }
                })
            if report_type == "technical":
                log_audit_event(request, "chat_report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type})
                return JSONResponse({
                    "reply": f"Technical report generated for scan {scan_id}.",
                    "actions": {"type": "report"},
                    "data": {
                        "scan_id": scan_id,
                        "technical": reports.get("technical", "")[:1500],
                        "html": f"/api/report/{scan_id}/technical_html"
                    }
                })
            log_audit_event(request, "chat_report_generate", "success", user, details={"scan_id": scan_id, "report_type": report_type})
            return JSONResponse({
                "reply": f"Both reports generated for scan {scan_id}.",
                "actions": {"type": "report"},
                "data": {
                    "scan_id": scan_id,
                    "executive": reports.get("executive", "")[:1500],
                    "technical": reports.get("technical", "")[:1500],
                    "html": f"/api/report/{scan_id}/html",
                    "markdown": f"/api/report/{scan_id}/markdown"
                }
            })
        except Exception as e:
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"scan_id": scan_id, "report_type": report_type, "reason": str(e)[:180]})
            return JSONResponse({"reply": f"Report generation failed: {str(e)}"})

    if cmd == "scan_same":
        tool = params.get("tool", "").strip().lower()
        target = last_scan_target.get(user["id"])
        if not target:
            return JSONResponse({"reply": "I don't have a previous target. Which target should I scan?"})
        if not tool:
            pending_scan_target[user["id"]] = normalize_target_display(target)
            return JSONResponse({
                "reply": (
                    f"Which tool should I use for {normalize_target_display(target)}?\n"
                    "Options: katana, nikto, nuclei, sqlmap, or 'all tools' to run all sequentially."
                )
            })
        return await handle_chat_command("scan", {"target": target, "tool": tool}, user, request, background_tasks)

    if cmd == "history":
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, target, tool, status, created_at, started_at, completed_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (user["id"],)
        )
        scans = []
        for row in cur.fetchall():
            scan = dict(row)
            if is_excluded_target(scan.get("target")):
                continue
            scan["duration"] = compute_scan_duration_seconds(scan)
            scan["created_at_local"] = format_abu_dhabi(scan["created_at"])
            scan["started_at_local"] = format_abu_dhabi(scan["started_at"]) if scan["started_at"] else None
            scan["completed_at_local"] = format_abu_dhabi(scan["completed_at"]) if scan["completed_at"] else None
            scans.append(scan)
        db.close()
        return JSONResponse({
            "reply": f"Found {len(scans)} recent scans.",
            "actions": {"type": "history"},
            "data": {"scans": scans}
        })

    if cmd == "scan":
        target = params.get("target", "")
        tool = params.get("tool", "katana")
        tool_aliases = {
            "nukei": "nuclei",
            "nuklei": "nuclei",
            "katanna": "katana",
            "nikto": "nikto",
            "sqlmap": "sqlmap"
        }
        tool = tool_aliases.get(tool, tool)
        valid_tools = SUPPORTED_TOOLS
        if tool not in valid_tools:
            # Handle "all tools" phrasing
            if "all" in tool or "4 tools" in tool:
                if not is_valid_target(target):
                    log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "invalid_target", "target": target})
                    return JSONResponse({"reply": "Please provide a valid target domain or IP. Example: scan example.com with katana"})
                if is_excluded_target(target):
                    log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "excluded_target", "target": target})
                    return JSONResponse({"reply": "This target is blocked (test placeholder)."})
                target = normalize_target(target)
                started = []
                scan_ids_tools = []
                for t in ALL_TOOLS_SCAN_ORDER:
                    db = get_db()
                    cur = db.cursor()
                    cur.execute(
                        "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'pending')",
                        (user["id"], target, t)
                    )
                    scan_id = cur.lastrowid
                    db.commit()
                    db.close()
                    scan_ids_tools.append((scan_id, t))
                    started.append(f"{t} (ID {scan_id})")
                background_tasks.add_task(run_multi_scan_async, scan_ids_tools, target)
                log_audit_event(
                    request,
                    "chat_scan_start",
                    "success",
                    user,
                    details={"mode": "all_tools", "target": target, "scan_ids": [scan_id for scan_id, _ in scan_ids_tools]},
                )
                return JSONResponse({
                    "reply": f"Queued sequential scans for {target}: {', '.join(started)}.",
                    "actions": {"type": "scan_started"}
                })
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "invalid_tool", "tool": tool})
            return JSONResponse({"reply": f"Invalid tool '{tool}'. Choose: {', '.join(valid_tools)} or 'all'."})
        if not is_valid_target(target):
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "invalid_target", "target": target})
            return JSONResponse({"reply": "Please provide a valid target domain or IP. Example: scan example.com with katana"})
        if is_excluded_target(target):
            log_audit_event(request, "chat_scan_start", "failure", user, severity="warning", details={"reason": "excluded_target", "target": target})
            return JSONResponse({"reply": "This target is blocked (test placeholder)."})

        target = normalize_target(target)
        last_scan_target[user["id"]] = target
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'pending')",
            (user["id"], target, tool)
        )
        scan_id = cur.lastrowid
        db.commit()
        db.close()

        background_tasks.add_task(run_scan_async, scan_id, target, tool)
        log_audit_event(request, "chat_scan_start", "success", user, details={"scan_id": scan_id, "target": target, "tool": tool})
        return JSONResponse({
            "reply": f"Scan {scan_id} started: {tool} on {target}.",
            "actions": {"type": "scan_started", "scan_id": scan_id}
        })

    if cmd == "status":
        scan_id = params.get("scan_id")
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, target, tool, status, created_at, completed_at FROM scans WHERE id=? AND user_id=?", (scan_id, user["id"]))
        scan = cur.fetchone()
        db.close()
        if not scan:
            return JSONResponse({"reply": f"Scan {scan_id} not found."})
        return JSONResponse({
            "reply": f"Scan {scan_id} status: {scan['status']}.",
            "actions": {"type": "status"},
            "data": {"scan": dict(scan)}
        })

    if cmd == "logs":
        scan_id = params.get("scan_id")
        log_file = LOG_DIR / f"scan_{scan_id}.log"
        if not log_file.exists():
            return JSONResponse({"reply": f"No logs available for scan {scan_id}."})
        try:
            log_data = json.loads(log_file.read_text())
        except Exception:
            log_data = {"log": log_file.read_text()}
        return JSONResponse({
            "reply": f"Logs for scan {scan_id}.",
            "actions": {"type": "logs"},
            "data": {"logs": log_data}
        })

    if cmd == "explain":
        scan_id = params.get("scan_id")
        scan = get_scan_for_user(scan_id, user["id"])
        if not scan:
            return JSONResponse({"reply": f"Scan {scan_id} not found."})
        results = {}
        if scan["results"]:
            try:
                results = json.loads(scan["results"]) or {}
            except Exception:
                results = {}
        output = clean_scan_text(results.get("output", ""))
        error = clean_scan_text(results.get("error", ""))
        progress = results.get("progress") if isinstance(results, dict) else None
        status_display = scan["status"]
        if scan["status"] == "failed" and "timed out" in error.lower() and output:
            status_display = "completed (partial timeout)"
        findings = build_findings_from_output(
            scan["tool"],
            output,
            error,
            scan["target"],
            progress,
            command=results.get("command") if isinstance(results, dict) else None,
        )
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cvss_values = []
        for item in findings:
            sev = str(item.get("severity", "info")).lower()
            counts[sev if sev in counts else "info"] += 1
            matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", str(item.get("cvss", "")))
            if matches:
                try:
                    cvss_values.append(max(0.0, min(float(matches[-1]), 10.0)))
                except Exception:
                    pass
        top_cvss = max(cvss_values) if cvss_values else 0.0
        if top_cvss >= 9.0 or counts["critical"] > 0:
            overall = "CRITICAL"
        elif top_cvss >= 7.0 or counts["high"] > 0:
            overall = "HIGH"
        elif top_cvss >= 4.0 or counts["medium"] > 0:
            overall = "MEDIUM"
        elif top_cvss > 0 or counts["low"] > 0:
            overall = "LOW"
        else:
            overall = "INFO"

        reply = build_chat_findings_explanation(
            scan_id=scan_id,
            target=scan["target"],
            tool=scan["tool"],
            status_display=status_display,
            findings_list=findings,
            counts=counts,
            overall_risk=overall,
        )
        return JSONResponse({
            "reply": reply,
            "actions": {"type": "explain"},
            "data": {
                "scan_id": scan_id,
                "counts": counts,
                "overall_risk": overall,
            },
        })

    if cmd == "report":
        scan_id = params.get("scan_id")
        report_type = params.get("report_type")
        if report_type:
            return await handle_chat_command("report_choice", {"scan_id": scan_id, "report_type": report_type}, user, request, background_tasks)
        pending_report_scan[user["id"]] = scan_id
        return JSONResponse({"reply": "Which report type? Reply: executive, technical, or both. I will open it automatically once ready."})

    if cmd == "report_target":
        target = params.get("target", "")
        if not target:
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"reason": "missing_target"})
            return JSONResponse({"reply": "Please provide a target. Example: report target example.com"})
        if is_excluded_target(target):
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"target": target, "reason": "excluded_target"})
            return JSONResponse({"reply": "This target is blocked (test placeholder)."})
        reports = await generate_consolidated_reports(user["id"], target)
        if reports.get("error"):
            log_audit_event(request, "chat_report_generate", "failure", user, severity="warning", details={"target": target, "reason": reports.get("error", "not_found")})
            return JSONResponse({"reply": f"No scans found for target {target}."})
        links = build_target_report_links(target)
        log_audit_event(request, "chat_report_generate", "success", user, details={"target": target, "mode": "consolidated"})
        return JSONResponse({
            "reply": f"Consolidated report generated for {target}.",
            "actions": {"type": "report"},
            "data": {
                "scan_id": None,
                "executive": reports.get("executive", "")[:1500],
                "technical": reports.get("technical", "")[:1500],
                "html": links["combined_html"],
                "executive_html": links["executive_html"],
                "technical_html": links["technical_html"]
            }
        })

    return JSONResponse({"reply": "Unsupported command. Type 'help' for options."})

@app.post("/api/chat")
async def chat_command(
    request: Request,
    background_tasks: BackgroundTasks,
    message: str = Form(...),
    credentials: HTTPBasicCredentials = Depends(security)
):
    """Chat-driven control: scans, reports, history, and AI Q&A"""
    user = verify_user(credentials)
    enforce_password_rotation(user, request)
    cmd, params = parse_chat_command(message)
    log_audit_event(
        request,
        "chat_message",
        "success",
        user,
        details={"command": cmd, "message_preview": (message or "")[:160]},
    )

    if cmd != "chat":
        # Explicit command from user
        return await handle_chat_command(cmd, params, user, request, background_tasks)

    lower_msg = message.strip().lower()
    if user["id"] in pending_report_scan:
        choice = None
        if "executive" in lower_msg:
            choice = "executive"
        elif "technical" in lower_msg:
            choice = "technical"
        elif "both" in lower_msg or "combined" in lower_msg or "all" in lower_msg:
            choice = "both"
        if choice:
            scan_id = pending_report_scan.pop(user["id"])
            return await handle_chat_command("report_choice", {"scan_id": scan_id, "report_type": choice}, user, request, background_tasks)
    tool_only = {
        "katana": "katana",
        "nikto": "nikto",
        "nuclei": "nuclei",
        "sqlmap": "sqlmap",
        "all tools": "all tools",
        "all": "all tools"
    }
    pending_target = pending_scan_target.get(user["id"])
    if pending_target:
        selected = None
        if lower_msg in tool_only:
            selected = tool_only[lower_msg]
        else:
            for key in SUPPORTED_TOOLS:
                if re.search(rf"\b{key}\b", lower_msg):
                    selected = key
                    break
            if "all tools" in lower_msg:
                selected = "all tools"
        if selected:
            return await handle_chat_command("scan_tool", {"tool": selected}, user, request, background_tasks)
    if lower_msg in tool_only and not pending_target:
        return JSONResponse({"reply": "Which target should I scan? Example: scan example.com with katana"})

    # Fast-path greetings or short messages to avoid LLM latency
    if len(message.strip()) <= 4 or lower_msg in ("hi", "hello", "hey"):
        return JSONResponse({
            "reply": (
                f"Hello. I am your {PRODUCT_BRAND_NAME} AI Assistant. I can orchestrate security scans "
                "(Katana, Nikto, Nuclei, SQLMap), monitor live status/logs, and generate executive, "
                "technical, or combined reports with remediation guidance. "
                "To begin, use: scan <target> with <katana|nikto|nuclei|sqlmap|all tools>."
            )
        })

    # Quick intents: last scan, findings, yesterday reports
    if "last scan" in lower_msg or "latest scan" in lower_msg:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, target, tool, status, created_at, completed_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["id"],)
        )
        scan = cur.fetchone()
        db.close()
        if not scan:
            return JSONResponse({"reply": "No scans found yet."})
        scan = dict(scan)
        return JSONResponse({
            "reply": f"Latest scan #{scan['id']} on {scan['target']} using {scan['tool']} is {scan['status']}. Created {format_abu_dhabi(scan['created_at'])}.",
            "actions": {"type": "status"},
            "data": {"scan": scan}
        })

    if "last finding" in lower_msg or "last findings" in lower_msg:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, results, created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["id"],)
        )
        row = cur.fetchone()
        db.close()
        if not row:
            return JSONResponse({"reply": "No scans found yet."})
        results_json = row["results"]
        summary = "No findings available."
        if results_json:
            try:
                results = json.loads(results_json)
                output = results.get("output", "")
                if output:
                    lines = output.split("\\n")
                    vuln_lines = [line for line in lines if any(word in line.lower() for word in 
                                   ['vulnerable', 'vulnerability', 'critical', 'high', 'medium', 'low', 
                                    'risk', 'warning', 'alert', 'finding', 'issue'])]
                    summary = "\\n".join(vuln_lines[:10]) if vuln_lines else "No critical findings reported."
            except Exception:
                pass
        return JSONResponse({"reply": f"Last scan findings (scan #{row['id']}):\\n{summary}"})

    if "failed scan" in lower_msg or "failed scans" in lower_msg:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, target, tool, status, created_at FROM scans WHERE user_id=? AND status='failed' ORDER BY id DESC LIMIT 10",
            (user["id"],)
        )
        rows = cur.fetchall()
        db.close()
        if not rows:
            return JSONResponse({"reply": "No failed scans found."})
        items = []
        for r in rows:
            err = ""
            try:
                db = get_db()
                cur = db.cursor()
                cur.execute("SELECT results FROM scans WHERE id=?", (r["id"],))
                row2 = cur.fetchone()
                db.close()
                if row2 and row2["results"]:
                    res = json.loads(row2["results"])
                    err = res.get("error", "")
            except Exception:
                err = ""
            err_snippet = f" | error: {err[:120]}" if err else ""
            items.append(f"#{r['id']} {r['tool']} {r['target']} ({format_abu_dhabi(r['created_at'])}){err_snippet}")
        return JSONResponse({"reply": "Recent failed scans:\n" + "\n".join(items)})

    if "yesterday" in lower_msg and "report" in lower_msg:
        tz = ZoneInfo("Asia/Dubai")
        now_local = datetime.now(tz)
        y_start = (now_local.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1))
        y_end = y_start + timedelta(days=1)
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, target, tool, status, created_at FROM scans WHERE user_id=? ORDER BY id DESC",
            (user["id"],)
        )
        scans = []
        for row in cur.fetchall():
            created_local = format_abu_dhabi(row["created_at"])
            dt_local = None
            if created_local:
                dt_local = datetime.strptime(created_local, "%Y-%m-%d %I:%M %p").replace(tzinfo=tz)
            if dt_local and y_start <= dt_local < y_end:
                scans.append(dict(row))
        db.close()
        if not scans:
            return JSONResponse({"reply": "No scans found from yesterday (Abu Dhabi time)."})
        ids = ", ".join(str(s["id"]) for s in scans[:10])
        return JSONResponse({"reply": f"Yesterday's scans: {ids}. You can request: report <scan_id>."})

    # Domain knowledge mode: explain security issues without forcing a scan ID.
    topic_reply = build_security_topic_reply_for_chat(message)
    if topic_reply:
        return JSONResponse({"reply": topic_reply, "actions": {"type": "chat"}})

    # Clarify missing targets or IDs for implied actions
    if any(word in lower_msg for word in ["scan", "conduct a scan", "perform a scan", "start a scan"]) and not re.search(r"(http://|https://|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|[a-z0-9.-]+\\.[a-z]{2,})", lower_msg):
        return JSONResponse({"reply": "Which target should I scan? Example: scan example.com with katana"})
    explain_scan_without_id = (
        re.search(r"\b(?:explain|summari[sz]e|interpret|clarify|walk\s+me\s+through)\b", lower_msg)
        and re.search(r"\b(?:scan|report|findings?)\b", lower_msg)
        and not re.search(r"\\b\\d+\\b", lower_msg)
    )
    if explain_scan_without_id:
        return JSONResponse({"reply": "Which scan ID should I explain? Example: explain findings for scan 20"})
    if (
        "report" in lower_msg
        and not any(k in lower_msg for k in ["explain", "summarize", "interpret", "clarify"])
        and not re.search(r"\\b\\d+\\b", lower_msg)
    ):
        return JSONResponse({"reply": "Which scan ID should I report on? Example: report 20"})

    # Default: AI chat response
    last_scans = []
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, target, tool, status, created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 5",
            (user["id"],)
        )
        last_scans = [dict(r) for r in cur.fetchall()]
        db.close()
    except Exception:
        last_scans = []

    context = "\n".join([f"- {s['id']}: {s['target']} ({s['tool']}) {s['status']}" for s in last_scans]) or "No scans yet."

    prompt = (
        f"{AI_AGENT_ROLE} "
        "Answer like a professional pentest advisor: concise, actionable, and clear. "
        "You can show scan status (use: status <scan_id>), list scan history (use: history), "
        "generate reports (use: report <scan_id>), generate consolidated reports for a target "
        "(use: report target <domain>), and explain findings (use: explain <scan_id>). "
        "If a user wants to run a scan or generate a report but did not provide a target or scan ID, "
        "ask a single clarifying question. "
        "When running a scan, use: scan <target> with <katana|nikto|nuclei|sqlmap|all tools>. "
        "Use only these tools when you give commands: katana, nikto, nuclei, sqlmap. "
        "Do not invent tools. Do not repeat yourself. Do not include the word 'Response:' in your reply.\n\n"
        f"Recent scans:\n{context}\n\n"
        f"User message: {message}\n\nAnswer:"
    )
    reply = run_llama_prompt(prompt, max_tokens=128)

    # Fallback if LLM unavailable/unresponsive
    if (not reply) or any(key in reply.lower() for key in [
        "llm is not available", "llm server", "not responding", "llm error", "timed out"
    ]):
        reply = build_fallback_reply(message, last_scans)

    # Sanitize hallucinated tools
    allowed_tools = SUPPORTED_TOOLS
    lowered = reply.lower()
    if any(t in lowered for t in ["nmap", "metasploit", "burp", "zap"]):
        reply = "I can use katana, nikto, nuclei, or sqlmap only. Ask me to run one of those tools on a target."

    return JSONResponse({"reply": reply, "actions": {"type": "chat"}})

# ========== MAIN ==========

# ============================================
# DASHBOARD SUMMARY (CISO Snapshot)
# ============================================
def _parse_cvss_value(cvss_text: str) -> float:
    if not cvss_text:
        return 0.0
    matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)", str(cvss_text))
    if not matches:
        return 0.0
    try:
        return max(0.0, min(float(matches[-1]), 10.0))
    except Exception:
        return 0.0

@app.get("/api/dashboard/summary")
def dashboard_summary(
    request: Request,
    window_days: int = 30,
    limit: int = 250,
    credentials: HTTPBasicCredentials = Depends(security),
):
    """
    Aggregated dashboard snapshot:
      - total scans within window
      - findings severity distribution (derived from stored scan outputs)
      - top 3 targets ranked by severity + CVSS
    """
    user = verify_user(credentials)
    enforce_password_rotation(user, request)

    window_days = max(1, min(int(window_days or 30), 365))
    limit = max(10, min(int(limit or 250), 2000))

    cutoff = (datetime.utcnow() - timedelta(days=window_days)).strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, target, tool, status, results, created_at, started_at, completed_at "
        "FROM scans WHERE user_id=? AND created_at >= ? ORDER BY id DESC LIMIT ?",
        (user["id"], cutoff, limit),
    )
    rows = cur.fetchall()
    db.close()

    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    high_risk_findings = 0

    # group by target for top targets
    target_map = {}  # target -> agg

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for row in rows:
        scan_id = int(row["id"])
        target = str(row["target"] or "").strip()
        tool = (str(row["tool"] or "").strip().lower())
        status = str(row["status"] or "").lower()

        results = {}
        if row["results"]:
            try:
                results = json.loads(row["results"]) or {}
            except Exception:
                results = {}

        output = clean_scan_text(results.get("output", ""))
        error = clean_scan_text(results.get("error", ""))
        progress = results.get("progress") if isinstance(results, dict) else None
        command = results.get("command") if isinstance(results, dict) else None

        findings = build_findings_from_output(tool, output, error, target, progress, command=command)

        scan_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        max_cvss = 0.0
        worst = "info"
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in scan_counts:
                sev = "info"
            scan_counts[sev] += 1
            cvss_v = _parse_cvss_value(f.get("cvss", ""))
            if cvss_v > max_cvss:
                max_cvss = cvss_v
            if severity_rank.get(sev, 4) < severity_rank.get(worst, 4):
                worst = sev

        for k in severity_totals:
            severity_totals[k] += scan_counts.get(k, 0)

        high_risk_findings += (scan_counts.get("critical", 0) + scan_counts.get("high", 0))

        # ignore empty targets
        if not target:
            continue

        # scoring: severity weight + CVSS
        score = (
            scan_counts["critical"] * 50
            + scan_counts["high"] * 20
            + scan_counts["medium"] * 8
            + scan_counts["low"] * 3
            + max_cvss
        )

        entry = target_map.get(target)
        if not entry:
            entry = {
                "target": target,
                "scan_id": scan_id,
                "overall_risk": worst,
                "max_cvss": max_cvss,
                "findings_total": sum(scan_counts.values()),
                "severity": dict(scan_counts),
                "score": score,
                "tool": tool,
                "status": status,
            }
            target_map[target] = entry
        else:
            # keep the highest-scoring scan as representative, but aggregate totals
            entry["findings_total"] += sum(scan_counts.values())
            for k in entry["severity"]:
                entry["severity"][k] += scan_counts.get(k, 0)
            # update representative scan if worse
            if score > entry["score"]:
                entry["score"] = score
                entry["scan_id"] = scan_id
                entry["overall_risk"] = worst
                entry["max_cvss"] = max_cvss
                entry["tool"] = tool
                entry["status"] = status

    def top_sev_label(totals: dict) -> str:
        if totals.get("critical", 0) > 0:
            return "Critical"
        if totals.get("high", 0) > 0:
            return "High"
        if totals.get("medium", 0) > 0:
            return "Medium"
        if totals.get("low", 0) > 0:
            return "Low"
        return "Info"

    top_targets = sorted(target_map.values(), key=lambda x: x.get("score", 0), reverse=True)[:3]
    # remove internal score
    for t in top_targets:
        t.pop("score", None)

    return JSONResponse({
        "window_days": window_days,
        "total_scans": len(rows),
        "severity": severity_totals,
        "high_risk_findings": high_risk_findings,
        "top_severity": top_sev_label(severity_totals),
        "top_targets": top_targets,
    })


if __name__ == "__main__":
    import uvicorn
    print(f"🚀 Starting {PRODUCT_BRAND_NAME} v4.0...")
    print("🤖 Features: Professional Reports, AI Assistant, Real Scanning")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
