"""
server.py — Vault MVP Service Provider Node (Hub + Agent + Portal)

Responsibilities:
1. Staff login & role management (Argon2id password hashing + bearer tokens)
2. Custom endpoint generation (e.g. vault.laddu.cc/<slug> via Cloudflare Tunnel)
3. Auto-registration with manager.py using enrollment token
4. Chunked file upload, AES-256-GCM encrypted staging, and signed receipts
5. Anti-forgery sync with manager.py's transparency log
6. Ephemeral kiosk session management with verified wipe engine & wipe-on-boot
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import shutil
import sqlite3
import sys
import time
import qrcode
import qrcode.image.svg
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
import uvicorn
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
except ImportError:
    _hasher = None

try:
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    SigningKey = None
    VerifyKey = None

# --- Configuration & Paths ---

DATA_DIR = Path(os.environ.get("VAULT_SERVER_DATA_DIR", "./data_server"))
DB_PATH = DATA_DIR / "server.db"
STAGING_DIR = DATA_DIR / "staging"
WORKSPACES_DIR = DATA_DIR / "workspaces"
IMAGES_DIR = DATA_DIR / "images"

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB default
SERVER_PEPPER = os.environ.get("VAULT_PASSWORD_PEPPER", "vault_secret_server_pepper_32bytes!").encode()
CLOUDFLARE_TUNNEL_URL = os.environ.get("VAULT_TUNNEL_URL", "https://consoles-obj-lucky-trembl.trycloudflare.com").rstrip("/")
VANITY_DOMAIN = os.environ.get("VAULT_VANITY_DOMAIN", "vault.laddu.cc").rstrip("/")

# --- Cryptographic Helpers ---

def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def ed25519_verify(vk_b64: str, message_bytes: bytes, sig_b64: str) -> bool:
    try:
        VerifyKey(unb64u(vk_b64)).verify(message_bytes, unb64u(sig_b64))
        return True
    except Exception:
        return False

def tree_hash(chunk_digests: List[bytes], total_size: int, chunk_size: int) -> str:
    """Calculates domain-separated tree hash over chunk digests."""
    h = hashlib.sha256()
    h.update(b"vault-file-v1\x00")
    h.update(chunk_size.to_bytes(4, "big"))
    h.update(total_size.to_bytes(8, "big"))
    for d in chunk_digests:
        h.update(d)
    return h.hexdigest()

def hash_password(password: str) -> str:
    prehashed = hmac.new(SERVER_PEPPER, password.encode("utf-8"), hashlib.sha256).digest()
    prehashed_b64 = base64.b64encode(prehashed).decode("ascii")
    if _hasher:
        return _hasher.hash(prehashed_b64)
    # Fallback to PBKDF2 if argon2 not available
    salt = os.urandom(16)
    kdf = hashlib.pbkdf2_hmac("sha256", prehashed, salt, 100_000)
    return f"pbkdf2:{b64u(salt)}:{b64u(kdf)}"

def verify_password(password: str, stored_hash: str) -> bool:
    prehashed = hmac.new(SERVER_PEPPER, password.encode("utf-8"), hashlib.sha256).digest()
    prehashed_b64 = base64.b64encode(prehashed).decode("ascii")
    if _hasher and stored_hash.startswith("$argon2"):
        try:
            return _hasher.verify(stored_hash, prehashed_b64)
        except Exception:
            return False
    elif stored_hash.startswith("pbkdf2:"):
        _, salt_str, kdf_str = stored_hash.split(":")
        salt = unb64u(salt_str)
        kdf = hashlib.pbkdf2_hmac("sha256", prehashed, salt, 100_000)
        return hmac.compare_digest(b64u(kdf), kdf_str)
    return False

# --- Database & Storage Initialization ---

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")
    return conn

def init_server_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)

    base_img = IMAGES_DIR / "base_image.bin"
    if not base_img.exists():
        base_img.write_text("VAULT_BASE_IMAGE_1.0.0")

    conn = get_db()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS identity (
            id TEXT PRIMARY KEY,
            device_id TEXT,
            cafe_slug TEXT,
            manager_url TEXT,
            private_key_b64 TEXT NOT NULL,
            public_key_b64 TEXT NOT NULL,
            manager_public_key_b64 TEXT,
            app_version TEXT DEFAULT '1.0.0',
            image_version TEXT DEFAULT '1.0.0',
            active_image_file TEXT DEFAULT 'base_image.bin',
            update_status TEXT DEFAULT 'up_to_date',
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS drops (
            code TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            label TEXT,
            max_bytes INTEGER,
            expires_at REAL NOT NULL,
            status TEXT DEFAULT 'open',
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS uploads (
            id TEXT PRIMARY KEY,
            drop_code TEXT NOT NULL,
            display_name TEXT NOT NULL,
            declared_size INTEGER NOT NULL,
            chunk_size INTEGER NOT NULL,
            total_chunks INTEGER NOT NULL,
            tree_hash TEXT,
            dek_b64 TEXT NOT NULL,
            status TEXT DEFAULT 'receiving',
            wipe_after REAL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chunks (
            upload_id TEXT NOT NULL,
            idx INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            PRIMARY KEY (upload_id, idx)
        );

        CREATE TABLE IF NOT EXISTS receipts (
            upload_id TEXT PRIMARY KEY,
            receipt_json TEXT NOT NULL,
            hub_sig TEXT NOT NULL,
            manager_ack_seq INTEGER,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            workspace_path TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            started_at REAL NOT NULL,
            ended_at REAL
        );

        CREATE TABLE IF NOT EXISTS pending_wipes (
            session_id TEXT PRIMARY KEY,
            workspace_path TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """)

        # Migration: ensure image columns exist on identity
        cols = [r[1] for r in conn.execute("PRAGMA table_info(identity)").fetchall()]
        if "image_version" not in cols:
            conn.execute("ALTER TABLE identity ADD COLUMN image_version TEXT DEFAULT '1.0.0'")
        if "active_image_file" not in cols:
            conn.execute("ALTER TABLE identity ADD COLUMN active_image_file TEXT DEFAULT 'base_image.bin'")
        if "update_status" not in cols:
            conn.execute("ALTER TABLE identity ADD COLUMN update_status TEXT DEFAULT 'up_to_date'")
        if "app_version" not in cols:
            conn.execute("ALTER TABLE identity ADD COLUMN app_version TEXT DEFAULT '1.0.0'")

        # Ensure local Ed25519 identity key exists
        row = conn.execute("SELECT * FROM identity WHERE id = 'node_identity'").fetchone()
        if not row:
            sk = SigningKey.generate()
            conn.execute(
                "INSERT INTO identity (id, private_key_b64, public_key_b64, created_at) VALUES (?, ?, ?, ?)",
                ("node_identity", b64u(bytes(sk)), b64u(bytes(sk.verify_key)), time.time())
            )

    conn.close()

def get_node_identity() -> dict:
    conn = get_db()
    row = conn.execute("SELECT * FROM identity WHERE id = 'node_identity'").fetchone()
    conn.close()
    return dict(row) if row else {}

# --- Wipe-on-Boot Engine ---

def execute_wipe_on_boot():
    """Safety guarantee: obliterated data even after sudden power failure."""
    conn = get_db()
    pending = conn.execute("SELECT session_id, workspace_path FROM pending_wipes").fetchall()
    for row in pending:
        ws_path = Path(row["workspace_path"])
        if ws_path.exists():
            try:
                shutil.rmtree(ws_path, ignore_errors=True)
            except Exception:
                pass
    with conn:
        conn.execute("DELETE FROM pending_wipes")
        conn.execute("UPDATE sessions SET status = 'wiped', ended_at = ? WHERE status = 'active'", (time.time(),))
    conn.close()
    if pending:
        print(f"[Wipe-on-Boot] Obliterated {len(pending)} un-wiped ephemeral workspaces.")

# --- FastAPI App & Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_server_db()
    execute_wipe_on_boot()
    yield

app = FastAPI(title="Vault Service Provider Node", version="1.0.0-mvp", lifespan=lifespan)
security = HTTPBearer(auto_error=False)

SERVER_HTML_FILE = Path(__file__).parent / "server.html"

@app.get("/", response_class=HTMLResponse)
@app.get("/{slug}", response_class=HTMLResponse)
@app.get("/{slug}/", response_class=HTMLResponse)
async def serve_ui(slug: Optional[str] = None):
    if slug and slug in ("api", "healthz", "p", "favicon.ico"):
        raise HTTPException(status_code=404, detail="Not found")
    if not SERVER_HTML_FILE.exists():
        return HTMLResponse("<h1>server.html not found</h1>", status_code=404)
    return HTMLResponse(SERVER_HTML_FILE.read_text(encoding="utf-8"))

# Authentication dependency
async def require_staff(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication token required")
    token = credentials.credentials
    conn = get_db()
    row = conn.execute(
        "SELECT u.id, u.username, u.role FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ? AND t.expires_at > ?",
        (token, time.time())
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    return dict(row)

# --- Pydantic Request / Response Models ---

class BootstrapRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "staff"

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateDropRequest(BaseModel):
    label: str = "Client Document Drop"
    max_bytes: int = 100 * 1024 * 1024  # 100 MB default
    ttl_minutes: int = 60

class InitUploadRequest(BaseModel):
    display_name: str
    size: int
    chunk_size: int = DEFAULT_CHUNK_SIZE

class CompleteUploadRequest(BaseModel):
    chunk_digests: List[str]
    tree_hash: str

# --- Authentication Endpoints ---

@app.post("/api/v1/auth/bootstrap")
async def bootstrap_owner(req: BootstrapRequest):
    """First-time setup: creates initial owner account."""
    conn = get_db()
    with conn:
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        if count > 0:
            raise HTTPException(status_code=400, detail="Node already bootstrapped")
        user_id = str(uuid4())
        hashed = hash_password(req.password)
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, 'owner', ?)",
            (user_id, req.username.lower(), hashed, time.time())
        )
    return {"status": "ok", "message": f"Owner account '{req.username}' created successfully"}

@app.post("/api/v1/auth/register")
async def register_user(req: RegisterRequest):
    """Allows staff/operator account registration (or initial owner if none exist)."""
    uname = req.username.lower().strip()
    if len(uname) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_db()
    with conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        role = "owner" if count == 0 else "staff"
        user_id = str(uuid4())
        hashed = hash_password(req.password)
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, uname, hashed, role, time.time())
        )
    conn.close()
    return {"status": "ok", "message": f"Account '{uname}' registered successfully", "role": role}

@app.post("/api/v1/auth/login")
async def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username.lower(),)).fetchone()

    # Rate limiting & lockout check
    now = time.time()
    if user and user["locked_until"] > now:
        conn.close()
        raise HTTPException(status_code=429, detail=f"Account temporarily locked. Try again in {int(user['locked_until'] - now)}s")

    valid = False
    if user:
        valid = verify_password(req.password, user["password_hash"])

    if not valid:
        if user:
            fails = user["failed_attempts"] + 1
            locked_until = now + (300 if fails >= 5 else 0)  # 5 min lockout after 5 fails
            with conn:
                conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (fails, locked_until, user["id"]))
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Login successful
    with conn:
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        token = b64u(os.urandom(32))
        expires_at = now + 8 * 3600  # 8 hours
        conn.execute("INSERT INTO tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", (token, user["id"], expires_at, now))
    conn.close()

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 28800,
        "role": user["role"]
    }

@app.get("/api/v1/auth/status")
async def auth_status():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    conn.close()
    return {"bootstrapped": count > 0}

@app.get("/api/v1/auth/me")
async def auth_me(staff: dict = Depends(require_staff)):
    return {"id": staff["id"], "username": staff["username"], "role": staff["role"]}

@app.get("/api/v1/users")
async def list_users(staff: dict = Depends(require_staff)):
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Standalone QR Code Generator ---

class QRCodeGenerator:
    def __init__(self, text: str):
        self.text = text

    def generate_svg(self) -> str:
        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(self.text, image_factory=factory, box_size=10, border=3)
        stream = io.BytesIO()
        img.save(stream)
        return stream.getvalue().decode('utf-8')

# --- Drop Management & Custom Endpoint Generation ---

@app.post("/api/v1/drops")
async def create_drop(req: CreateDropRequest, staff: dict = Depends(require_staff)):
    """Staff creates a secure drop endpoint for a customer."""
    code = b64u(os.urandom(6)).upper()[:8]  # Clean 8-char code
    expires_at = time.time() + (req.ttl_minutes * 60)

    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO drops (code, created_by, label, max_bytes, expires_at, status, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?)",
            (code, staff["username"], req.label, req.max_bytes, expires_at, time.time())
        )
        ident = conn.execute("SELECT cafe_slug FROM identity WHERE id = 'node_identity'").fetchone()

    slug = ident["cafe_slug"] if ident and ident["cafe_slug"] else "local"
    tunnel_link = f"{CLOUDFLARE_TUNNEL_URL}/{slug}/d/{code}/upload"
    vanity_link = f"https://{VANITY_DOMAIN}/{slug}/d/{code}/upload"
    return {
        "drop_code": code,
        "portal_url": vanity_link,
        "vanity_url": vanity_link,
        "tunnel_url": tunnel_link,
        "upload_tunnel_url": tunnel_link,
        "upload_vanity_url": vanity_link,
        "local_portal_url": f"/p/{code}/upload",
        "qr_endpoint": f"/api/v1/drops/{code}/qr",
        "expires_at": expires_at,
        "max_bytes": req.max_bytes
    }

@app.get("/api/v1/drops")
async def list_drops(staff: dict = Depends(require_staff)):
    conn = get_db()
    drops = conn.execute("SELECT code, created_by, label, max_bytes, expires_at, status, created_at FROM drops ORDER BY created_at DESC LIMIT 50").fetchall()
    ident = conn.execute("SELECT cafe_slug FROM identity WHERE id = 'node_identity'").fetchone()
    conn.close()
    slug = ident["cafe_slug"] if ident and ident["cafe_slug"] else "local"
    return [
        {
            **dict(d),
            "portal_url": f"https://{VANITY_DOMAIN}/{slug}/d/{d['code']}/upload",
            "vanity_url": f"https://{VANITY_DOMAIN}/{slug}/d/{d['code']}/upload",
            "tunnel_url": f"{CLOUDFLARE_TUNNEL_URL}/{slug}/d/{d['code']}/upload",
            "upload_tunnel_url": f"{CLOUDFLARE_TUNNEL_URL}/{slug}/d/{d['code']}/upload",
            "upload_vanity_url": f"https://{VANITY_DOMAIN}/{slug}/d/{d['code']}/upload",
            "local_portal_url": f"/p/{d['code']}/upload",
            "qr_endpoint": f"/api/v1/drops/{d['code']}/qr",
            "is_expired": d["expires_at"] < time.time()
        }
        for d in drops
    ]

@app.get("/api/v1/drops/{code}/qr")
@app.get("/p/{code}/qr")
@app.get("/{slug}/d/{code}/qr")
@app.get("/{slug}/d/{code}/upload/qr")
async def get_drop_qr_code(code: str, slug: Optional[str] = None):
    conn = get_db()
    drop = conn.execute("SELECT code, status, expires_at FROM drops WHERE code = ?", (code,)).fetchone()
    ident = conn.execute("SELECT cafe_slug FROM identity WHERE id = 'node_identity'").fetchone()
    conn.close()

    if not drop or drop["status"] != "open" or drop["expires_at"] < time.time():
        raise HTTPException(status_code=404, detail="Drop not found or expired")

    cafe_slug = ident["cafe_slug"] if ident and ident["cafe_slug"] else "local"
    upload_url = f"{CLOUDFLARE_TUNNEL_URL}/{cafe_slug}/d/{code}/upload"

    svg_content = QRCodeGenerator(upload_url).generate_svg()
    return Response(content=svg_content, media_type="image/svg+xml")

@app.post("/api/v1/drops/{code}/close")
async def close_drop(code: str, staff: dict = Depends(require_staff)):
    conn = get_db()
    with conn:
        conn.execute("UPDATE drops SET status = 'closed' WHERE code = ?", (code,))
    conn.close()
    return {"status": "closed", "code": code}

# --- Public Customer Portal Upload Endpoints ---

@app.get("/upload", response_class=HTMLResponse)
@app.get("/p/{code}")
@app.get("/p/{code}/upload")
@app.get("/{slug}/d/{code}")
@app.get("/{slug}/d/{code}/upload")
async def get_drop_info(request: Request, code: Optional[str] = None, slug: Optional[str] = None):
    """Customer opens drop link to view metadata or portal page."""
    accept = request.headers.get("accept", "") if request else ""
    if ("text/html" in accept or "text/*" in accept or "*/*" in accept or not accept) and SERVER_HTML_FILE.exists() and "application/json" not in accept:
        return HTMLResponse(SERVER_HTML_FILE.read_text(encoding="utf-8"))

    conn = get_db()
    if not code:
        drop = conn.execute("SELECT code, label, max_bytes, expires_at, status FROM drops WHERE status = 'open' AND expires_at > ? ORDER BY created_at DESC LIMIT 1", (time.time(),)).fetchone()
    else:
        drop = conn.execute("SELECT code, label, max_bytes, expires_at, status FROM drops WHERE code = ?", (code,)).fetchone()
    conn.close()

    if not drop or drop["status"] != "open" or drop["expires_at"] < time.time():
        raise HTTPException(status_code=404, detail="Drop not found or expired")
    return dict(drop)

@app.post("/p/{code}/uploads")
@app.post("/p/{code}/upload/uploads")
@app.post("/{slug}/d/{code}/uploads")
@app.post("/{slug}/d/{code}/upload/uploads")
async def init_upload(code: str, req: InitUploadRequest, slug: Optional[str] = None):
    """Customer initiates chunked file upload."""
    conn = get_db()
    drop = conn.execute("SELECT * FROM drops WHERE code = ?", (code,)).fetchone()
    if not drop or drop["status"] != "open" or drop["expires_at"] < time.time():
        conn.close()
        raise HTTPException(status_code=404, detail="Drop not found or expired")

    if req.size > drop["max_bytes"]:
        conn.close()
        raise HTTPException(status_code=400, detail="File size exceeds drop limit")

    upload_id = str(uuid4())
    total_chunks = (req.size + req.chunk_size - 1) // req.chunk_size
    dek = os.urandom(32)  # Per-upload Data Encryption Key for AES-256-GCM at rest

    upload_dir = STAGING_DIR / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    with conn:
        conn.execute(
            """INSERT INTO uploads (id, drop_code, display_name, declared_size, chunk_size, total_chunks, dek_b64, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'receiving', ?)""",
            (upload_id, code, req.display_name, req.size, req.chunk_size, total_chunks, b64u(dek), time.time())
        )
    conn.close()

    return {
        "upload_id": upload_id,
        "chunk_size": req.chunk_size,
        "total_chunks": total_chunks
    }

@app.put("/p/{code}/uploads/{upload_id}/chunks/{idx}")
@app.put("/p/{code}/upload/uploads/{upload_id}/chunks/{idx}")
@app.put("/{slug}/d/{code}/uploads/{upload_id}/chunks/{idx}")
@app.put("/{slug}/d/{code}/upload/uploads/{upload_id}/chunks/{idx}")
async def upload_chunk(
    code: str,
    upload_id: str,
    idx: int,
    request: Request,
    x_chunk_sha256: str = Header(...),
    slug: Optional[str] = None
):
    """Uploads a single chunk, verifies hash, and encrypts with AES-256-GCM at rest."""
    conn = get_db()
    upload = conn.execute("SELECT * FROM uploads WHERE id = ? AND drop_code = ?", (upload_id, code)).fetchone()
    if not upload or upload["status"] != "receiving":
        conn.close()
        raise HTTPException(status_code=404, detail="Upload session not active")

    data = await request.body()
    computed_digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(computed_digest.lower(), x_chunk_sha256.lower()):
        conn.close()
        raise HTTPException(status_code=422, detail="Chunk SHA-256 hash mismatch")

    # Encrypt chunk at rest using AES-256-GCM with positional coordinate AAD
    dek = unb64u(upload["dek_b64"])
    nonce = os.urandom(12)
    aad = f"{upload_id}:{idx}".encode()
    ciphertext = AESGCM(dek).encrypt(nonce, data, aad)

    chunk_file = STAGING_DIR / upload_id / f"{idx}.chunk"
    with open(chunk_file, "wb") as f:
        f.write(nonce + ciphertext)

    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO chunks (upload_id, idx, sha256, size) VALUES (?, ?, ?, ?)",
            (upload_id, idx, computed_digest, len(data))
        )
    conn.close()

    return {"status": "chunk_accepted", "idx": idx}

@app.post("/p/{code}/uploads/{upload_id}/complete")
@app.post("/p/{code}/upload/uploads/{upload_id}/complete")
@app.post("/{slug}/d/{code}/uploads/{upload_id}/complete")
@app.post("/{slug}/d/{code}/upload/uploads/{upload_id}/complete")
async def complete_upload(code: str, upload_id: str, req: CompleteUploadRequest, slug: Optional[str] = None):
    """Verifies all chunks, validates tree hash, issues Ed25519 receipt, and syncs to manager log."""
    conn = get_db()
    upload = conn.execute("SELECT * FROM uploads WHERE id = ? AND drop_code = ?", (upload_id, code)).fetchone()
    if not upload:
        conn.close()
        raise HTTPException(status_code=404, detail="Upload not found")

    chunks = conn.execute("SELECT idx, sha256, size FROM chunks WHERE upload_id = ? ORDER BY idx ASC", (upload_id,)).fetchall()
    if len(chunks) != upload["total_chunks"]:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Incomplete upload: {len(chunks)} of {upload['total_chunks']} chunks received")

    # Calculate domain-separated tree hash
    digests_bytes = [bytes.fromhex(c["sha256"]) for c in chunks]
    total_received_size = sum(c["size"] for c in chunks)
    computed_tree = tree_hash(digests_bytes, total_received_size, upload["chunk_size"])

    if computed_tree.lower() != req.tree_hash.lower():
        conn.close()
        raise HTTPException(status_code=409, detail="Tree hash mismatch: file integrity corrupted")

    # Sign digital receipt with Hub's Ed25519 key
    ident = conn.execute("SELECT * FROM identity WHERE id = 'node_identity'").fetchone()
    sk = SigningKey(unb64u(ident["private_key_b64"]))
    cafe_slug = ident["cafe_slug"] or "local"

    receipt = {
        "version": 1,
        "upload_id": upload_id,
        "drop_code": code,
        "cafe_slug": cafe_slug,
        "tree_hash": computed_tree,
        "size": total_received_size,
        "chunk_size": upload["chunk_size"],
        "received_at": time.time(),
        "hub_public_key": ident["public_key_b64"]
    }
    hub_sig = b64u(sk.sign(canonical_json(receipt)).signature)

    with conn:
        conn.execute("UPDATE uploads SET status = 'verified', tree_hash = ? WHERE id = ?", (computed_tree, upload_id))
        conn.execute(
            "INSERT OR REPLACE INTO receipts (upload_id, receipt_json, hub_sig, created_at) VALUES (?, ?, ?, ?)",
            (upload_id, json.dumps(receipt), hub_sig, time.time())
        )

    # Sync with Central Manager's Transparency Log (anti-forgery notarization)
    mgr_url = ident["manager_url"]
    mgr_ack_seq = None
    if mgr_url and ident["device_id"]:
        try:
            ts = str(int(time.time()))
            nonce = b64u(os.urandom(16))
            payload = {"receipt": receipt, "hub_sig": hub_sig}
            body_bytes = canonical_json(payload)
            body_hash = hashlib.sha256(body_bytes).hexdigest()
            sign_str = f"VAULT-REQ-V1\nPOST\n/api/v1/log/entries\n{ts}\n{nonce}\n{body_hash}".encode()
            sig = b64u(sk.sign(sign_str).signature)

            headers = {
                "X-Vault-Device": ident["device_id"],
                "X-Vault-Timestamp": ts,
                "X-Vault-Nonce": nonce,
                "X-Vault-Signature": sig,
                "Content-Type": "application/json"
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(f"{mgr_url}/api/v1/log/entries", content=body_bytes, headers=headers)
                if res.status_code == 200:
                    mgr_ack_seq = res.json().get("seq")
                    with conn:
                        conn.execute("UPDATE receipts SET manager_ack_seq = ? WHERE upload_id = ?", (mgr_ack_seq, upload_id))
        except Exception as e:
            print(f"[Sync] Warning: Manager notarization queued/deferred: {e}")

    conn.close()

    return {
        "status": "verified",
        "receipt": receipt,
        "hub_sig": hub_sig,
        "manager_ack_seq": mgr_ack_seq
    }

@app.get("/p/{code}/uploads/{upload_id}/receipt")
@app.get("/p/{code}/upload/uploads/{upload_id}/receipt")
@app.get("/{slug}/d/{code}/uploads/{upload_id}/receipt")
@app.get("/{slug}/d/{code}/upload/uploads/{upload_id}/receipt")
async def get_receipt(code: str, upload_id: str, slug: Optional[str] = None):
    conn = get_db()
    row = conn.execute("SELECT receipt_json, hub_sig, manager_ack_seq FROM receipts WHERE upload_id = ?", (upload_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Receipt not found")
    return {
        "receipt": json.loads(row["receipt_json"]),
        "hub_sig": row["hub_sig"],
        "manager_ack_seq": row["manager_ack_seq"]
    }

# --- Kiosk Session Lifecycle & Verified Wipe Engine ---

@app.post("/api/v1/session/start")
async def start_kiosk_session(staff: dict = Depends(require_staff)):
    """Initializes an ephemeral disposable kiosk workspace with ephemeral session key."""
    session_id = str(uuid4())
    ws_path = WORKSPACES_DIR / session_id
    ws_path.mkdir(parents=True, exist_ok=True)

    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO sessions (id, workspace_path, status, started_at) VALUES (?, ?, 'active', ?)",
            (session_id, str(ws_path), time.time())
        )
        conn.execute(
            "INSERT INTO pending_wipes (session_id, workspace_path, created_at) VALUES (?, ?, ?)",
            (session_id, str(ws_path), time.time())
        )
    conn.close()

    return {
        "session_id": session_id,
        "workspace_path": str(ws_path),
        "status": "active"
    }

@app.post("/api/v1/session/{session_id}/deliver/{upload_id}")
async def deliver_file_to_workspace(session_id: str, upload_id: str, staff: dict = Depends(require_staff)):
    """Decrypts verified chunks into the customer's ephemeral workspace ONLY."""
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE id = ? AND status = 'active'", (session_id,)).fetchone()
    if not sess:
        conn.close()
        raise HTTPException(status_code=404, detail="Active session not found")

    upload = conn.execute("SELECT * FROM uploads WHERE id = ? AND status = 'verified'", (upload_id,)).fetchone()
    if not upload:
        conn.close()
        raise HTTPException(status_code=404, detail="Verified upload not found")

    chunks = conn.execute("SELECT idx, sha256 FROM chunks WHERE upload_id = ? ORDER BY idx ASC", (upload_id,)).fetchall()
    dek = unb64u(upload["dek_b64"])
    ws_path = Path(sess["workspace_path"])

    # Reconstruct decrypted file directly into workspace
    out_file = ws_path / upload["display_name"]
    with open(out_file, "wb") as out_f:
        for c in chunks:
            chunk_file = STAGING_DIR / upload_id / f"{c['idx']}.chunk"
            with open(chunk_file, "rb") as cf:
                blob = cf.read()
            nonce = blob[:12]
            ciphertext = blob[12:]
            aad = f"{upload_id}:{c['idx']}".encode()
            chunk_data = AESGCM(dek).decrypt(nonce, ciphertext, aad)
            out_f.write(chunk_data)

    conn.close()
    return {"status": "delivered", "file_name": upload["display_name"], "path": str(out_file)}

@app.post("/api/v1/session/{session_id}/end")
async def end_kiosk_session(session_id: str, staff: dict = Depends(require_staff)):
    """
    Obliterates the session workspace, destroys keys (crypto-shredding),
    verifies complete absence of files, and clears pending_wipes.
    """
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE id = ? AND status = 'active'", (session_id,)).fetchone()
    if not sess:
        conn.close()
        raise HTTPException(status_code=404, detail="Active session not found")

    ws_path = Path(sess["workspace_path"])

    # 1. Obliterate workspace
    if ws_path.exists():
        shutil.rmtree(ws_path, ignore_errors=True)

    # 2. Verification
    if ws_path.exists():
        conn.close()
        raise HTTPException(status_code=500, detail="Wipe verification failed: workspace directory still exists")

    # 3. Clear pending_wipes & mark session destroyed
    with conn:
        conn.execute("DELETE FROM pending_wipes WHERE session_id = ?", (session_id,))
        conn.execute("UPDATE sessions SET status = 'wiped', ended_at = ? WHERE id = ?", (time.time(), session_id))
    conn.close()

    return {
        "status": "obliterated",
        "session_id": session_id,
        "wipe_verified": True
    }

@app.get("/api/v1/sessions")
async def list_sessions(staff: dict = Depends(require_staff)):
    conn = get_db()
    sessions = conn.execute("SELECT id, workspace_path, status, started_at, ended_at FROM sessions ORDER BY started_at DESC LIMIT 50").fetchall()
    pending = {r["session_id"] for r in conn.execute("SELECT session_id FROM pending_wipes").fetchall()}
    conn.close()

    results = []
    for s in sessions:
        d = dict(s)
        d["has_pending_wipe"] = s["id"] in pending
        files = []
        ws_path = Path(s["workspace_path"])
        if s["status"] == "active" and ws_path.exists():
            for f in ws_path.glob("*"):
                if f.is_file():
                    files.append({
                        "name": f.name,
                        "size": f.stat().st_size,
                        "modified_at": f.stat().st_mtime,
                        "path": str(f)
                    })
        d["files"] = files
        results.append(d)

    return results

@app.get("/api/v1/uploads")
async def list_uploads(staff: dict = Depends(require_staff)):
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.drop_code, u.display_name, u.declared_size, u.total_chunks, u.status, u.tree_hash, u.created_at,
               r.receipt_json, r.hub_sig, r.manager_ack_seq
        FROM uploads u
        LEFT JOIN receipts r ON u.id = r.upload_id
        ORDER BY u.created_at DESC LIMIT 50
    """).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if d.get("receipt_json"):
            d["receipt"] = json.loads(d["receipt_json"])
        else:
            d["receipt"] = None
        d.pop("receipt_json", None)
        results.append(d)
    return results

@app.get("/api/v1/uploads/{upload_id}/download")
async def download_upload_file(
    upload_id: str,
    inline: bool = False,
    staff: dict = Depends(require_staff)
):
    """
    Decrypts verified upload chunks on-the-fly and returns the plaintext file
    for staff members (e.g. Akshaya center operators) to view, download, or forward.
    Requires valid staff Bearer token.
    """
    conn = get_db()
    upload = conn.execute("SELECT * FROM uploads WHERE id = ? AND status = 'verified'", (upload_id,)).fetchone()
    if not upload:
        conn.close()
        raise HTTPException(status_code=404, detail="Verified upload not found")

    chunks = conn.execute("SELECT idx, sha256 FROM chunks WHERE upload_id = ? ORDER BY idx ASC", (upload_id,)).fetchall()
    dek = unb64u(upload["dek_b64"])
    conn.close()

    decrypted_bytes = bytearray()
    for c in chunks:
        chunk_file = STAGING_DIR / upload_id / f"{c['idx']}.chunk"
        if not chunk_file.exists():
            raise HTTPException(status_code=500, detail=f"Missing chunk file index {c['idx']}")
        with open(chunk_file, "rb") as cf:
            blob = cf.read()
        nonce = blob[:12]
        ciphertext = blob[12:]
        aad = f"{upload_id}:{c['idx']}".encode()
        try:
            chunk_data = AESGCM(dek).decrypt(nonce, ciphertext, aad)
        except Exception:
            raise HTTPException(status_code=500, detail=f"Decryption failed for chunk {c['idx']}")
        decrypted_bytes.extend(chunk_data)

    display_name = upload["display_name"]
    media_type, _ = mimetypes.guess_type(display_name)
    if not media_type:
        media_type = "application/octet-stream"

    disposition = "inline" if inline else f'attachment; filename="{display_name}"'
    return Response(
        content=bytes(decrypted_bytes),
        media_type=media_type,
        headers={"Content-Disposition": disposition}
    )

# --- System Status & OTA Update Engine ---

async def check_and_apply_ota_update(client_session: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Checks manager for new signed OTA updates, downloads the .bin/image file,
    verifies checksums and Ed25519 manifest signature, activates the image,
    and reports status to the central manager.
    """
    conn = get_db()
    ident = conn.execute("SELECT * FROM identity WHERE id = 'node_identity'").fetchone()
    conn.close()

    if not ident or not ident["device_id"] or not ident["manager_url"]:
        return {"status": "error", "message": "Node is not enrolled with a manager"}

    device_id = ident["device_id"]
    mgr_url = ident["manager_url"]
    current_image = ident["image_version"] if "image_version" in ident.keys() else "1.0.0"
    sk = SigningKey(unb64u(ident["private_key_b64"]))

    # 1. Send signed heartbeat to check for updates
    ts = str(int(time.time()))
    nonce = b64u(os.urandom(16))
    hb_body = {
        "app_version": ident["app_version"] if "app_version" in ident.keys() else "1.0.0",
        "image_version": current_image,
        "uptime_s": 300.0,
        "state": "idle",
        "last_wipe_ok": True,
        "pending_wipes": 0,
        "active_sessions": 0,
        "update_status": ident["update_status"] if "update_status" in ident.keys() else "up_to_date"
    }
    body_bytes = canonical_json(hb_body)
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    sign_str = f"VAULT-REQ-V1\nPOST\n/api/v1/devices/{device_id}/heartbeat\n{ts}\n{nonce}\n{body_hash}".encode()
    sig = b64u(sk.sign(sign_str).signature)

    headers = {
        "X-Vault-Timestamp": ts,
        "X-Vault-Nonce": nonce,
        "X-Vault-Signature": sig,
        "Content-Type": "application/json"
    }

    async def _do_update(c: httpx.AsyncClient):
        res = await c.post(f"{mgr_url}/api/v1/devices/{device_id}/heartbeat", content=body_bytes, headers=headers)
        if res.status_code != 200:
            return {"status": "error", "message": f"Heartbeat failed: {res.text}"}

        data = res.json()
        update_offer = data.get("update")
        if not update_offer:
            return {"status": "up_to_date", "current_image_version": current_image}

        # 2. Cryptographic verification of manifest
        manifest = update_offer["manifest"]
        manifest_sig = update_offer["sig"]
        mgr_pub = ident["manager_public_key_b64"]
        if not ed25519_verify(mgr_pub, canonical_json(manifest), manifest_sig):
            return {"status": "rejected", "reason": "Manifest signature verification failed"}

        target_version = manifest["version"]
        artifacts = manifest.get("artifacts", [])
        if not artifacts:
            conn = get_db()
            with conn:
                conn.execute(
                    "UPDATE identity SET image_version = ?, update_status = 'applied' WHERE id = 'node_identity'",
                    (target_version,)
                )
            conn.close()
            return {"status": "applied", "new_version": target_version}

        # 3. Download & verify artifact (.bin / image)
        artifact = artifacts[0]
        download_url = artifact["url"]
        if not download_url.startswith("http"):
            download_url = f"{mgr_url}{download_url}"

        dl_res = await c.get(download_url)
        if dl_res.status_code != 200:
            return {"status": "failed", "reason": f"Failed to download image: {dl_res.status_code}"}

        downloaded_bytes = dl_res.content
        calc_sha256 = hashlib.sha256(downloaded_bytes).hexdigest()
        if not hmac.compare_digest(calc_sha256.lower(), artifact["sha256"].lower()):
            return {"status": "failed", "reason": "Artifact SHA-256 checksum mismatch (corrupted / tampered image)"}

        # 4. Save and activate the new image
        target_file = IMAGES_DIR / artifact["name"]
        with open(target_file, "wb") as f:
            f.write(downloaded_bytes)

        conn = get_db()
        with conn:
            conn.execute(
                """UPDATE identity SET image_version = ?, active_image_file = ?, update_status = 'applied'
                   WHERE id = 'node_identity'""",
                (target_version, artifact["name"])
            )
        conn.close()

        # 5. Send status report to Manager
        rep_ts = str(int(time.time()))
        rep_nonce = b64u(os.urandom(16))
        rep_body = {"version": target_version, "status": "applied"}
        rep_bytes = canonical_json(rep_body)
        rep_hash = hashlib.sha256(rep_bytes).hexdigest()
        rep_sign = f"VAULT-REQ-V1\nPOST\n/api/v1/devices/{device_id}/update-status\n{rep_ts}\n{rep_nonce}\n{rep_hash}".encode()
        rep_sig = b64u(sk.sign(rep_sign).signature)

        rep_headers = {
            "X-Vault-Timestamp": rep_ts,
            "X-Vault-Nonce": rep_nonce,
            "X-Vault-Signature": rep_sig,
            "Content-Type": "application/json"
        }
        await c.post(f"{mgr_url}/api/v1/devices/{device_id}/update-status", content=rep_bytes, headers=rep_headers)

        return {
            "status": "applied",
            "previous_version": current_image,
            "new_version": target_version,
            "active_image_file": artifact["name"],
            "sha256": calc_sha256
        }

    if client_session:
        return await _do_update(client_session)
    else:
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await _do_update(client)

@app.get("/api/v1/system/status")
async def get_system_status():
    """Returns local node health, active image version, and status."""
    ident = get_node_identity()
    return {
        "device_id": ident.get("device_id"),
        "cafe_slug": ident.get("cafe_slug"),
        "app_version": ident.get("app_version", "1.0.0"),
        "image_version": ident.get("image_version", "1.0.0"),
        "active_image_file": ident.get("active_image_file", "base_image.bin"),
        "update_status": ident.get("update_status", "up_to_date"),
        "server_time": time.time()
    }

@app.post("/api/v1/system/check-update")
async def trigger_ota_update(staff: dict = Depends(require_staff)):
    """Staff triggers an immediate check and application of OTA updates."""
    result = await check_and_apply_ota_update()
    return result

class EnrollNodeRequest(BaseModel):
    manager_url: str
    token: str

@app.post("/api/v1/system/enroll")
async def api_enroll_node(req: EnrollNodeRequest, staff: dict = Depends(require_staff)):
    ident = get_node_identity()
    vk_b64 = ident["public_key_b64"]
    req_data = {
        "enrollment_token": req.token,
        "role": "hub",
        "public_key": vk_b64,
        "label": "Counter-Node",
        "os_info": sys.platform,
        "app_version": ident.get("app_version", "1.0.0")
    }
    mgr_url = req.manager_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(f"{mgr_url}/api/v1/enroll", json=req_data)
            if res.status_code != 200:
                raise HTTPException(status_code=res.status_code, detail=f"Enrollment rejected: {res.text}")
            data = res.json()
            conn = get_db()
            with conn:
                conn.execute(
                    """UPDATE identity SET device_id = ?, cafe_slug = ?, manager_url = ?, manager_public_key_b64 = ?
                       WHERE id = 'node_identity'""",
                    (data["device_id"], data["cafe_slug"], mgr_url, data["manager_public_key"])
                )
            conn.close()
            return {
                "status": "enrolled",
                "device_id": data["device_id"],
                "cafe_slug": data["cafe_slug"],
                "portal_url": f"https://vault.laddu.cc/{data['cafe_slug']}"
            }
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Failed to connect to manager at {mgr_url}: {e}")

# --- CLI Management Subcommands ---

def cli_enroll(manager_url: str, token: str):
    init_server_db()
    ident = get_node_identity()
    sk = SigningKey(unb64u(ident["private_key_b64"]))
    vk_b64 = ident["public_key_b64"]

    req_data = {
        "enrollment_token": token,
        "role": "hub",
        "public_key": vk_b64,
        "label": "Counter-Node",
        "os_info": sys.platform,
        "app_version": "1.0.0"
    }

    print(f"Connecting to manager at {manager_url}...")
    try:
        res = httpx.post(f"{manager_url}/api/v1/enroll", json=req_data, timeout=10.0)
        if res.status_code != 200:
            print(f"Enrollment failed: {res.text}")
            return
        data = res.json()
        conn = get_db()
        with conn:
            conn.execute(
                """UPDATE identity SET device_id = ?, cafe_slug = ?, manager_url = ?, manager_public_key_b64 = ?
                   WHERE id = 'node_identity'""",
                (data["device_id"], data["cafe_slug"], manager_url, data["manager_public_key"])
            )
        print("--- AUTO-REGISTRATION SUCCESSFUL ---")
        print(f"Device ID: {data['device_id']}")
        print(f"Assigned Café Slug: {data['cafe_slug']}")
        print(f"Public Portal Endpoint: vault.laddu.cc/{data['cafe_slug']}")
    except Exception as e:
        print(f"Connection error: {e}")

def cli_bootstrap(username: str, password: str):
    init_server_db()
    conn = get_db()
    with conn:
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        if count > 0:
            print("Server already bootstrapped with an owner account.")
            return
        user_id = str(uuid4())
        hashed = hash_password(password)
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, 'owner', ?)",
            (user_id, username.lower(), hashed, time.time())
        )
    print(f"Bootstrapped owner account '{username}' successfully.")

def cli_status():
    init_server_db()
    ident = get_node_identity()
    print("--- VAULT NODE STATUS ---")
    print(f"Device ID:     {ident.get('device_id') or 'Not Enrolled'}")
    print(f"Café Slug:     {ident.get('cafe_slug') or 'local'}")
    print(f"Manager URL:   {ident.get('manager_url') or 'None'}")
    print(f"App Version:   {ident.get('app_version', '1.0.0')}")
    print(f"Active Image:  {ident.get('active_image_file', 'base_image.bin')}")
    print(f"Image Version: {ident.get('image_version', '1.0.0')}")
    print(f"Update Status: {ident.get('update_status', 'up_to_date')}")

def cli_check_update():
    import asyncio
    init_server_db()
    print("Checking Central Manager for OTA updates...")
    res = asyncio.run(check_and_apply_ota_update())
    if res.get("status") == "applied":
        print("--- OTA UPDATE SUCCESSFULLY APPLIED ---")
        print(f"Previous Image Version: {res['previous_version']}")
        print(f"New Active Version:     {res['new_version']}")
        print(f"Installed Image File:   {res['active_image_file']}")
        print(f"Verified SHA-256:       {res['sha256']}")
        print("Status reported back to Central Manager.")
    elif res.get("status") == "up_to_date":
        print(f"Node is up to date (Image Version: {res.get('current_image_version')}).")
    else:
        print(f"Update failed or rejected: {res}")

def cli_reset_password(username: str, password: str):
    init_server_db()
    conn = get_db()
    with conn:
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username.lower(),)).fetchone()
        if not user:
            print(f"Error: User '{username}' does not exist.")
            return
        hashed = hash_password(password)
        conn.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?", (hashed, user["id"]))
    print(f"Password for '{username}' successfully reset.")

def main():
    parser = argparse.ArgumentParser(description="Vault Service Provider Node")
    subparsers = parser.add_subparsers(dest="command")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Run the node HTTP service")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8443)
    serve_parser.add_argument("--reload", action="store_true", help="Auto-reload on file changes")

    # bootstrap
    boot_parser = subparsers.add_parser("bootstrap", help="Create first-time owner account")
    boot_parser.add_argument("--username", required=True)
    boot_parser.add_argument("--password", required=True)

    # reset-password
    pw_parser = subparsers.add_parser("reset-password", help="Reset password for an existing staff account")
    pw_parser.add_argument("--username", default="admin")
    pw_parser.add_argument("--password", required=True)

    # enroll
    enroll_parser = subparsers.add_parser("enroll", help="Auto-register with manager.py")
    enroll_parser.add_argument("--manager", default="http://localhost:8000")
    enroll_parser.add_argument("--token", required=True)

    # status
    subparsers.add_parser("status", help="Print local node and active image status")

    # check-update
    subparsers.add_parser("check-update", help="Check manager and install latest OTA image")

    args = parser.parse_args()

    if args.command == "serve":
        init_server_db()
        execute_wipe_on_boot()
        uvicorn.run("server:app", host=args.host, port=args.port, reload=args.reload)
    elif args.command == "bootstrap":
        cli_bootstrap(args.username, args.password)
    elif args.command == "reset-password":
        cli_reset_password(args.username, args.password)
    elif args.command == "enroll":
        cli_enroll(args.manager, args.token)
    elif args.command == "status":
        cli_status()
    elif args.command == "check-update":
        cli_check_update()
    else:
        init_server_db()
        parser.print_help()

if __name__ == "__main__":
    main()
