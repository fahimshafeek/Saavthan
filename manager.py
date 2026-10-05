"""
manager.py — Vault MVP Central Authority & Fleet Notary

Responsibilities:
1. Device auto-registration & enrollment tokens (business model fleet tracking)
2. Custom endpoint / slug directory (e.g. vault.laddu.cc/mycafe1)
3. Hash-chained transparency log (anti-forgery notarization)
4. Heartbeat collection & fleet telemetry (monitoring shop systems)
5. Release signing & update publishing (automated security patches)
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
import uvicorn
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.responses import FileResponse

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    SigningKey = None
    VerifyKey = None

# --- Cryptographic & Canonical Utilities ---

def canonical_json(data: Any) -> bytes:
    """Deterministic UTF-8 JSON encoding with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def generate_ed25519_keypair():
    sk = SigningKey.generate()
    vk_b64 = b64u(bytes(sk.verify_key))
    return sk, vk_b64

def ed25519_sign(sk: SigningKey, message_bytes: bytes) -> str:
    return b64u(sk.sign(message_bytes).signature)

def ed25519_verify(vk_b64: str, message_bytes: bytes, sig_b64: str) -> bool:
    try:
        VerifyKey(unb64u(vk_b64)).verify(message_bytes, unb64u(sig_b64))
        return True
    except Exception:
        return False

# --- Database & Storage Setup (SQLite) ---

DB_PATH = os.environ.get("VAULT_MANAGER_DB", "manager.db")
RELEASES_STORAGE = Path(os.environ.get("VAULT_RELEASES_DIR", "manager_releases"))
CLOUDFLARE_TUNNEL_URL = os.environ.get("VAULT_TUNNEL_URL", "https://vocals-shakespeare-fragrance-distances.trycloudflare.com").rstrip("/")
LOCAL_HUB_URL = os.environ.get("VAULT_LOCAL_HUB_URL", "http://localhost:8443").rstrip("/")

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    RELEASES_STORAGE.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS server_keys (
            id TEXT PRIMARY KEY,
            private_key_b64 TEXT NOT NULL,
            public_key_b64 TEXT NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cafes (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            owner_email TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            cafe_slug TEXT NOT NULL,
            role TEXT DEFAULT 'hub',
            max_uses INTEGER DEFAULT 1,
            used_count INTEGER DEFAULT 0,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            cafe_slug TEXT NOT NULL,
            role TEXT NOT NULL,
            public_key_b64 TEXT NOT NULL,
            label TEXT,
            os TEXT,
            app_version TEXT,
            image_version TEXT DEFAULT '1.0.0',
            update_status TEXT DEFAULT 'up_to_date',
            status TEXT DEFAULT 'active',
            last_seen REAL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transparency_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            cafe_slug TEXT NOT NULL,
            device_id TEXT NOT NULL,
            entry_json TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hub_sig TEXT NOT NULL,
            manager_sig TEXT NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS releases (
            version TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sig TEXT NOT NULL,
            min_supported_version TEXT NOT NULL,
            published_at REAL NOT NULL
        );
        """)

        # Migration: ensure image_version and update_status exist on devices
        cols = [r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
        if "image_version" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN image_version TEXT DEFAULT '1.0.0'")
        if "update_status" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN update_status TEXT DEFAULT 'up_to_date'")

        # Ensure manager signing key exists
        row = conn.execute("SELECT * FROM server_keys WHERE id = 'manager_key'").fetchone()
        if not row:
            sk = SigningKey.generate()
            sk_b64 = b64u(bytes(sk))
            vk_b64 = b64u(bytes(sk.verify_key))
            conn.execute(
                "INSERT INTO server_keys (id, private_key_b64, public_key_b64, created_at) VALUES (?, ?, ?, ?)",
                ("manager_key", sk_b64, vk_b64, time.time())
            )

    conn.close()

def get_manager_keypair() -> tuple[SigningKey, str]:
    conn = get_db()
    row = conn.execute("SELECT private_key_b64, public_key_b64 FROM server_keys WHERE id = 'manager_key'").fetchone()
    conn.close()
    if not row:
        raise RuntimeError("Manager keys not initialized!")
    sk = SigningKey(unb64u(row["private_key_b64"]))
    return sk, row["public_key_b64"]

# --- Pydantic Request / Response Models ---

class EnrollRequest(BaseModel):
    enrollment_token: str
    role: str = "hub"  # "hub" or "agent"
    public_key: str
    label: Optional[str] = "Shop-Node-1"
    os_info: Optional[str] = "Linux/Windows"
    app_version: str = "1.0.0"

class EnrollResponse(BaseModel):
    device_id: str
    cafe_slug: str
    manager_public_key: str
    heartbeat_interval_s: int = 60

class HeartbeatRequest(BaseModel):
    app_version: str
    image_version: Optional[str] = "1.0.0"
    uptime_s: float
    state: str = "idle"
    last_wipe_ok: bool = True
    pending_wipes: int = 0
    active_sessions: int = 0
    update_status: Optional[str] = "up_to_date"

class UpdateStatusReport(BaseModel):
    version: str
    status: str  # "downloading", "applied", "failed"
    error: Optional[str] = None

class LogEntrySubmit(BaseModel):
    receipt: Dict[str, Any]
    hub_sig: str

class PublishReleaseRequest(BaseModel):
    version: str
    severity: str = "normal"  # "normal", "security", "critical"
    min_supported_version: str = "1.0.0"
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)

# --- FastAPI Application ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Vault Central Manager", version="1.0.0-mvp", lifespan=lifespan)

# Verification helper for Ed25519 signed requests from devices
def verify_device_request(request: Request, body_bytes: bytes, device_id: str, ts: str, nonce: str, sig: str) -> dict:
    conn = get_db()
    device = conn.execute("SELECT * FROM devices WHERE id = ? AND status = 'active'", (device_id,)).fetchone()
    conn.close()
    if not device:
        raise HTTPException(status_code=401, detail="Device not recognized or revoked")

    # Time freshness check (allow +- 120 seconds)
    try:
        req_ts = float(ts)
        if abs(time.time() - req_ts) > 120:
            raise HTTPException(status_code=401, detail="Timestamp expired or clock skewed")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    # Validate signature over canonical request input
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    sign_payload = f"VAULT-REQ-V1\n{request.method.upper()}\n{request.url.path}\n{ts}\n{nonce}\n{body_hash}".encode()

    if not ed25519_verify(device["public_key_b64"], sign_payload, sig):
        raise HTTPException(status_code=401, detail="Invalid request signature")

    return dict(device)

HTML_FILE = Path(__file__).parent / "manager.html"

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    if not HTML_FILE.exists():
        return HTMLResponse("<h1>manager.html not found</h1>", status_code=404)
    return HTMLResponse(HTML_FILE.read_text(encoding="utf-8"))

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "time": time.time()}

@app.get("/.well-known/vault-manager.json")
async def well_known():
    _, pub_key = get_manager_keypair()
    return {"manager_public_key": pub_key, "version": "1.0.0-mvp"}

@app.post("/api/v1/enroll", response_model=EnrollResponse)
async def enroll(req: EnrollRequest):
    """Auto-register a shop node using an enrollment token."""
    token_hash = hashlib.sha256(req.enrollment_token.encode()).hexdigest()
    conn = get_db()
    with conn:
        row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ? AND used_count < max_uses AND expires_at > ?",
            (token_hash, time.time())
        ).fetchone()

        if not row:
            raise HTTPException(status_code=400, detail="Invalid, exhausted or expired enrollment token")

        cafe_slug = row["cafe_slug"]
        device_id = str(uuid4())

        # Atomic increment of token usage
        conn.execute(
            "UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE token_hash = ?",
            (token_hash,)
        )

        conn.execute(
            """INSERT INTO devices (id, cafe_slug, role, public_key_b64, label, os, app_version, image_version, update_status, status, last_seen, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, '1.0.0', 'up_to_date', 'active', ?, ?)""",
            (device_id, cafe_slug, req.role, req.public_key, req.label, req.os_info, req.app_version, time.time(), time.time())
        )

    _, mgr_pub = get_manager_keypair()
    return EnrollResponse(
        device_id=device_id,
        cafe_slug=cafe_slug,
        manager_public_key=mgr_pub,
        heartbeat_interval_s=60
    )

@app.post("/api/v1/devices/{device_id}/heartbeat")
async def heartbeat(
    device_id: str,
    req_body: HeartbeatRequest,
    request: Request,
    x_vault_timestamp: str = Header(...),
    x_vault_nonce: str = Header(...),
    x_vault_signature: str = Header(...)
):
    raw_body = await request.body()
    device = verify_device_request(request, raw_body, device_id, x_vault_timestamp, x_vault_nonce, x_vault_signature)

    conn = get_db()
    with conn:
        conn.execute(
            "UPDATE devices SET last_seen = ?, app_version = ?, image_version = ?, update_status = ? WHERE id = ?",
            (time.time(), req_body.app_version, req_body.image_version, req_body.update_status, device_id)
        )
        # Check latest release
        latest_release = conn.execute(
            "SELECT * FROM releases ORDER BY published_at DESC LIMIT 1"
        ).fetchone()
    conn.close()

    update_offer = None
    if latest_release and latest_release["version"] != req_body.image_version:
        update_offer = {
            "version": latest_release["version"],
            "severity": latest_release["severity"],
            "manifest": json.loads(latest_release["manifest_json"]),
            "sig": latest_release["manifest_sig"]
        }

    return {
        "status": "acknowledged",
        "server_time": time.time(),
        "update": update_offer
    }

@app.post("/api/v1/devices/{device_id}/update-status")
async def report_update_status(
    device_id: str,
    req_body: UpdateStatusReport,
    request: Request,
    x_vault_timestamp: str = Header(...),
    x_vault_nonce: str = Header(...),
    x_vault_signature: str = Header(...)
):
    """Device reports progress and completion of an OTA update."""
    raw_body = await request.body()
    device = verify_device_request(request, raw_body, device_id, x_vault_timestamp, x_vault_nonce, x_vault_signature)
    conn = get_db()
    with conn:
        conn.execute(
            "UPDATE devices SET image_version = ?, update_status = ?, last_seen = ? WHERE id = ?",
            (req_body.version, req_body.status, time.time(), device_id)
        )
    conn.close()
    return {
        "status": "recorded",
        "device_id": device_id,
        "image_version": req_body.version,
        "update_status": req_body.status
    }

@app.get("/api/v1/releases/{version}/download/{filename}")
async def download_release_artifact(version: str, filename: str):
    """Endpoint for shop nodes to download verified .bin / image OTA files."""
    file_path = RELEASES_STORAGE / version / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Release artifact not found")
    return FileResponse(file_path, filename=filename, media_type="application/octet-stream")

@app.post("/api/v1/log/entries")
async def append_transparency_log(
    entry: LogEntrySubmit,
    request: Request,
    x_vault_device: str = Header(...),
    x_vault_timestamp: str = Header(...),
    x_vault_nonce: str = Header(...),
    x_vault_signature: str = Header(...)
):
    """
    Append-only notary: stores receipts in a tamper-evident SHA-256 hash chain.
    No file content is ever stored; only cryptographic receipts and hashes.
    """
    raw_body = await request.body()
    device = verify_device_request(request, raw_body, x_vault_device, x_vault_timestamp, x_vault_nonce, x_vault_signature)

    # 1. Verify hub's digital signature over the receipt
    receipt_bytes = canonical_json(entry.receipt)
    if not ed25519_verify(device["public_key_b64"], receipt_bytes, entry.hub_sig):
        raise HTTPException(status_code=400, detail="Invalid hub receipt signature")

    conn = get_db()
    with conn:
        # Get head of hash chain
        last_entry = conn.execute("SELECT seq, entry_hash FROM transparency_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = last_entry["entry_hash"] if last_entry else "0" * 64

        entry_json_str = json.dumps(entry.receipt, sort_keys=True)
        # Hash chain computation: SHA256(prev_hash || entry_bytes)
        entry_hash = hashlib.sha256(prev_hash.encode() + canonical_json(entry.receipt)).hexdigest()

        # Manager countersignature
        sk, _ = get_manager_keypair()
        sig_data = f"{entry_hash}:{prev_hash}:{time.time()}".encode()
        mgr_sig = ed25519_sign(sk, sig_data)

        cursor = conn.execute(
            """INSERT INTO transparency_log (cafe_slug, device_id, entry_json, entry_hash, prev_hash, hub_sig, manager_sig, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (device["cafe_slug"], x_vault_device, entry_json_str, entry_hash, prev_hash, entry.hub_sig, mgr_sig, time.time())
        )
        seq = cursor.lastrowid

    return {
        "seq": seq,
        "entry_hash": entry_hash,
        "prev_hash": prev_hash,
        "manager_sig": mgr_sig,
        "logged_at": time.time()
    }

@app.get("/api/v1/log/checkpoint")
async def get_log_checkpoint():
    """Returns the signed head of the transparency log."""
    conn = get_db()
    last = conn.execute("SELECT seq, entry_hash, created_at FROM transparency_log ORDER BY seq DESC LIMIT 1").fetchone()
    conn.close()

    if not last:
        return {"seq": 0, "head_hash": "0" * 64, "signed": None}

    sk, _ = get_manager_keypair()
    checkpoint_data = canonical_json({"seq": last["seq"], "head_hash": last["entry_hash"]})
    sig = ed25519_sign(sk, checkpoint_data)

    return {
        "seq": last["seq"],
        "head_hash": last["entry_hash"],
        "timestamp": last["created_at"],
        "manager_sig": sig
    }

@app.get("/api/v1/log/verify")
@app.get("/api/v1/log/verify/{tree_hash}")
async def verify_log_entry(tree_hash: Optional[str] = None):
    """Public dispute verification: checks if a file's tree hash exists in the transparency log."""
    if not tree_hash:
        return {"found": False, "error": "Missing tree_hash parameter"}
    conn = get_db()
    # Receipts store tree_hash inside entry_json
    rows = conn.execute("SELECT seq, entry_hash, prev_hash, entry_json, manager_sig, created_at FROM transparency_log").fetchall()
    conn.close()

    for r in rows:
        receipt = json.loads(r["entry_json"])
        if receipt.get("tree_hash") == tree_hash:
            return {
                "found": True,
                "seq": r["seq"],
                "entry_hash": r["entry_hash"],
                "logged_at": r["created_at"],
                "receipt": receipt
            }

    return {"found": False}

@app.get("/api/v1/admin/fleet")
async def admin_fleet():
    """Fleet status dashboard for the software makers."""
    conn = get_db()
    devices = conn.execute("SELECT id, cafe_slug, role, label, os, app_version, image_version, update_status, status, last_seen, created_at FROM devices").fetchall()
    cafes = conn.execute("SELECT * FROM cafes").fetchall()
    log_count = conn.execute("SELECT COUNT(*) as count FROM transparency_log").fetchone()["count"]
    conn.close()

    return {
        "total_devices": len(devices),
        "total_cafes": len(cafes),
        "notarized_receipts_count": log_count,
        "devices": [dict(d) for d in devices],
        "cafes": [dict(c) for c in cafes]
    }

class CreateCafeRequest(BaseModel):
    slug: str
    name: str
    email: str

class IssueTokenRequest(BaseModel):
    cafe_slug: str
    max_uses: int = 1
    ttl_hours: int = 72

@app.post("/api/v1/admin/cafes")
async def api_create_cafe(req: CreateCafeRequest):
    cli_create_cafe(req.slug, req.name, req.email)
    return {"status": "ok", "slug": req.slug, "name": req.name}

@app.post("/api/v1/admin/tokens")
async def api_issue_token(req: IssueTokenRequest):
    token = cli_issue_token(req.cafe_slug, req.max_uses, req.ttl_hours)
    return {"status": "ok", "token": token, "cafe_slug": req.cafe_slug, "max_uses": req.max_uses}

@app.get("/api/v1/admin/tokens")
async def api_list_tokens():
    conn = get_db()
    rows = conn.execute("SELECT token_hash, cafe_slug, max_uses, used_count, expires_at, created_at FROM enrollment_tokens ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/v1/admin/releases/upload")
async def api_upload_release(
    version: str = Form(...),
    severity: str = Form("normal"),
    file: UploadFile = File(...)
):
    dest_dir = RELEASES_STORAGE / version
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / file.filename
    content = await file.read()
    dest_file.write_bytes(content)
    cli_publish_release(version, str(dest_file), severity)
    return {"status": "published", "version": version, "filename": file.filename}

@app.get("/api/v1/admin/releases")
async def api_list_releases():
    conn = get_db()
    releases = conn.execute("SELECT * FROM releases ORDER BY published_at DESC").fetchall()
    conn.close()
    return [{"version": r["version"], "severity": r["severity"], "manifest": json.loads(r["manifest_json"]), "published_at": r["published_at"]} for r in releases]

@app.get("/api/v1/log/recent")
async def api_recent_logs(limit: int = 25):
    conn = get_db()
    rows = conn.execute("SELECT seq, cafe_slug, device_id, entry_json, entry_hash, prev_hash, hub_sig, manager_sig, created_at FROM transparency_log ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Dynamic Cafe Slug Router (Maps localhost:8000/<slug> to Cloudflare / Local Hub) ---

@app.api_route("/{slug}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
@app.api_route("/{slug}/", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
@app.api_route("/{slug}/{rest_of_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def route_cafe_to_tunnel(slug: str, request: Request, rest_of_path: Optional[str] = None):
    """
    Routes customer/staff requests for a cafe slug (e.g. /mycafe1 or /mycafe1/d/123)
    from Manager to the Cloudflare Tunnel URL (which terminates at localhost:8443).
    Supports transparent reverse proxying when X-Vault-Proxy header or ?proxy=1 is set.
    """
    # Guard against reserved manager paths
    if slug in ("api", "healthz", "static", ".well-known", "favicon.ico"):
        raise HTTPException(status_code=404, detail="Not found")

    subpath = f"/{rest_of_path}" if rest_of_path else ""
    query = f"?{request.url.query}" if request.url.query else ""
    target_url = f"{CLOUDFLARE_TUNNEL_URL}/{slug}{subpath}{query}"

    # If proxy is requested explicitly via header or query param
    if request.headers.get("X-Vault-Proxy") == "1" or request.query_params.get("proxy") == "1":
        local_target = f"{LOCAL_HUB_URL}/{slug}{subpath}{query}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                proxied_res = await client.request(
                    method=request.method,
                    url=local_target,
                    headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")},
                    content=await request.body()
                )
                return Response(
                    content=proxied_res.content,
                    status_code=proxied_res.status_code,
                    headers={k: v for k, v in proxied_res.headers.items() if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")}
                )
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Failed to proxy to local hub: {e}")

    return RedirectResponse(url=target_url, status_code=307)

# --- CLI Management Subcommands ---

def cli_create_cafe(slug: str, name: str, email: str):
    init_db()
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO cafes (id, name, slug, owner_email, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid4()), name, slug, email, time.time())
        )
    print(f"Created Café '{name}' with slug '{slug}' and owner <{email}>")

def cli_issue_token(cafe_slug: str, max_uses: int = 1, ttl_hours: int = 72) -> str:
    init_db()
    raw_token = b64u(os.urandom(24))
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = time.time() + (ttl_hours * 3600)

    conn = get_db()
    with conn:
        # Check cafe exists
        c = conn.execute("SELECT slug FROM cafes WHERE slug = ?", (cafe_slug,)).fetchone()
        if not c:
            conn.execute(
                "INSERT INTO cafes (id, name, slug, owner_email, created_at) VALUES (?, ?, ?, ?, ?)",
                (str(uuid4()), cafe_slug.title(), cafe_slug, f"owner@{cafe_slug}.cc", time.time())
            )
        conn.execute(
            "INSERT INTO enrollment_tokens (token_hash, cafe_slug, max_uses, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (token_hash, cafe_slug, max_uses, expires_at, time.time())
        )

    print(f"--- ENROLLMENT TOKEN ISSUED FOR [{cafe_slug}] ---")
    print(f"Token: {raw_token}")
    print(f"Valid for: {max_uses} uses until {time.ctime(expires_at)}")
    return raw_token

def cli_publish_release(version: str, file_path: Optional[str] = None, severity: str = "normal"):
    init_db()
    sk, _ = get_manager_keypair()
    artifacts = []

    if file_path:
        src = Path(file_path)
        if not src.exists():
            print(f"Error: file '{file_path}' does not exist.")
            return
        dest_dir = RELEASES_STORAGE / version
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / src.name
        if src.resolve() != dest_file.resolve():
            shutil.copy2(src, dest_file)
        data = dest_file.read_bytes()
        sha256_hex = hashlib.sha256(data).hexdigest()
        artifacts.append({
            "name": src.name,
            "sha256": sha256_hex,
            "size": len(data),
            "url": f"/api/v1/releases/{version}/download/{src.name}"
        })

    manifest = {
        "version": version,
        "severity": severity,
        "published_at": time.time(),
        "min_supported_version": "1.0.0",
        "artifacts": artifacts
    }
    manifest_bytes = canonical_json(manifest)
    sig = ed25519_sign(sk, manifest_bytes)

    conn = get_db()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO releases (version, severity, manifest_json, manifest_sig, min_supported_version, published_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (version, severity, json.dumps(manifest), sig, "1.0.0", time.time())
        )
    conn.close()
    art_info = f" with image artifact '{artifacts[0]['name']}' (SHA256={artifacts[0]['sha256'][:16]}...)" if artifacts else ""
    print(f"Published Release {version} (severity={severity}){art_info} signed by Manager!")

def main():
    parser = argparse.ArgumentParser(description="Vault Central Manager")
    subparsers = parser.add_subparsers(dest="command")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Run the Manager HTTP service")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true", help="Auto-reload on code change")

    # create-cafe
    cafe_parser = subparsers.add_parser("create-cafe", help="Register a new Akshaya/cafe tenant")
    cafe_parser.add_argument("--slug", required=True)
    cafe_parser.add_argument("--name", required=True)
    cafe_parser.add_argument("--email", default="admin@cafe.cc")

    # issue-token
    token_parser = subparsers.add_parser("issue-token", help="Issue an enrollment token")
    token_parser.add_argument("--cafe", required=True)
    token_parser.add_argument("--max-uses", type=int, default=1)
    token_parser.add_argument("--ttl", type=int, default=72)

    # publish-release
    rel_parser = subparsers.add_parser("publish-release", help="Sign and publish a security update")
    rel_parser.add_argument("--version", required=True)
    rel_parser.add_argument("--file", help="Path to .bin or image file to publish")
    rel_parser.add_argument("--severity", default="normal")

    # list-devices
    subparsers.add_parser("list-devices", help="List enrolled devices")

    args = parser.parse_args()

    if args.command == "serve":
        init_db()
        uvicorn.run("manager:app", host=args.host, port=args.port, reload=args.reload)
    elif args.command == "create-cafe":
        cli_create_cafe(args.slug, args.name, args.email)
    elif args.command == "issue-token":
        cli_issue_token(args.cafe, args.max_uses, args.ttl)
    elif args.command == "publish-release":
        cli_publish_release(args.version, args.file, args.severity)
    elif args.command == "list-devices":
        init_db()
        conn = get_db()
        devs = conn.execute("SELECT * FROM devices").fetchall()
        print(f"--- ENROLLED FLEET DEVICES ({len(devs)}) ---")
        for d in devs:
            img = d["image_version"] if "image_version" in d.keys() else "1.0.0"
            up_st = d["update_status"] if "update_status" in d.keys() else "up_to_date"
            last_s = time.ctime(d['last_seen']) if d['last_seen'] else 'Never'
            print(f"[{d['id'][:8]}] Cafe: {d['cafe_slug']:<12} | Role: {d['role']:<6} | App: {d['app_version']} | Image: {img:<8} | Status: {up_st:<12} | Last Seen: {last_s}")
        conn.close()
    else:
        init_db()
        parser.print_help()

if __name__ == "__main__":
    main()
