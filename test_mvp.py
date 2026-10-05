"""
test_mvp.py — Complete End-to-End Test Suite for Vault MVP (manager.py & server.py)

Covers all 6 requirements:
1. Backend login & Argon2id password hashing + lockout
2. Custom endpoint generation & drop creation
3. Auto-registration of shop nodes via enrollment token + heartbeats
4. Anti-forgery chunked upload, AES-256-GCM encryption, receipts, and transparency log
5. Ephemeral kiosk workspace creation & verified wipe engine
6. Wipe-on-boot crash recovery
7. Negative & tamper test suite
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

# Import the two MVP modules
import manager
import server

@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Isolates each test with temporary directories and databases."""
    mgr_db = str(tmp_path / "test_manager.db")
    server_dir = tmp_path / "server_data"

    monkeypatch.setenv("VAULT_MANAGER_DB", mgr_db)
    monkeypatch.setattr(manager, "DB_PATH", mgr_db)

    monkeypatch.setattr(server, "DATA_DIR", server_dir)
    monkeypatch.setattr(server, "DB_PATH", server_dir / "server.db")
    monkeypatch.setattr(server, "STAGING_DIR", server_dir / "staging")
    monkeypatch.setattr(server, "WORKSPACES_DIR", server_dir / "workspaces")

    manager.init_db()
    server.init_server_db()

    yield

@pytest.mark.asyncio
async def test_full_vault_lifecycle():
    # 1. Manager Setup & Issue Token
    cafe_slug = "mycafe1"
    manager.cli_create_cafe(cafe_slug, "My Akshaya Center 1", "owner@mycafe1.cc")
    raw_token = manager.cli_issue_token(cafe_slug, max_uses=1, ttl_hours=24)
    assert len(raw_token) > 20

    # Create test async clients for both ASGI apps
    mgr_transport = ASGITransport(app=manager.app)
    server_transport = ASGITransport(app=server.app)

    async with AsyncClient(transport=mgr_transport, base_url="http://testmanager") as mgr_client, \
               AsyncClient(transport=server_transport, base_url="http://testserver") as srv_client:

        # 2. Staff Bootstrap & Password Hashing (Argon2id)
        boot_res = await srv_client.post("/api/v1/auth/bootstrap", json={
            "username": "owner",
            "password": "CorrectSuperSecretPassword123!"
        })
        assert boot_res.status_code == 200

        # Test invalid password failure
        bad_login = await srv_client.post("/api/v1/auth/login", json={
            "username": "owner",
            "password": "WrongPassword!"
        })
        assert bad_login.status_code == 401

        # Test valid login
        good_login = await srv_client.post("/api/v1/auth/login", json={
            "username": "owner",
            "password": "CorrectSuperSecretPassword123!"
        })
        assert good_login.status_code == 200
        auth_data = good_login.json()
        token = auth_data["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        # 3. Auto-Registration / Enrollment with Manager (Requirement 3)
        ident = server.get_node_identity()
        enroll_res = await mgr_client.post("/api/v1/enroll", json={
            "enrollment_token": raw_token,
            "role": "hub",
            "public_key": ident["public_key_b64"],
            "label": "Counter-1",
            "os_info": "Linux-Test",
            "app_version": "1.0.0"
        })
        assert enroll_res.status_code == 200
        enroll_data = enroll_res.json()
        assert enroll_data["cafe_slug"] == cafe_slug
        device_id = enroll_data["device_id"]

        # Save enrolled identity on the server node
        conn = server.get_db()
        with conn:
            conn.execute(
                """UPDATE identity SET device_id = ?, cafe_slug = ?, manager_url = 'http://testmanager', manager_public_key_b64 = ?
                   WHERE id = 'node_identity'""",
                (device_id, cafe_slug, enroll_data["manager_public_key"])
            )
        conn.close()

        # Check token exhaustion (single use)
        replayed_enroll = await mgr_client.post("/api/v1/enroll", json={
            "enrollment_token": raw_token,
            "role": "hub",
            "public_key": ident["public_key_b64"]
        })
        assert replayed_enroll.status_code == 400

        # 4. Custom Endpoint / Drop Generation (Requirement 2)
        drop_res = await srv_client.post("/api/v1/drops", json={
            "label": "Passport Application Files",
            "max_bytes": 50 * 1024 * 1024,
            "ttl_minutes": 60
        }, headers=auth_headers)
        assert drop_res.status_code == 200
        drop_data = drop_res.json()
        drop_code = drop_data["drop_code"]
        assert f"vault.laddu.cc/{cafe_slug}/d/{drop_code}" in drop_data["portal_url"]

        # 5. Remote Customer Uploads File in Chunks (Requirement 4)
        file_payload = b"Top secret passport citizen data that must be obliterated after printing!" * 1000
        total_size = len(file_payload)
        chunk_size = 16 * 1024  # 16 KB chunks for testing

        init_res = await srv_client.post(f"/p/{drop_code}/uploads", json={
            "display_name": "passport_application.pdf",
            "size": total_size,
            "chunk_size": chunk_size
        })
        assert init_res.status_code == 200
        upload_data = init_res.json()
        upload_id = upload_data["upload_id"]
        total_chunks = upload_data["total_chunks"]

        # Upload each chunk with SHA-256 header
        chunk_digests = []
        for idx in range(total_chunks):
            start = idx * chunk_size
            end = min(start + chunk_size, total_size)
            chunk_data = file_payload[start:end]
            c_digest = hashlib.sha256(chunk_data).hexdigest()
            chunk_digests.append(c_digest)

            chunk_res = await srv_client.put(
                f"/p/{drop_code}/uploads/{upload_id}/chunks/{idx}",
                content=chunk_data,
                headers={"X-Chunk-SHA256": c_digest}
            )
            assert chunk_res.status_code == 200

            # Verify chunk is stored AES-256-GCM encrypted on disk (not plaintext)
            chunk_file = server.STAGING_DIR / upload_id / f"{idx}.chunk"
            assert chunk_file.exists()
            assert chunk_data not in chunk_file.read_bytes()  # Encrypted!

        # Calculate expected tree hash
        expected_tree = server.tree_hash(
            [bytes.fromhex(d) for d in chunk_digests],
            total_size,
            chunk_size
        )

        # 6. Complete Upload & Issue Signed Digital Receipt (Requirement 4 & Anti-Forgery)
        complete_res = await srv_client.post(f"/p/{drop_code}/uploads/{upload_id}/complete", json={
            "chunk_digests": chunk_digests,
            "tree_hash": expected_tree
        })
        assert complete_res.status_code == 200
        complete_data = complete_res.json()
        assert complete_data["status"] == "verified"
        assert complete_data["receipt"]["tree_hash"] == expected_tree

        # Verify receipt signature with server's public key
        hub_pub = complete_data["receipt"]["hub_public_key"]
        receipt_bytes = server.canonical_json(complete_data["receipt"])
        assert manager.ed25519_verify(hub_pub, receipt_bytes, complete_data["hub_sig"]) is True

        # 7. Verify Transparency Log Notarization on Manager
        sk = manager.SigningKey(manager.unb64u(ident["private_key_b64"]))
        ts = str(int(time.time()))
        nonce = manager.b64u(os.urandom(16))
        log_payload = {"receipt": complete_data["receipt"], "hub_sig": complete_data["hub_sig"]}
        body_bytes = manager.canonical_json(log_payload)
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        sign_str = f"VAULT-REQ-V1\nPOST\n/api/v1/log/entries\n{ts}\n{nonce}\n{body_hash}".encode()
        sig = manager.b64u(sk.sign(sign_str).signature)

        log_res = await mgr_client.post(
            "/api/v1/log/entries",
            content=body_bytes,
            headers={
                "X-Vault-Device": device_id,
                "X-Vault-Timestamp": ts,
                "X-Vault-Nonce": nonce,
                "X-Vault-Signature": sig,
                "Content-Type": "application/json"
            }
        )
        assert log_res.status_code == 200
        log_data = log_res.json()
        assert log_data["seq"] >= 1

        # Check public dispute verification on Manager
        verify_res = await mgr_client.get(f"/api/v1/log/verify?tree_hash={expected_tree}")
        assert verify_res.status_code == 200
        assert verify_res.json()["found"] is True

        # 8. Ephemeral Kiosk Session & Wipe Engine (Core Promise / Requirement 4.5)
        sess_res = await srv_client.post("/api/v1/session/start", headers=auth_headers)
        assert sess_res.status_code == 200
        sess_data = sess_res.json()
        session_id = sess_data["session_id"]
        ws_path = Path(sess_data["workspace_path"])
        assert ws_path.exists()

        # Deliver file strictly into session workspace
        deliver_res = await srv_client.post(
            f"/api/v1/session/{session_id}/deliver/{upload_id}",
            headers=auth_headers
        )
        assert deliver_res.status_code == 200
        delivered_file = ws_path / "passport_application.pdf"
        assert delivered_file.exists()
        assert delivered_file.read_bytes() == file_payload  # Plaintext intact in workspace!

        # End session -> Wipe engine triggers
        end_res = await srv_client.post(
            f"/api/v1/session/{session_id}/end",
            headers=auth_headers
        )
        assert end_res.status_code == 200
        assert end_res.json()["status"] == "obliterated"
        assert end_res.json()["wipe_verified"] is True

        # Verify physical absence of workspace
        assert not ws_path.exists()
        assert not delivered_file.exists()

        # Check pending wipes table is empty
        conn = server.get_db()
        pending = conn.execute("SELECT * FROM pending_wipes").fetchall()
        assert len(pending) == 0
        conn.close()

@pytest.mark.asyncio
async def test_wipe_on_boot_recovery():
    """Simulates a sudden power loss mid-session and proves wipe-on-boot obliterates leaked data."""
    fake_session_id = str(uuid4())
    fake_ws = server.WORKSPACES_DIR / fake_session_id
    fake_ws.mkdir(parents=True, exist_ok=True)
    leaked_canary = fake_ws / "confidential_aadhaar.txt"
    leaked_canary.write_text("SENSITIVE CITIZEN RECORD")

    # Manually inject into pending_wipes as if the power failed before end_session
    conn = server.get_db()
    with conn:
        conn.execute(
            "INSERT INTO sessions (id, workspace_path, status, started_at) VALUES (?, ?, 'active', ?)",
            (fake_session_id, str(fake_ws), time.time())
        )
        conn.execute(
            "INSERT INTO pending_wipes (session_id, workspace_path, created_at) VALUES (?, ?, ?)",
            (fake_session_id, str(fake_ws), time.time())
        )
    conn.close()

    assert leaked_canary.exists()

    # Trigger wipe-on-boot engine
    server.execute_wipe_on_boot()

    # Assert complete obliteration
    assert not fake_ws.exists()
    assert not leaked_canary.exists()

    conn = server.get_db()
    pending = conn.execute("SELECT * FROM pending_wipes").fetchall()
    assert len(pending) == 0
    conn.close()

@pytest.mark.asyncio
async def test_tamper_detection():
    """Ensures chunk corruption or tree hash manipulation is blocked."""
    server_transport = ASGITransport(app=server.app)

    async with AsyncClient(transport=server_transport, base_url="http://testserver") as srv_client:
        # Bootstrap & login
        await srv_client.post("/api/v1/auth/bootstrap", json={"username": "admin", "password": "Password123!"})
        login_res = await srv_client.post("/api/v1/auth/login", json={"username": "admin", "password": "Password123!"})
        auth_headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

        # Create drop
        drop_res = await srv_client.post("/api/v1/drops", json={"label": "Tamper Test"}, headers=auth_headers)
        code = drop_res.json()["drop_code"]

        init_res = await srv_client.post(f"/p/{code}/uploads", json={"display_name": "file.txt", "size": 100, "chunk_size": 100})
        upload_id = init_res.json()["upload_id"]

        # Upload with bit flip / hash mismatch
        bad_chunk = await srv_client.put(
            f"/p/{code}/uploads/{upload_id}/chunks/0",
            content=b"CORRUPTED_BYTES",
            headers={"X-Chunk-SHA256": "0" * 64}  # Wrong hash
        )
        assert bad_chunk.status_code == 422  # Hash mismatch error!

        # Complete with wrong tree hash
        valid_chunk_digest = hashlib.sha256(b"VALID_BYTES").hexdigest()
        good_chunk = await srv_client.put(
            f"/p/{code}/uploads/{upload_id}/chunks/0",
            content=b"VALID_BYTES",
            headers={"X-Chunk-SHA256": valid_chunk_digest}
        )
        assert good_chunk.status_code == 200

        bad_tree_res = await srv_client.post(
            f"/p/{code}/uploads/{upload_id}/complete",
            json={"chunk_digests": [valid_chunk_digest], "tree_hash": "f" * 64}
        )
        assert bad_tree_res.status_code == 409  # Conflict / Tree hash mismatch!

@pytest.mark.asyncio
async def test_account_lockout():
    """Validates that 5 successive invalid login attempts trigger temporary account lockout."""
    server_transport = ASGITransport(app=server.app)

    async with AsyncClient(transport=server_transport, base_url="http://testserver") as srv_client:
        await srv_client.post("/api/v1/auth/bootstrap", json={"username": "lockout_user", "password": "Password123!"})

        for i in range(5):
            res = await srv_client.post("/api/v1/auth/login", json={"username": "lockout_user", "password": "WrongPassword!"})
            assert res.status_code == 401

        # 6th attempt should return 429 Too Many Requests (Lockout)
        locked_res = await srv_client.post("/api/v1/auth/login", json={"username": "lockout_user", "password": "Password123!"})
        assert locked_res.status_code == 429
        assert "Account temporarily locked" in locked_res.json()["detail"]

@pytest.mark.asyncio
async def test_heartbeat_and_release_updates():
    """Validates fleet heartbeat and update offers when new releases are published."""
    cafe_slug = "heartbeat_cafe"
    manager.cli_create_cafe(cafe_slug, "Heartbeat Cafe", "hb@cafe.cc")
    token = manager.cli_issue_token(cafe_slug)

    mgr_transport = ASGITransport(app=manager.app)
    async with AsyncClient(transport=mgr_transport, base_url="http://testmanager") as mgr_client:
        sk, vk_b64 = manager.generate_ed25519_keypair()

        # Enroll
        enroll_res = await mgr_client.post("/api/v1/enroll", json={
            "enrollment_token": token,
            "role": "hub",
            "public_key": vk_b64,
            "app_version": "1.0.0"
        })
        assert enroll_res.status_code == 200
        device_id = enroll_res.json()["device_id"]

        # 1. Publish Release 1.2.0 on Manager
        manager.cli_publish_release("1.2.0", severity="security")

        # 2. Send Heartbeat from device with version 1.0.0
        ts = str(int(time.time()))
        nonce = manager.b64u(os.urandom(16))
        hb_body = {"app_version": "1.0.0", "uptime_s": 120.0, "state": "idle", "last_wipe_ok": True, "pending_wipes": 0, "active_sessions": 0}
        body_bytes = manager.canonical_json(hb_body)
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        sign_str = f"VAULT-REQ-V1\nPOST\n/api/v1/devices/{device_id}/heartbeat\n{ts}\n{nonce}\n{body_hash}".encode()
        sig = manager.b64u(sk.sign(sign_str).signature)

        hb_res = await mgr_client.post(
            f"/api/v1/devices/{device_id}/heartbeat",
            content=body_bytes,
            headers={
                "X-Vault-Timestamp": ts,
                "X-Vault-Nonce": nonce,
                "X-Vault-Signature": sig,
                "Content-Type": "application/json"
            }
        )
        assert hb_res.status_code == 200
        hb_data = hb_res.json()
        assert hb_data["status"] == "acknowledged"
        assert hb_data["update"] is not None
        assert hb_data["update"]["version"] == "1.2.0"
        assert hb_data["update"]["severity"] == "security"

        # Check Fleet view
        fleet_res = await mgr_client.get("/api/v1/admin/fleet")
        assert fleet_res.status_code == 200
        assert fleet_res.json()["total_devices"] >= 1

@pytest.mark.asyncio
async def test_ota_binary_image_update_workflow(tmp_path):
    """
    Validates end-to-end OTA workflow:
    1. Manager publishes patch .bin image
    2. Client node downloads and verifies image
    3. Client applies update & activates new image
    4. Client reports 'applied' status
    5. Manager fleet view reflects new version and status
    """
    cafe_slug = "ota_cafe"
    manager.cli_create_cafe(cafe_slug, "OTA Akshaya Center", "ota@cafe.cc")
    token = manager.cli_issue_token(cafe_slug)

    mgr_transport = ASGITransport(app=manager.app)
    server_transport = ASGITransport(app=server.app)

    async with AsyncClient(transport=mgr_transport, base_url="http://testmanager") as mgr_client, \
               AsyncClient(transport=server_transport, base_url="http://testserver") as srv_client:

        # 1. Enroll Node
        ident = server.get_node_identity()
        enroll_res = await mgr_client.post("/api/v1/enroll", json={
            "enrollment_token": token,
            "role": "hub",
            "public_key": ident["public_key_b64"],
            "app_version": "1.0.0"
        })
        assert enroll_res.status_code == 200
        enroll_data = enroll_res.json()
        device_id = enroll_data["device_id"]

        conn = server.get_db()
        with conn:
            conn.execute(
                """UPDATE identity SET device_id = ?, cafe_slug = ?, manager_url = 'http://testmanager', manager_public_key_b64 = ?
                   WHERE id = 'node_identity'""",
                (device_id, cafe_slug, enroll_data["manager_public_key"])
            )
        conn.close()

        # Check initial status on server
        status_res = await srv_client.get("/api/v1/system/status")
        assert status_res.status_code == 200
        assert status_res.json()["image_version"] == "1.0.0"
        assert status_res.json()["active_image_file"] == "base_image.bin"

        # 2. Manager creates and publishes a vulnerability patch binary (.bin)
        patch_file = tmp_path / "vault_kiosk_patch_v2.0.0.bin"
        patch_file.write_bytes(b"SECURITY_PATCH_BINARY_IMAGE_CONTENTS_V2_0_0")
        manager.cli_publish_release("2.0.0", file_path=str(patch_file), severity="security")

        # 3. Client node triggers OTA update
        update_result = await server.check_and_apply_ota_update(client_session=mgr_client)
        assert update_result["status"] == "applied"
        assert update_result["new_version"] == "2.0.0"
        assert update_result["active_image_file"] == "vault_kiosk_patch_v2.0.0.bin"

        # Verify new image exists on server disk
        installed_image = server.IMAGES_DIR / "vault_kiosk_patch_v2.0.0.bin"
        assert installed_image.exists()
        assert installed_image.read_bytes() == b"SECURITY_PATCH_BINARY_IMAGE_CONTENTS_V2_0_0"

        # 4. Verify client node reflects new version in status endpoint
        new_status = await srv_client.get("/api/v1/system/status")
        assert new_status.json()["image_version"] == "2.0.0"
        assert new_status.json()["active_image_file"] == "vault_kiosk_patch_v2.0.0.bin"
        assert new_status.json()["update_status"] == "applied"

        # 5. Verify Manager's fleet view reflects the update from the client!
        fleet_res = await mgr_client.get("/api/v1/admin/fleet")
        assert fleet_res.status_code == 200
        dev_list = fleet_res.json()["devices"]
        my_dev = next(d for d in dev_list if d["id"] == device_id)
        assert my_dev["image_version"] == "2.0.0"
        assert my_dev["update_status"] == "applied"

        # 6. Subsequent check should report 'up_to_date'
        repeat_check = await server.check_and_apply_ota_update(client_session=mgr_client)
        assert repeat_check["status"] == "up_to_date"

@pytest.mark.asyncio
async def test_ui_and_helper_endpoints(tmp_path):
    """Verifies that manager.html and server.html are properly served, and all helper endpoints function."""
    cafe_slug = "uitestcafe"
    manager.cli_create_cafe(cafe_slug, "UI Test Café", "ui@cafe.cc")
    raw_token = manager.cli_issue_token(cafe_slug, max_uses=2, ttl_hours=24)

    mgr_transport = ASGITransport(app=manager.app)
    server_transport = ASGITransport(app=server.app)

    async with AsyncClient(transport=mgr_transport, base_url="http://testmanager") as mgr_client, \
               AsyncClient(transport=server_transport, base_url="http://testserver") as srv_client:

        # 1. Test manager UI HTML serving
        mgr_ui_res = await mgr_client.get("/")
        assert mgr_ui_res.status_code == 200
        assert "text/html" in mgr_ui_res.headers["content-type"]
        assert "Central Maker Console" in mgr_ui_res.text
        assert "pane-transparency" in mgr_ui_res.text

        # 2. Test manager tokens listing
        tokens_res = await mgr_client.get("/api/v1/admin/tokens")
        assert tokens_res.status_code == 200
        tokens_list = tokens_res.json()
        assert len(tokens_list) >= 1
        assert tokens_list[0]["cafe_slug"] == cafe_slug

        # 3. Test server UI HTML serving
        srv_ui_res = await srv_client.get("/")
        assert srv_ui_res.status_code == 200
        assert "text/html" in srv_ui_res.headers["content-type"]
        assert "Privacy Kiosk Hub & Secure Portal" in srv_ui_res.text
        assert "view-customer-portal" in srv_ui_res.text

        # 4. Check auth status endpoint before bootstrap
        auth_st = await srv_client.get("/api/v1/auth/status")
        assert auth_st.status_code == 200
        assert auth_st.json()["bootstrapped"] is False

        # Bootstrap server
        await srv_client.post("/api/v1/auth/bootstrap", json={
            "username": "uimanager",
            "password": "ValidPassword999!"
        })

        # Check auth status endpoint after bootstrap
        auth_st2 = await srv_client.get("/api/v1/auth/status")
        assert auth_st2.json()["bootstrapped"] is True

        # Login
        login_res = await srv_client.post("/api/v1/auth/login", json={
            "username": "uimanager",
            "password": "ValidPassword999!"
        })
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 5. Check auth/me endpoint
        me_res = await srv_client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["username"] == "uimanager"

        # 5b. Test staff signup / registration
        reg_res = await srv_client.post("/api/v1/auth/register", json={
            "username": "staff_operator_1",
            "password": "StaffPassword123!"
        })
        assert reg_res.status_code == 200
        assert reg_res.json()["role"] == "staff"

        # Login as new staff
        staff_login_res = await srv_client.post("/api/v1/auth/login", json={
            "username": "staff_operator_1",
            "password": "StaffPassword123!"
        })
        assert staff_login_res.status_code == 200
        staff_token = staff_login_res.json()["access_token"]
        assert staff_login_res.json()["role"] == "staff"

        # List staff team members
        users_res = await srv_client.get("/api/v1/users", headers=headers)
        assert users_res.status_code == 200
        users = users_res.json()
        assert len(users) >= 2
        assert any(u["username"] == "uimanager" and u["role"] == "owner" for u in users)
        assert any(u["username"] == "staff_operator_1" and u["role"] == "staff" for u in users)

        # 6. Create drop & test list_drops helper (with cloudflare tunnel url)
        drop_res = await srv_client.post("/api/v1/drops", json={
            "label": "Test Passport Scan",
            "max_bytes": 50 * 1024 * 1024,
            "ttl_minutes": 30
        }, headers=headers)
        drop_code = drop_res.json()["drop_code"]
        assert "vocals-shakespeare-fragrance-distances.trycloudflare.com" in drop_res.json()["tunnel_url"]
        assert "vault.laddu.cc" in drop_res.json()["vanity_url"]

        drops_list_res = await srv_client.get("/api/v1/drops", headers=headers)
        assert drops_list_res.status_code == 200
        drops = drops_list_res.json()
        assert any(d["code"] == drop_code for d in drops)

        # 7. Test Customer Portal HTML serving at both /p/{code} and /{slug}/d/{code}
        portal_html_res = await srv_client.get(f"/p/{drop_code}", headers={"Accept": "text/html"})
        assert portal_html_res.status_code == 200
        assert "text/html" in portal_html_res.headers["content-type"]
        assert "view-customer-portal" in portal_html_res.text

        tunnel_html_res = await srv_client.get(f"/mycafe/d/{drop_code}", headers={"Accept": "text/html"})
        assert tunnel_html_res.status_code == 200
        assert "text/html" in tunnel_html_res.headers["content-type"]
        assert "view-customer-portal" in tunnel_html_res.text

        # 8. Test list sessions & obliteration
        sess_res = await srv_client.post("/api/v1/session/start", headers=headers)
        sess_id = sess_res.json()["session_id"]

        sessions_list = await srv_client.get("/api/v1/sessions", headers=headers)
        assert sessions_list.status_code == 200
        assert any(s["id"] == sess_id and s["status"] == "active" for s in sessions_list.json())

        # Obliterate session
        end_res = await srv_client.post(f"/api/v1/session/{sess_id}/end", headers=headers)
        assert end_res.status_code == 200
        assert end_res.json()["wipe_verified"] is True

        sessions_after = await srv_client.get("/api/v1/sessions", headers=headers)
        ended_sess = next(s for s in sessions_after.json() if s["id"] == sess_id)
        assert ended_sess["status"] == "wiped"
        assert ended_sess["has_pending_wipe"] is False

        # 9. Test close drop helper
        close_res = await srv_client.post(f"/api/v1/drops/{drop_code}/close", headers=headers)
        assert close_res.status_code == 200
        assert close_res.json()["status"] == "closed"

        # 10. Test Manager OTA multipart upload endpoint
        patch_content = b"TEST_OTA_MULTIPART_IMAGE_CONTENT"
        files = {"file": ("ota_patch.bin", patch_content, "application/octet-stream")}
        upload_rel_res = await mgr_client.post("/api/v1/admin/releases/upload", data={"version": "3.0.0", "severity": "critical"}, files=files)
        assert upload_rel_res.status_code == 200
        assert upload_rel_res.json()["version"] == "3.0.0"

        # Check releases list
        rel_list_res = await mgr_client.get("/api/v1/admin/releases")
        assert rel_list_res.status_code == 200
        assert any(r["version"] == "3.0.0" for r in rel_list_res.json())

        # 11. Test Public Dispute Verifier on manager (both path and query parameter)
        # Not found case
        fake_hash = "0" * 64
        verif_fake = await mgr_client.get(f"/api/v1/log/verify/{fake_hash}")
        assert verif_fake.status_code == 200
        assert verif_fake.json()["found"] is False

        verif_query = await mgr_client.get(f"/api/v1/log/verify?tree_hash={fake_hash}")
        assert verif_query.status_code == 200
        assert verif_query.json()["found"] is False

        # 12. Test Manager mapping localhost:8000/<slug> to Cloudflare URL
        slug_res = await mgr_client.get("/mycafe1")
        assert slug_res.status_code == 307
        assert slug_res.headers["location"] == "https://vocals-shakespeare-fragrance-distances.trycloudflare.com/mycafe1"

        slug_drop_res = await mgr_client.get(f"/mycafe1/d/{drop_code}")
        assert slug_drop_res.status_code == 307
        assert slug_drop_res.headers["location"] == f"https://vocals-shakespeare-fragrance-distances.trycloudflare.com/mycafe1/d/{drop_code}"

        # Test Server Hub UI serving directly on /{slug}
        srv_slug_res = await srv_client.get("/mycafe1")
        assert srv_slug_res.status_code == 200
        assert "view-customer-portal" in srv_slug_res.text or "VAULT" in srv_slug_res.text


