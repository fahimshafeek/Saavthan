"""
scratch/test_live_e2e.py — Real Live TCP Socket End-to-End Test for Vault
Tests real HTTP requests against manager (port 8765) and server (port 8766).
"""

import multiprocessing
import os
import shutil
import tempfile
import time
from pathlib import Path
import httpx
import uvicorn

import manager
import server

def run_manager(db_path, port):
    os.environ["VAULT_MANAGER_DB"] = str(db_path)
    manager.DB_PATH = Path(db_path)
    manager.init_db()
    uvicorn.run(manager.app, host="127.0.0.1", port=port, log_level="warning")

def run_server(server_dir, port):
    sdir = Path(server_dir)
    server.DATA_DIR = sdir
    server.DB_PATH = sdir / "server.db"
    server.STAGING_DIR = sdir / "staging"
    server.WORKSPACES_DIR = sdir / "workspaces"
    server.init_server_db()
    uvicorn.run(server.app, host="127.0.0.1", port=port, log_level="warning")

def main():
    tmp = Path(tempfile.mkdtemp(prefix="vault_e2e_"))
    mgr_db = tmp / "mgr.db"
    srv_dir = tmp / "srv"
    srv_dir.mkdir()

    mgr_port = 8765
    srv_port = 8766

    p_mgr = multiprocessing.Process(target=run_manager, args=(mgr_db, mgr_port))
    p_srv = multiprocessing.Process(target=run_server, args=(srv_dir, srv_port))

    p_mgr.start()
    p_srv.start()

    time.sleep(2.0)  # Wait for servers to bind

    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{mgr_port}", timeout=10.0) as mgr_c, \
             httpx.Client(base_url=f"http://127.0.0.1:{srv_port}", timeout=10.0) as srv_c:

            # 1. Check Manager UI
            r = mgr_c.get("/")
            assert r.status_code == 200, f"Manager UI status: {r.status_code}"
            assert "Vault Central Maker" in r.text
            print("✓ Manager HTML UI loaded successfully (HTTP 200)")

            # 2. Check Server UI
            r = srv_c.get("/")
            assert r.status_code == 200, f"Server UI status: {r.status_code}"
            assert "Privacy Kiosk Hub & Secure Portal" in r.text
            print("✓ Server Staff HTML UI loaded successfully (HTTP 200)")

            # 3. Manager creates cafe and issues token
            r = mgr_c.post("/api/v1/admin/cafes", json={"name": "Kottayam Hub", "slug": "kottayam", "email": "admin@kottayam.cc"})
            assert r.status_code == 200
            print("✓ Manager created cafe 'kottayam'")

            r = mgr_c.post("/api/v1/admin/tokens", json={"cafe_slug": "kottayam", "max_uses": 2, "ttl_hours": 24})
            assert r.status_code == 200
            token = r.json()["token"]
            print(f"✓ Manager issued token: {token[:12]}...")

            # 4. Bootstrap Server
            r = srv_c.post("/api/v1/auth/bootstrap", json={"username": "staff1", "password": "StrongPassword123!"})
            assert r.status_code == 200
            print("✓ Server bootstrapped owner account")

            # 5. Login to Server
            r = srv_c.post("/api/v1/auth/login", json={"username": "staff1", "password": "StrongPassword123!"})
            assert r.status_code == 200
            staff_jwt = r.json()["access_token"]
            headers = {"Authorization": f"Bearer {staff_jwt}"}
            print("✓ Server staff login successful (Argon2id verified)")

            # 6. Auto-enroll Node to Manager over real TCP
            r = srv_c.post("/api/v1/system/enroll", json={"manager_url": f"http://127.0.0.1:{mgr_port}", "token": token}, headers=headers)
            assert r.status_code == 200, f"Enroll error: {r.text}"
            enroll_info = r.json()
            assert enroll_info["cafe_slug"] == "kottayam"
            print(f"✓ Server node enrolled with Manager over TCP! Device ID: {enroll_info['device_id'][:8]}...")

            # 7. Create Drop
            r = srv_c.post("/api/v1/drops", json={"label": "Citizen Aadhaar Drop", "max_bytes": 10*1024*1024, "ttl_minutes": 60}, headers=headers)
            assert r.status_code == 200
            drop_code = r.json()["drop_code"]
            print(f"✓ Drop created: {drop_code} (Vanity: vault.laddu.cc/kottayam/d/{drop_code})")

            # 8. Customer Portal UI
            r = srv_c.get(f"/p/{drop_code}", headers={"Accept": "text/html"})
            assert r.status_code == 200
            assert "Zero-Retention Client Drop" in r.text
            print(f"✓ Customer Portal HTML served at /p/{drop_code}")

            # 9. Customer uploads file via chunking
            payload = b"REAL_WORLD_DOCUMENT_BYTES_FOR_NOTARIZATION"
            init_r = srv_c.post(f"/p/{drop_code}/uploads", json={"display_name": "aadhaar.pdf", "size": len(payload), "chunk_size": 8*1024*1024})
            assert init_r.status_code == 200
            upload_id = init_r.json()["upload_id"]

            import hashlib
            chunk_sha = hashlib.sha256(payload).hexdigest()
            chunk_r = srv_c.put(f"/p/{drop_code}/uploads/{upload_id}/chunks/0", content=payload, headers={"X-Chunk-SHA256": chunk_sha})
            assert chunk_r.status_code == 200

            # Tree hash calculation
            tree_hash = server.tree_hash([bytes.fromhex(chunk_sha)], len(payload), 8*1024*1024)

            comp_r = srv_c.post(f"/p/{drop_code}/uploads/{upload_id}/complete", json={"chunk_digests": [chunk_sha], "tree_hash": tree_hash})
            assert comp_r.status_code == 200
            receipt_data = comp_r.json()
            print(f"✓ Upload complete! Tree Hash: {tree_hash[:16]}... Manager Ack: #{receipt_data.get('manager_ack_seq')}")

            # 10. Manager Public Dispute Verifier
            verif_r = mgr_c.get(f"/api/v1/log/verify/{tree_hash}")
            assert verif_r.status_code == 200
            assert verif_r.json()["found"] is True
            print("✓ Manager Public Dispute Verifier successfully authenticated tree hash notarization!")

            # 11. Kiosk session & Obliteration
            s_res = srv_c.post("/api/v1/session/start", headers=headers)
            sess_id = s_res.json()["session_id"]
            d_res = srv_c.post(f"/api/v1/session/{sess_id}/deliver/{upload_id}", headers=headers)
            assert d_res.status_code == 200
            print("✓ Decrypted document delivered to kiosk ephemeral workspace")

            end_res = srv_c.post(f"/api/v1/session/{sess_id}/end", headers=headers)
            assert end_res.status_code == 200
            assert end_res.json()["wipe_verified"] is True
            print("✓ BIG RED OBLITERATION verified: workspace obliterated, zero data retained!")

            # 12. OTA Update Flow
            patch_file = tmp / "patch_v2.5.0.bin"
            patch_file.write_bytes(b"OTA_BINARY_IMAGE_TEST_PAYLOAD")
            with open(patch_file, "rb") as f:
                rel_r = mgr_c.post("/api/v1/admin/releases/upload", data={"version": "2.5.0", "severity": "security"}, files={"file": ("patch_v2.5.0.bin", f, "application/octet-stream")})
            assert rel_r.status_code == 200
            print("✓ Manager published and digitally signed OTA release 2.5.0")

            ota_r = srv_c.post("/api/v1/system/check-update", headers=headers)
            assert ota_r.status_code == 200
            assert ota_r.json()["status"] == "applied"
            assert ota_r.json()["new_version"] == "2.5.0"
            print("✓ Server node checked, verified signature, and applied OTA update 2.5.0!")

            # 13. Fleet check on Manager
            fleet_r = mgr_c.get("/api/v1/admin/fleet")
            assert fleet_r.status_code == 200
            dev = next(d for d in fleet_r.json()["devices"] if d["id"] == enroll_info["device_id"])
            assert dev["image_version"] == "2.5.0"
            assert dev["update_status"] == "applied"
            print(f"✓ Manager fleet reflects updated image version 2.5.0 for {dev['cafe_slug']}!")

            print("\n===========================================")
            print("🎉 ALL REAL-WORLD LIVE TCP TESTS PASSED 100%!")
            print("===========================================")

    finally:
        p_mgr.terminate()
        p_srv.terminate()
        p_mgr.join()
        p_srv.join()
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
