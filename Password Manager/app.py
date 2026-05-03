"""
app.py — Flask backend for the Secure Password Manager UI
Run:  pip install flask
      python app.py
Then open:  http://localhost:5000
"""

from flask import Flask, request, jsonify, send_from_directory
import os, sys

# make sure vault.py can find Elgamal_keys and Digital_signature
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault import (
    add_credential,
    get_credentials,
    update_credential,
    delete_credential,
    load_vault,
    decrypt_data,
    derive_key,
    verify_vault,
)
from Elgamal_keys import initialize_user, load_public_key

app = Flask(__name__, static_folder=".")

VAULT_FILE = "vault.json"

# ── serve the UI ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

# ── initialize user (generate ElGamal keys) ───────────────────
@app.route("/api/init", methods=["POST"])
def api_init():
    d = request.json
    username = d.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Username required"}), 400
    try:
        initialize_user(username)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── unlock vault (just verify password + signature) ───────────
@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    d = request.json
    master   = d.get("master", "")
    username = d.get("username", "").strip()
    try:
        vault = load_vault(VAULT_FILE)
        if not vault:
            return jsonify({"ok": True, "entries": []})
        # verify ElGamal signature
        if not verify_vault(vault, username):
            return jsonify({"ok": False, "error": "VAULT TAMPERED — signature invalid!"}), 403
        # try to decrypt
        key       = derive_key(master)
        plaintext = decrypt_data(key, vault["encrypted_vault"])
        import json
        entries = json.loads(plaintext.decode("utf-8"))
        # return entries without passwords (shown on demand)
        safe = [{"website": e["website"], "username": e["username"]} for e in entries]
        return jsonify({"ok": True, "entries": safe})
    except Exception as e:
        return jsonify({"ok": False, "error": "Wrong password or corrupted vault"}), 401

# ── get password for one entry ────────────────────────────────
@app.route("/api/get", methods=["POST"])
def api_get():
    d        = request.json
    master   = d.get("master", "")
    username = d.get("username", "")
    website  = d.get("website", "")
    try:
        vault     = load_vault(VAULT_FILE)
        key       = derive_key(master)
        plaintext = decrypt_data(key, vault["encrypted_vault"])
        import json
        entries   = json.loads(plaintext.decode("utf-8"))
        results   = [e for e in entries if e["website"] == website]
        if not results:
            return jsonify({"ok": False, "error": "Not found"}), 404
        return jsonify({"ok": True, "entries": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── add ───────────────────────────────────────────────────────
@app.route("/api/add", methods=["POST"])
def api_add():
    d = request.json
    try:
        add_credential(
            VAULT_FILE,
            d["master"],
            d["website"],
            d["username"],
            d["password"],
            d["vault_owner"],
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── update ────────────────────────────────────────────────────
@app.route("/api/update", methods=["POST"])
def api_update():
    d = request.json
    try:
        update_credential(
            VAULT_FILE,
            d["master"],
            d["website"],
            d["username"],
            d["new_password"],
            d["vault_owner"],
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── delete ────────────────────────────────────────────────────
@app.route("/api/delete", methods=["POST"])
def api_delete():
    d = request.json
    try:
        delete_credential(
            VAULT_FILE,
            d["master"],
            d["username_cred"],
            d["website"],
            d["vault_owner"],
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("\n  SecureVault UI →  http://localhost:5000\n")
    app.run(debug=True, port=5000)
