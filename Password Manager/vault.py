import json
import os
import base64
import binascii
from hashlib import sha256
from Crypto.Cipher import AES
from Elgamal_keys import load_private_key, load_public_key
from Digital_signature import sign, verify


# convert master password to a 32-byte key (AES) using SHA-256
def derive_key(master_password):
    return sha256(master_password.encode("utf-8")).digest()

# ─────────────────────────────────────────────

#key is derived from master password, data is the vault data in bytes
def encrypt_data(key, data):
    #generate a random nonce, storing it in cipher
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(data)
    #from bytes to base64 bytes then decode to string for json
    encrypt = {
        "nonce":      base64.b64encode(cipher.nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag":        base64.b64encode(tag).decode("utf-8")
    }
    return encrypt

def decrypt_data(key, enc):
    #string → base64 decode → bytes
    nonce      = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    tag        = base64.b64decode(enc["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) #use the same nonce to create the cipher for decryption
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# ─────────────────────────────────────────────

def load_vault(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def save_vault(path, vault):
    with open(path, "w") as f:
        json.dump(vault, f, indent=4)

# ─────────────────────────────────────────────
# Module 3 helpers: sign and verify the encrypted_vault

def sign_vault(vault, username):
    # convert the encrypted_vault dict to bytes then sign it
    private_key = load_private_key(username)
    vault_bytes = json.dumps(vault["encrypted_vault"], sort_keys=True).encode("utf-8")
    r, s = sign(vault_bytes, private_key)
    vault["signature"] = {"r": r, "s": s}
    
def verify_vault(vault, username):
    if "signature" not in vault:
        print("Vault has no signature")
        return False 

    public_key = load_public_key(username)

    vault_bytes = json.dumps(vault["encrypted_vault"], sort_keys=True).encode("utf-8")

    r = vault["signature"]["r"]
    s = vault["signature"]["s"]

    return verify(vault_bytes, (r, s), public_key)

# ─────────────────────────────────────────────

def add_credential(path, master_password, website, username, password, vault_owner):
    key   = derive_key(master_password)
    vault = load_vault(path)

    if "encrypted_vault" not in vault:
        entries = []
    else:
        plaintext = decrypt_data(key, vault["encrypted_vault"])
        entries   = json.loads(plaintext.decode("utf-8"))

    new_entry = {
        "website":  website,
        "username": username,
        "password": password
    }
    entries.append(new_entry)

    data= json.dumps(entries).encode("utf-8")
    vault["encrypted_vault"] = encrypt_data(key, data)

    # sign after every change 
    sign_vault(vault, vault_owner)

    save_vault(path, vault)
    print("Credential added successfully")

def get_credentials(path, master_password, website, vault_owner):
    key   = derive_key(master_password)
    vault = load_vault(path)

    if "encrypted_vault" not in vault:
        print("Vault is empty")
        return

    # verify before opening 
    if not verify_vault(vault, vault_owner):
        print("ALERT: Vault has been tampered with!")
        return

    try:
        plaintext = decrypt_data(key, vault["encrypted_vault"])
        entries   = json.loads(plaintext.decode("utf-8"))
    except (ValueError, KeyError, binascii.Error):
        print("Vault cannot be opened. Wrong password or file was tampered with.")
        return

    found = False
    for e in entries:
        if e["website"] == website:
            print("Username:", e["username"])
            print("Password:", e["password"])
            found = True

    if not found:
        print("No credentials found for this website")

def update_credential(path, master_password, website, username, new_password, vault_owner):
    key   = derive_key(master_password)
    vault = load_vault(path)

    if "encrypted_vault" not in vault:
        print("Vault is empty")
        return

    plaintext = decrypt_data(key, vault["encrypted_vault"])
    entries   = json.loads(plaintext.decode("utf-8"))

    found = False
    for e in entries:
        if e["website"]== website and e["username"]== username:
            e["password"] = new_password
            found = True
            break

    if not found:
        print("Entry not found")
        return

    data = json.dumps(entries).encode("utf-8")
    vault["encrypted_vault"] = encrypt_data(key, data)

    # sign after every change
    sign_vault(vault, vault_owner)

    save_vault(path, vault)
    print("Password updated successfully")

def delete_credential(path, master_password, website, username, vault_owner):
    key   = derive_key(master_password)
    vault = load_vault(path)

    if "encrypted_vault" not in vault:
        print("Vault is empty")
        return

    plaintext   = decrypt_data(key, vault["encrypted_vault"])
    entries     = json.loads(plaintext.decode("utf-8"))
    new_entries = [e for e in entries 
                   if not (e["website"] == website and e["username"] == username)]

    if len(new_entries) == len(entries):
        print("Entry not found")
        return

    data = json.dumps(new_entries).encode("utf-8")
    vault["encrypted_vault"] = encrypt_data(key, data)

    # sign after every change 
    sign_vault(vault, vault_owner)

    save_vault(path, vault)
    print("Credential deleted successfully")

# ─────────────────────────────────────────────

def main():
    vault_file      = "vault.json"
    master_password = input("Enter master password: ")
    vault_owner     = input("Enter your username: ")   # used for ElGamal sign/verify

    while True:
        print("\n1. Add")
        print("2. Retrieve")
        print("3. Update")
        print("4. Delete")
        print("5. Exit")

        choice = input("Choose: ")

        if choice == "1":
            website  = input("Website: ")
            username = input("Username: ")
            password = input("Password: ")
            add_credential(vault_file, master_password, website, username, password, vault_owner)

        elif choice == "2":
            website = input("Website: ")
            get_credentials(vault_file, master_password, website, vault_owner)

        elif choice == "3":
            website      = input("Website: ")
            username     = input("Username: ")
            new_password = input("New Password: ")
            update_credential(vault_file, master_password, website, username, new_password, vault_owner)

        elif choice == "4":
            website  = input("Website: ")
            username = input("Username: ")
            delete_credential(vault_file, master_password, website, username, vault_owner)

        elif choice == "5":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()