import random
import json
import hashlib
import os

from Crypto.Cipher import AES
from Elgamal_keys import load_private_key, load_public_key
from Digital_signature import sign, verify
from vault import derive_key, encrypt_data, decrypt_data, load_vault, save_vault, sign_vault


def get_vault_data(user, password):
    key = derive_key(password)
    vault = load_vault("vault.json")
    return decrypt_data(key, vault["encrypted_vault"])


def save_vault_data(user, password, data):
    key = derive_key(password)
    vault = load_vault("vault.json")
    vault["encrypted_vault"] = encrypt_data(key, data)
    sign_vault(vault, user)
    save_vault("vault.json", vault)

# load q and alpha from config file
def load_parameters(path="config.json"):
    if not os.path.exists(path):
        raise FileNotFoundError("config.json not found")
    with open(path, "r") as f:
        cfg = json.load(f)
    return cfg["q"], cfg["alpha"]


def generate_dh_config(bits=512, path="config.json"):
    from Crypto.Util.number import getPrime, isPrime
    print("Generating DH parameters...")
    while True:
        p = getPrime(bits - 1)
        q = 2 * p + 1
        if isPrime(q):
            break
    while True:
        alpha = random.randint(2, q - 2)
        if pow(alpha, 2, q) != 1 and pow(alpha, p, q) != 1:
            break
    with open(path, "w") as f:
        json.dump({"q": q, "alpha": alpha}, f, indent=4)
    print("DH parameters saved to config.json")


def generate_keypair(q, alpha):
    priv = random.randint(2, q - 2)
    pub = pow(alpha, priv, q)
    return priv, pub


def get_shared_secret(their_pub, my_priv, q):
    return pow(their_pub, my_priv, q)

# we will hash the shared secret to get a 32-byte AES key
def get_session_key(shared_secret):
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
    return hashlib.sha256(secret_bytes).digest()


def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }

# decrypt and verify to make sure data is fine and not tampered with
def aes_decrypt(key, pkg):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(pkg["nonce"]))
    return cipher.decrypt_and_verify(bytes.fromhex(pkg["ciphertext"]), bytes.fromhex(pkg["tag"]))


def sender_send_pub(pub, priv_key):
    pub_bytes = str(pub).encode()
    r, s = sign(pub_bytes, priv_key)
    return {"dh_public": pub, "signature": {"r": r, "s": s}}


def receiver_verify_respond(pkg, sender_pub_key, recv_pub, recv_priv_key):
    pub_bytes = str(pkg["dh_public"]).encode()
    sig = (pkg["signature"]["r"], pkg["signature"]["s"])
    if not verify(pub_bytes, sig, sender_pub_key):
        print("ABORT: Sender signature invalid.")
        return {}, False
    print("Sender DH key verified.")
    r, s = sign(str(recv_pub).encode(), recv_priv_key)
    return {"dh_public": recv_pub, "signature": {"r": r, "s": s}}, True

# han verify el receiver's signature abl mangeeb el shared secret
def sender_verify_receiver(pkg, recv_pub_key):
    pub_bytes = str(pkg["dh_public"]).encode()
    sig = (pkg["signature"]["r"], pkg["signature"]["s"])
    if not verify(pub_bytes, sig, recv_pub_key):
        print("ABORT: Receiver signature invalid.")
        return 0, False
    print("Receiver DH key verified.")
    return pkg["dh_public"], True

# hane3mel decryption lel vault b master password ba3den ne encrypt b session key
def prepare_export(sender, password, session_key, sender_priv_key):
    print("Decrypting vault...")
    data = get_vault_data(sender, password)
    print("Encrypting with session key...")
    pkg = aes_encrypt(session_key, data)
    pkg_bytes = json.dumps(pkg).encode()
    r, s = sign(pkg_bytes, sender_priv_key)
    print("Vault ready to send.")
    return {"encrypted_vault": pkg, "signature": {"r": r, "s": s}}


def import_vault(transfer, sender_pub_key, receiver, new_password, session_key):
    print("Verifying signature...")
    pkg_bytes = json.dumps(transfer["encrypted_vault"]).encode()
    sig = (transfer["signature"]["r"], transfer["signature"]["s"])
    if not verify(pkg_bytes, sig, sender_pub_key):
        print("ABORT: Vault signature invalid.")
        return False
    print("Signature verified.")
    try:
        data = aes_decrypt(session_key, transfer["encrypted_vault"])
    except ValueError:
        print("ABORT: Decryption failed.")
        return False
    print("Saving vault...")
    save_vault_data(receiver, new_password, data)
    print(f"Vault imported successfully for {receiver}.")
    return True


def run_export(sender, receiver, sender_pw, receiver_pw, config_path="config.json"):
    print("\n--- Vault Export ---")

    sender_priv = load_private_key(sender)
    sender_pub = load_public_key(sender)
    receiver_priv = load_private_key(receiver)
    receiver_pub = load_public_key(receiver)

    q, alpha = load_parameters(config_path)

    s_priv, s_pub = generate_keypair(q, alpha)
    r_priv, r_pub = generate_keypair(q, alpha)

    pkg1 = sender_send_pub(s_pub, sender_priv)

    pkg2, ok = receiver_verify_respond(pkg1, sender_pub, r_pub, receiver_priv)
    if not ok:
        return

    _, ok = sender_verify_receiver(pkg2, receiver_pub)
    if not ok:
        return

    secret1 = get_shared_secret(r_pub, s_priv, q)
    secret2 = get_shared_secret(s_pub, r_priv, q)
    assert secret1 == secret2

    session_key = get_session_key(secret1)
    print("Shared secret established.")

    transfer = prepare_export(sender, sender_pw, session_key, sender_priv)

    success = import_vault(transfer, sender_pub, receiver, receiver_pw, session_key)

    if success:
        print("\nExport complete!")
    else:
        print("\nExport failed.")


def main():
    if not os.path.exists("config.json"):
        generate_dh_config()

    sender = input("Sender username   : ").strip()
    receiver = input("Receiver username : ").strip()
    sender_pw = input(f"{sender}'s master password   : ").strip()
    receiver_pw = input(f"{receiver}'s new master password : ").strip()

    run_export(sender, receiver, sender_pw, receiver_pw)


if __name__ == "__main__":
    main()