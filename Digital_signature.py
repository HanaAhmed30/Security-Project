import random
import json 
import hashlib

from matplotlib.pylab import gcd



def hash_data(data: bytes):
    return int(hashlib.sha256(data).hexdigest(), 16)



def mod_inverse(e: int, phi: int) -> int:
    
    g, x, y = extended_gcd(e, phi)

    if g != 1:
        raise ValueError("Inverse does not exist")
    
    return x % phi

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm.

    Returns (g, x, y) such that  a*x + b*y == g == gcd(a, b).
    """
    # Variables initialization for the extended Euclidean algorithm.
    # Matching the lecture table (slide 12):
    #   r_{i-2}, r_{i-1}  start as  a, b
    #   x_{i-2}, x_{i-1}  start as  1, 0
    #   y_{i-2}, y_{i-1}  start as  0, 1
    
    r_old, r_cur = a, b
    x_old, x_cur = 1, 0
    y_old, y_cur = 0, 1

   

    while r_cur != 0:
        quotient = r_old // r_cur
 
        r_old, r_cur = r_cur,r_old % r_cur
        x_old, x_cur = x_cur, x_old - quotient * x_cur
        y_old, y_cur = y_cur, y_old - quotient * y_cur
 
    # r_old is gcd, x_old and y_old are the bezout coeff.
    return r_old, x_old, y_old
    
def sign(data_bytes, private_key):
    p = private_key["p"]
    g = private_key["g"]
    x = private_key["x"]

    #step1: hash the data (becomes an int)
    h = hash_data(data_bytes)  

    #step2: choose a random k (lazem teb2a coprime to p-1 )
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break

    #step3: calculate r= g^k mod p
    r= pow(g, k, p)    
    k_inv = mod_inverse(k, p - 1)

    #step4: calculate s
    s = (k_inv * (h - x * r)) % (p - 1)

    return r, s


def verify(data_bytes, signature, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    r, s = signature

    h = hash_data(data_bytes)

    #compute left side of verification equation using signature and public key
    left = (pow(y, r, p) * pow(r, s, p)) % p
    #compute right side of verification equation using message and public key
    right = pow(g, h, p)

    return left == right

def save_vault(filename, encrypted_data, signature):
    vault = {
        "data": encrypted_data,
        "signature": {
            "r": signature[0],
            "s": signature[1]
        }
    }

    with open(filename, "w") as f:
        json.dump(vault, f, indent=4)

def load_and_verify_vault(filename, public_key):
    with open(filename, "r") as f:
        vault = json.load(f)

    data = vault["data"]
    signature = (vault["signature"]["r"], vault["signature"]["s"])

    #data.encode() converts the string data to bytes
    is_valid = verify(data.encode(), signature, public_key)

    if not is_valid:
        print("ALERT: Vault has been tampered with!")
        return None

    print("Vault verified successfully")
    return vault        

def main():
    from Elgamal_keys import load_private_key, load_public_key

    #ask user for username to load keys and verify vault
    username = input("Enter username: ").strip()

    private_key = load_private_key(username)
    public_key = load_public_key(username)

    data = "my encrypted vault data"

    # sign
    signature = sign(data.encode(), private_key)

    print("Signature:", signature)

    # verify
    result = verify(data.encode(), signature, public_key)

    print("Verification result:", result)
    tampered_data = "encrypted_vault_content_exampleX"

    tamper_result = verify(tampered_data.encode(), signature, public_key)
    print("\nTampered verification result:", tamper_result)

if __name__ == "__main__":
    main()