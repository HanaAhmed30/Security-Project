import random
import json
import os
from Crypto.Util.number import getPrime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
#initialize user

def initialize_user(username):
    print("DEBUG: generating keys...")
    #given el username, han generate elgamal keys w ne3melohom save fe files
    private_key, public_key = generate_elgamal_keys()

    save_private_key(username, private_key)
    save_public_key(username, public_key)

    print(f"[+] User {username} initialized successfully")

#generate public and private keys

def generate_elgamal_keys(bits=256):
    #generate a large prime number p
    p = generate_large_prime(bits)
    
    #choose g
    g = choose_primitive_root(p)
    
    #choose a private key x
    x = choose_private_key(p)
    
    #calculate the public key y
    y = pow(g, x, p)
    
    private_key = {
        "p": p,
        "g": g,
        "x": x
    }

    public_key = {
        "p": p,
        "g": g,
        "y": y
    }

    return private_key, public_key

#generate a large prime number
def generate_large_prime(bits=10):
    return getPrime(bits)

#choose a primitive root
def choose_primitive_root(p):
    
    while True:
        g = random.randint(2, p - 2)

        
        if pow(g, (p - 1) // 2, p) != 1:
            return g
        
def prime_factors(n):

    #set() only stores unique values
    factors = set()

    # el awel han extract 2 as a factor
    #ha3od a divide n by 2 until n is odd
    while n % 2 == 0:
        factors.add(2)
        n //= 2

    # n delwa2ty odd, fa han extract odd factors starting from 3 le7ad sqrt(n) 3ashan ba3d keda el factors hatet3ad in reverse
    
    for i in range(3, int(n**0.5) + 1, 2):
        while n % i == 0:
            factors.add(i)
            n //= i

    # what is left is prime law akbar men 2, fa han add it to the factors set
    if n > 2:
        factors.add(n)

    return factors

#choose a private key
def choose_private_key(p):
    return random.randint(2, p - 2)

#save keys to a file
def save_private_key(username, private_key):
    path = os.path.join(BASE_DIR, f"{username}_private.json")
    with open(path, "w") as f:
        json.dump(private_key, f, indent=4)

def save_public_key(username, public_key):
    path = os.path.join(BASE_DIR, f"{username}_public.json")

    with open(path, "w") as f:
        json.dump(public_key, f, indent=4)

#load keys from a file
def load_private_key(username):
    path = os.path.join(BASE_DIR, f"{username}_private.json")

    if not os.path.exists(path):
        raise FileNotFoundError("Private key not found")
    
    with open(path, "r") as f:
        return json.load(f)

def load_public_key(username):
    path = os.path.join(BASE_DIR, f"{username}_public.json")

    if not os.path.exists(path):
        raise FileNotFoundError("Public key not found")
    
    with open(path, "r") as f:
        return json.load(f)


#main function to initialize a user and generate keys   
def main():
    username = input("Enter username: ").strip()
    initialize_user(username)


#to only run the main function if this file is executed directly, not when imported as a module
if __name__ == "__main__":
    main()