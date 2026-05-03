
## Overview
A command-line password manager that uses AES-256-GCM for encryption, SHA-256 for key derivation, ElGamal Digital Signatures for vault integrity, and Diffie-Hellman for secure vault export between users.



## Requirements
- Python 3.10 or higher
- pycryptodome

Install dependencies:

pip3 install pycryptodome




## How to Run

cd "Password Manager"
python3 main.py




## Full Workflow

### Step 1 — Set up users
Choose option 1 and enter a username. Do this for each user (e.g. alice and bob).
This generates an ElGamal key pair for each user and saves it locally.

### Step 2 — Add credentials
Choose option 2, enter your username and master password.
Then choose option 1 to add a credential (website, username, password).
The vault is encrypted with AES-256-GCM and signed with your ElGamal private key automatically.

### Step 3 — Retrieve credentials
Choose option 2, enter your username and master password.
Then choose option 2 and enter the website name.
The vault signature is verified before displaying any credentials.

### Step 4 — Update or delete credentials
Choose option 2, enter your username and master password.
Choose option 3 to update or option 4 to delete.
The vault is re-encrypted and re-signed after every change.

### Step 5 — Export vault to another user
Choose option 3.
Enter the sender username, receiver username, and both master passwords.
The vault is securely transferred using Diffie-Hellman key exchange with ElGamal signatures protecting against man-in-the-middle attacks.



## Notes
- Private keys are stored locally as `{username}_private.json` and should never be shared.
- Public keys are stored as `{username}_public.json` and can be shared with other users.
- `config.json` contains the shared Diffie-Hellman parameters and is generated automatically on the first export.
- Diffie-Hellman and ElGamal Digital Signatures are implemented from scratch.
- AES and SHA-256 use the pycryptodome library as permitted by the project requirements.