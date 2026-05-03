import os
from Elgamal_keys import initialize_user
from vault import add_credential, get_credentials, update_credential, delete_credential
from dh_export import run_export, generate_dh_config

VAULT_FILE = "vault.json"

def print_main_menu():
    print("""
1. Set up new user
2. Manage vault
3. Export vault to another user
4. Exit
""")


def setup_user():
    print("\n--- Set Up New User ---")
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    initialize_user(username)


def manage_vault():
    print("\n--- Vault Management ---")
    username        = input("Enter your username   : ").strip()
    master_password = input("Enter master password : ").strip()

    if not username or not master_password:
        print("Username and master password are required.")
        return

    while True:
        print("""
  1. Add credential
  2. Retrieve credential
  3. Update credential
  4. Delete credential
  5. Back
""")
        choice = input("Choose: ").strip()

        if choice == "1":
            website  = input("Website  : ").strip()
            usr      = input("Username : ").strip()
            password = input("Password : ").strip()
            add_credential(VAULT_FILE, master_password, website, usr, password, username)

        elif choice == "2":
            website = input("Website : ").strip()
            get_credentials(VAULT_FILE, master_password, website, username)

        elif choice == "3":
            website      = input("Website      : ").strip()
            usr          = input("Username     : ").strip()
            new_password = input("New Password : ").strip()
            update_credential(VAULT_FILE, master_password, website, usr, new_password, username)

        elif choice == "4":
            website = input("Website  : ").strip()
            usr     = input("Username : ").strip()
            delete_credential(VAULT_FILE, master_password, website, usr, username)

        elif choice == "5":
            break

        else:
            print("Invalid choice.")


def export_vault():
    print("\n--- Export Vault (Diffie-Hellman) ---")

    if not os.path.exists("config.json"):
        print("No config.json found. Generating DH parameters...")
        generate_dh_config()

    sender      = input("Enter sender username              : ").strip()
    receiver    = input("Enter receiver username            : ").strip()
    sender_pw   = input(f"Enter {sender}'s master password   : ").strip()
    receiver_pw = input(f"Enter {receiver}'s new master password : ").strip()

    if not sender or not receiver or not sender_pw or not receiver_pw:
        print("All fields are required.")
        return

    run_export(sender, receiver, sender_pw, receiver_pw)


def main():
    while True:
        print_main_menu()
        choice = input("Choose: ").strip()

        if choice == "1":
            setup_user()

        elif choice == "2":
            manage_vault()

        elif choice == "3":
            export_vault()

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()