import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from getpass import getpass

# Constants
DATA_FILE = "passwords.json"
MASTER_HASH_FILE = "master_hash.key"

# Utility functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}


def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)


def load_master_hash():
    if os.path.exists(MASTER_HASH_FILE):
        with open(MASTER_HASH_FILE, "rb") as file:
            return file.read().decode()
    return None


def save_master_hash(hash_value):
    with open(MASTER_HASH_FILE, "wb") as file:
        file.write(hash_value.encode())


def derive_key(master_password):
    """Derive a Fernet key from the master password using SHA-256."""
    hash_obj = hashlib.sha256(master_password.encode())
    key = base64.urlsafe_b64encode(hash_obj.digest())
    return key


def encrypt_password(password, key):
    cipher = Fernet(key)
    return cipher.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_password.encode()).decode()


# Core functions
def set_master_password():
    if load_master_hash():
        print("\nMaster password is already set.")
        return

    password = getpass("\nSet a master password: ")
    confirm_password = getpass("\nConfirm the master password: ")

    if password != confirm_password:
        print("\nPasswords do not match. Try again.")
        return

    master_hash = hashlib.sha256(password.encode()).hexdigest()
    save_master_hash(master_hash)
    print("\nMaster password set successfully.")


def add_login():
    master_hash = load_master_hash()
    if not master_hash:
        print("\nError: Set master password first.")
        return

    master_password = getpass("\nEnter master password: ")
    if hashlib.sha256(master_password.encode()).hexdigest() != master_hash:
        print("\nIncorrect master password.")
        return

    key = derive_key(master_password)

    login = input("\nEnter login name: ")
    password = getpass("\nEnter password: ")
    confirm_password = getpass("\nConfirm password: ")

    if password != confirm_password:
        print("\nPasswords do not match.")
        return

    data = load_data()
    data[login] = encrypt_password(password, key)
    save_data(data)
    print("\nLogin added successfully.")


def delete_login():
    master_hash = load_master_hash()
    if not master_hash:
        print("\nError: Set master password first.")
        return

    master_password = getpass("\nEnter master password: ")
    if hashlib.sha256(master_password.encode()).hexdigest() != master_hash:
        print("\nIncorrect master password.")
        return

    login = input("\nEnter login name to delete: ")
    data = load_data()

    if login in data:
        del data[login]
        save_data(data)
        print(f"\nLogin '{login}' deleted successfully.")
    else:
        print("\nLogin not found.")


def list_logins():
    master_hash = load_master_hash()
    if not master_hash:
        print("\nError: Set master password first.")
        return

    master_password = getpass("\nEnter master password: ")
    if hashlib.sha256(master_password.encode()).hexdigest() != master_hash:
        print("\nIncorrect master password.")
        return

    data = load_data()
    if data:
        print("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
        print("\nLogins:\n")
        for login in data.keys():
            print(f"- {login}")
        print("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    else:
        print("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
        print("No logins found.")
        print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")


def get_password():
    master_hash = load_master_hash()
    if not master_hash:
        print("\nError: Set master password first.")
        return

    master_password = getpass("\nEnter master password: ")
    if hashlib.sha256(master_password.encode()).hexdigest() != master_hash:
        print("\nIncorrect master password.")
        return

    key = derive_key(master_password)

    login = input("\nEnter login name: ")
    data = load_data()

    if login in data:
        try:
            password = decrypt_password(data[login], key)
            print(f"\nPassword for '{login}': {password}")
        except Exception:
            print("\nError: Could not decrypt password.")
    else:
        print("\nLogin not found.")


def main():
    print("\n -> LOCKER")
    print(" -> Login Organizer with Cryptography and Key Encryption Records")
    print(" -> Created by: Ira Bell")
    print(" -> www.irabell.com")
    while True:
        print("\nPassword Vault Menu:\n")
        print("(L)ist all logins")
        print("(A)dd new login")
        print("(D)elete login")
        print("(G)et password")
        print("(S)et master password")
        print("(Q)uit")

        choice = input("\nChoose an option: ").strip().lower()

        if choice == "l":
            list_logins()
        elif choice == "a":
            add_login()
        elif choice == "d":
            delete_login()
        elif choice == "g":
            get_password()
        elif choice == "s":
            set_master_password()
        elif choice == "q":
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid option. Try again.")


if __name__ == "__main__":
    main()
