import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DATA_FILE = "data.enc"


def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def aes_decrypt(enc_text: str, password: str):
    raw = base64.b64decode(enc_text.encode())

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def main():
    if not os.path.exists(DATA_FILE):
        print("Encrypted file not found")
        return

    password = input("Enter password to decrypt data: ")

    try:
        with open(DATA_FILE, "r") as f:
            encrypted_data = f.read()

        decrypted = aes_decrypt(encrypted_data, password)
        print("\nACCESS GRANTED")
        print("Decrypted Data:", decrypted)

    except Exception:
        print("\nACCESS DENIED")
        print("Wrong password or data has been tampered with")


if __name__ == "__main__":
    main()