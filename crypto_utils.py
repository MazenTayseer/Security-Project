import secrets
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hash_password(password):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=500_000,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=500_000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), hashed_password)
        return True
    except Exception:
        return False

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=500_000,
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_file(data, key):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, nonce, tag

def decrypt_file(ciphertext, key, nonce, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def compute_file_hash(data):
    return hashlib.sha256(data).digest()

def verify_file_hash(data, expected_hash):
    computed_hash = hashlib.sha256(data).digest()
    return computed_hash == expected_hash