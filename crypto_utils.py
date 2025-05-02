import secrets
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    
    salted_password = password.encode('utf-8') + salt
    hashed_password = hashlib.sha256(salted_password).digest() # converts to binary format (bytes shown in hex)
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    salted_password = password.encode('utf-8') + salt
    computed_hash = hashlib.sha256(salted_password).digest() # converts to binary format (bytes shown in hex)
    return computed_hash == hashed_password

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,            # Key length for AES-256
        salt=salt,
        iterations=100000,    # Increase for better security
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