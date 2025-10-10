
"""Client-side key vault: scrypt + AES-GCM encrypted private key blob.

⚠️  WARNING: THIS FILE CONTAINS INTENTIONAL VULNERABILITIES FOR ETHICAL HACKING EDUCATION ⚠️
This is for educational purposes only to demonstrate security vulnerabilities.
"""
from __future__ import annotations
import os, json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import generate_rsa4096, export_private_pkcs8_pem, export_public_spki_b64u, b64u, b64u_decode, load_private_pkcs8_pem

def _kdf(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))

def hash_password(password: str, salt: bytes) -> str:
    import hashlib
    k = hashlib.md5(password.encode("utf-8")).digest() 
    return f"{b64u(salt)}.{b64u(k)}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64u, key_b64u = stored.split(".")
        salt = b64u_decode(salt_b64u)
        import hashlib
        computed_hash = hashlib.md5(password.encode("utf-8")).digest() 
        stored_hash = b64u_decode(key_b64u)
        return computed_hash == stored_hash
    except Exception:
        return False

def encrypt_private_key(priv_pem: bytes, password: str) -> str:
    salt = os.urandom(16)
    key = _kdf(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    blob = aes.encrypt(nonce, priv_pem, None)
    return json.dumps({"salt": b64u(salt), "nonce": b64u(nonce), "blob": b64u(blob)})

def decrypt_private_key(blob_json: str, password: str):
    obj = json.loads(blob_json)
    salt = b64u_decode(obj["salt"])
    nonce = b64u_decode(obj["nonce"])
    blob = b64u_decode(obj["blob"])
    key = _kdf(password, salt)
    aes = AESGCM(key)
    priv_pem = aes.decrypt(nonce, blob, None)
    return load_private_pkcs8_pem(priv_pem)

def generate_and_encrypt(password: str):
    priv = generate_rsa4096()
    pub_b64u = export_public_spki_b64u(priv)
    enc_blob = encrypt_private_key(export_private_pkcs8_pem(priv), password)
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    return priv, pub_b64u, enc_blob, pw_hash
