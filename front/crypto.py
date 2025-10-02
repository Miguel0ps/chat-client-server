# crypto.py

import base64
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hmac

# Sesiones por conexión
sessions = {}

# -------------------------
# RSA
# -------------------------
def generate_rsa_keypair(bits: int = 2048):
    return RSA.generate(bits)

def rsa_pub_pem(rsa_key) -> bytes:
    return rsa_key.publickey().export_key()

def rsa_decrypt_with_key(rsa_priv_key, ciphertext_bytes: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_priv_key)
    return cipher.decrypt(ciphertext_bytes)

def rsa_encrypt_with_pub_pem(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(plaintext)

# -------------------------
# AES-GCM
# -------------------------
def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    packed = nonce + tag + ciphertext
    return base64.b64encode(packed).decode()

def aes_gcm_decrypt(aes_key: bytes, enc_b64: str) -> bytes:
    raw = base64.b64decode(enc_b64)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# -------------------------
# Sesiones
# -------------------------
def set_session_aes(conn, aes_key: bytes):
    sessions.setdefault(conn, {})['aes_key'] = aes_key

def get_session_aes(conn):
    return sessions.get(conn, {}).get('aes_key')

def clear_session(conn):
    sessions.pop(conn, None)

# -------------------------
# Helpers para mensajes
# -------------------------
def encrypt_for(conn, plaintext: str) -> str:
    aes_key = get_session_aes(conn)
    if not aes_key:
        raise ValueError("No AES key for this session.")
    return aes_gcm_encrypt(aes_key, plaintext.encode())

def decrypt_from(conn, enc_b64: str) -> str:
    aes_key = get_session_aes(conn)
    if not aes_key:
        raise ValueError("No AES key for this session.")
    return aes_gcm_decrypt(aes_key, enc_b64).decode()

# -------------------------
# OTP
# -------------------------
def create_otp_for(conn) -> str:
    otp = '{:06d}'.format(secrets.randbelow(10**6))
    sessions.setdefault(conn, {})['otp'] = otp
    return otp

def verify_otp_for(conn, code: str) -> bool:
    otp = sessions.get(conn, {}).get('otp')
    if not otp:
        return False
    ok = hmac.compare_digest(otp, code)
    if ok:
        sessions[conn].pop('otp', None)
    return ok
