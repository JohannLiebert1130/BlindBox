import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib, binascii


def aes_encrypt(data, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    encryptor = cipher.encryptor()
    encypted_data = encryptor.update(data) + encryptor.finalize()

    return encypted_data


def aes_decrypt(data, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)


def dpi_encrypt(data, key):

    return data


def derive_key(password, salt, iterations=100000):
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    return binascii.hexlify(dk)[:32]
