import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# Metodo para cifrar con chacha20 generando la salt y el nonce aleatoriamente
def encrypt_message(message, password):
    salt = os.urandom(16)  # Genera una sal aleatoria
    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    # Genera un nonce aleatorio
    nonce = os.urandom(16)

    # Crea el objeto Cipher con el algoritmo ChaCha20 y el modo AEAD
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    # Cifra el mensaje utilizando el cifrador ChaCha20-Poly1305
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Retorna la sal, el nonce y el texto cifrado
    return salt, nonce, ciphertext


# Metodo para cifrar con chacha20 indicando salt y nonce
def encrypt_message_salt_nonce(message, password, salt, nonce):
    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    # Genera un nonce aleatorio

    # Crea el objeto Cipher con el algoritmo ChaCha20 y el modo AEAD
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    # Cifra el mensaje utilizando el cifrador ChaCha20-Poly1305
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Retorna la sal, el nonce y el texto cifrado
    return ciphertext


# Metodo para descifrar 
def decrypt_message(salt, nonce, ciphertext, password):
    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2 con la misma sal y contraseña
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    # Crea el objeto Cipher con el algoritmo ChaCha20 y el modo AEAD
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    # Descifra el mensaje utilizando el cifrador ChaCha20-Poly1305
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext