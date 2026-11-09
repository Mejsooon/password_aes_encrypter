import base64
import binascii
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.exceptions import InvalidEncryptionData


KEY_SIZES = (16, 24, 32)
TAG_SIZE = 16
NONCE_SIZE = 12


def generate_key() -> str:
    key = AESGCM.generate_key(bit_length=128)

    key_string = base64.b64encode(key).decode("utf-8") # Zamieniamy na bajty ASCII a potem na <str>

    return key_string


def encrypt(password: str, key: str | None = None) -> dict[str, str]:
    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        try:
            key_bytes = base64.b64decode(key, validate=True) # <str> do <bytes>
        except binascii.Error as exc:
            raise InvalidEncryptionData("Key is not valid base64") from exc


    if len(key_bytes) not in KEY_SIZES:
        raise InvalidEncryptionData("Key must be 16, 24 or 32 bytes long")

    password_bytes = password.encode("utf-8")

    aesgcm = AESGCM(key_bytes) # Bajty
    nonce = os.urandom(NONCE_SIZE) # Bajty
    ciphertext = aesgcm.encrypt(nonce, password_bytes, None) # Bajty

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"), # Zamieniamy na <str>
        "nonce": base64.b64encode(nonce).decode("utf-8"), # Zamieniamy na <str>
        "key": base64.b64encode(key_bytes).decode("utf-8") # Zamieniamy na <str>
    }


def decrypt(ciphertext: str, nonce: str, key: str) -> dict[str, str]:

    try:
        ciphertext_bytes = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("Ciphertext is not a valid base64") from exc

    if len(ciphertext_bytes) < TAG_SIZE:
        raise InvalidEncryptionData("Ciphertext is too short")

    try:
        nonce_bytes = base64.b64decode(nonce, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("Nonce is not a valid base64") from exc

    try:
        key_bytes = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("Key is not a valid base64") from exc


    aesgcm = AESGCM(key_bytes)

    try:
        password = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)

        return {"decrypted password": password.decode("utf=8")}
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise InvalidEncryptionData("Invalid Encryption Data") from exc