from fastapi import FastAPI, HTTPException

from app.core.exceptions import InvalidEncryptionData
from app.schemas.passwords import EncryptionResponse, EncryptionRequest, DecryptionResponse, DecryptionRequest
from app.services.encrypt import encrypt, decrypt, generate_key


app = FastAPI()

@app.get("/")
def root():
    return {"Hello": "World"}


@app.post("/encrypt", response_model=EncryptionResponse)
def encrypt_password(data: EncryptionRequest):
    try:
        encrypted_password = encrypt(data.password, data.key)
    except InvalidEncryptionData as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return encrypted_password


@app.post("/decrypt", response_model=DecryptionResponse)
def decrypt_password(data: DecryptionRequest):
    try:
        decrypted_password = decrypt(data.ciphertext, data.nonce, data.key)
    except InvalidEncryptionData as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return decrypted_password


@app.get("/key")
def generate_new_key():
    return generate_key()