from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.exceptions import AppException
from app.schemas.passwords import EncryptionResponse, EncryptionRequest, DecryptionResponse, DecryptionRequest
from app.services.encrypt import encrypt, decrypt, generate_key


app = FastAPI()

@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.get("/")
def root():
    return {"Hello": "World"}


@app.post("/encrypt", response_model=EncryptionResponse)
def encrypt_password(data: EncryptionRequest):
    return encrypt(data.password, data.key)


@app.post("/decrypt", response_model=DecryptionResponse)
def decrypt_password(data: DecryptionRequest):
    return decrypt(data.ciphertext, data.nonce, data.key)


@app.get("/key")
def generate_new_key():
    return generate_key()