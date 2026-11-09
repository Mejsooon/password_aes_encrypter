from pydantic import BaseModel, Field


class EncryptionRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    key: str | None = None


class EncryptionResponse(BaseModel):
    encrypted_password: str
    nonce: str
    key: str


class DecryptionRequest(BaseModel):
    ciphertext: str
    nonce: str
    key: str


class DecryptionResponse(BaseModel):
    decrypted_password: str
