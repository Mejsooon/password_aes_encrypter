from pydantic import BaseModel, Field

# W base64: 3 bajty to 4 znaki

class EncryptionRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    key: str | None = Field(default=None, max_length=44) # Klucz może mieć makstymalnie 32B, czyli 44 znaki


class EncryptionResponse(BaseModel):
    encrypted_password: str
    nonce: str
    key: str


class DecryptionRequest(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=5484) # 1024 znaki * max 4B (UTF-8) + 16B tagu = 4112B = 5484 znaki
    nonce: str = Field(min_length=1, max_length=16) # Maksymalnie 12B, czyli 16 znaków
    key: str = Field(min_length=1, max_length=44) # Klucz może mieć maksymalnie 32B, czyli 44 znaki


class DecryptionResponse(BaseModel):
    decrypted_password: str
