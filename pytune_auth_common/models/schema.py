from typing import Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field
from pytune_data.models import UserTypeEnum, UserStatusEnum , ClientStatusEnum, User

# Schema definitions
class LoginSchema(BaseModel):
    email: str
    password: str
    
class UserBase(BaseModel):
    email: EmailStr
    hashed_password: Optional[str]
    user_type: Optional[UserTypeEnum] = Field(default=UserTypeEnum.INDIVIDUAL)

class EmailRequest(BaseModel):
    email: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    status: UserStatusEnum
    user_type: UserTypeEnum
    client_status: ClientStatusEnum = ClientStatusEnum.FREE
    first_name:Optional[str] = None
    last_name: Optional[str] = None
    oauth_provider : Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    scopes: list[str] = []

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str
    confirm_password: str

class ChangePasswordSchema(BaseModel):
    new_password: str = Field(..., min_length=6)

class UsernameAlreadyExists(Exception):
    pass

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class RevokeUserSchema(BaseModel):
    email:str
    reason: str

class RevokeUserSchema(BaseModel):
    email: str

class CodeVerifierRequest(BaseModel):
    code_verifier: str