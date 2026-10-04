"""Request bodies for M1's endpoints.  Owner: M1"""
from typing import Literal

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    secret: str = Field(min_length=1, max_length=256, description="Password or PIN")
    secret_kind: Literal["password", "pin"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    secret: str = Field(min_length=1, max_length=256)
