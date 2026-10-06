"""Request bodies for M1's endpoints.  Owner: M1"""
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints

# Surrounding spaces are removed before the length is checked, so "  ab " is too short.
# Never strip the secret: spaces can be part of a password.
Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=64)]
LoginUsername = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=254)]


class RegisterRequest(BaseModel):
    username: Username
    email: Email
    secret: str = Field(min_length=1, max_length=256, description="Password or PIN")
    secret_kind: Literal["password", "pin"]


class LoginRequest(BaseModel):
    username: LoginUsername
    secret: str = Field(min_length=1, max_length=256)
