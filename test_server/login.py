from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Request, Form
from pydantic import BaseModel

login_router = APIRouter(prefix="/login")


class User(BaseModel):
    username: str
    password: str
    token: str


def compare(username, password, token):
    if not username == "admin":
        detail = "invalid username"
    elif not password == "123123":
        detail = "invalid password"
    elif not token == "fjlalksdjfaksdj":
        detail = "invalid token"
    else:
        return "ok"

    raise HTTPException(status_code=400, detail=detail)


@login_router.post("/json")
async def login(request: Request, user: Annotated[User, Body()]):
    print(request.headers)

    return compare(user.username, user.password, user.token)


@login_router.post("/form")
async def login_form(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    token: Annotated[str, Form()],
):
    print(request.headers)

    return compare(username, password, token)
