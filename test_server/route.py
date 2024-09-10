from fastapi import APIRouter, Body, HTTPException, Request, Form, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Annotated

# first (change)
router = APIRouter(prefix="/first")


class User(BaseModel):
    username: str
    password: str
    token: str


h_csrf = """<h1>Alo</h1>
<p>grep me -> _token=fjlalksdjfaksdj</p>
"""


@router.get("/get-csrf", response_class=HTMLResponse)
async def get_csrf(request: Request, response: Response):
    print("Headers:")
    print(request.headers)
    response.set_cookie("PHPSESSID", "SUPERSECURECOOKIE123")

    return h_csrf


@router.post("/login")
async def login(request: Request, user: Annotated[User, Body()]):
    print("Headers:")
    print(request.headers)
    print(request.query_params)

    if not user.username == "admin":
        detail = "invalid username"
    elif not user.password == "123123":
        detail = "invalid password"
    elif not user.token == "fjlalksdjfaksdj":
        detail = "invalid token"
    else:
        return "ok"

    raise HTTPException(status_code=400, detail=detail)


@router.post("/login-form")
async def login_form(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    token: Annotated[str, Form()],
):
    print("Headers:")
    print(request.headers)
    print(request.query_params)

    if not username == "admin":
        detail = "invalid username"
    elif not password == "123123":
        detail = "invalid password"
    elif not token == "fjlalksdjfaksdj":
        detail = "invalid token"
    else:
        return "ok"

    raise HTTPException(status_code=400, detail=detail)
