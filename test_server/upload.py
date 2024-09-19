from typing import Annotated

from fastapi import APIRouter, UploadFile, File, HTTPException

upload_router = APIRouter(prefix="/upload")


@upload_router.post("/file")
async def upload(token: Annotated[str, File()], upload_file: UploadFile):
    if token != "fjlalksdjfaksdj":
        return HTTPException(status_code=400, detail="Invalid token")

    with open("../Cargo.toml", "r") as f:
        original = f.read()

    transferred_bytes = await upload_file.read()
    transferred_str = transferred_bytes.decode()

    if original != transferred_str:
        return HTTPException(status_code=400, detail="Invalid file")

    return "ok"
