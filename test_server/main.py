from typing import Any
import asyncio
import signal

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from hypercorn.asyncio import serve
from hypercorn.config import Config

from login import login_router
from upload import upload_router

app = FastAPI(docs_url=None, redoc_url=None)
app.include_router(login_router)
app.include_router(upload_router)

h_csrf = """<h1>Alo</h1>
<p>grep me -> _token=fjlalksdjfaksdj</p>
"""


@app.get("/get-csrf", response_class=HTMLResponse)
async def get_csrf(request: Request, response: Response):
    print(request.headers)
    response.set_cookie("PHPSESSID", "SUPERSECURECOOKIE123")

    return h_csrf


shutdown_event = asyncio.Event()


def handler(*_: Any):
    shutdown_event.set()


async def main():
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, handler)
    loop.add_signal_handler(signal.SIGTERM, handler)

    config = Config()
    config.bind = ["127.0.0.1:8888"]
    await serve(app, config, shutdown_trigger=shutdown_event.wait)


if __name__ == "__main__":
    asyncio.run(main())
