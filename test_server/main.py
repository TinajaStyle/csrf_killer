from fastapi import FastAPI
from hypercorn.asyncio import serve
from hypercorn.config import Config
from typing import Any
import asyncio
import signal
from route import router

app = FastAPI(docs_url=None, redoc_url=None)
app.include_router(router)

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