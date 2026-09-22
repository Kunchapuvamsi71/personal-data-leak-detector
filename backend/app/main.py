from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .scanner import scan_text

BASE_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = BASE_DIR / "frontend"
MAX_BYTES = 2 * 1024 * 1024

app = FastAPI(title="Personal Data Leak Detector", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_BYTES)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
def scan(request: ScanRequest) -> dict:
    return scan_text(request.text)


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)) -> dict:
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File is larger than the 2 MB limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=415, detail="Only UTF-8 text files are supported") from error
    result = scan_text(text)
    result["filename"] = file.filename or "unnamed"
    return result
