import httpx
import shutil
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="OSSEC Malware Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SERVICES = {
    "dynamic":  "http://localhost:8000",
    "speakeasy": "http://localhost:8001",
    "ai":       "http://localhost:8002",
    "pdf_png":  "http://localhost:8003",
}

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def save_file(upload: UploadFile) -> str:
    path = os.path.join(UPLOAD_DIR, upload.filename)
    with open(path, "wb") as f:
        shutil.copyfileobj(upload.file, f)
    return path


async def forward(service_url: str, endpoint: str, file_path: str) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
            resp = await client.post(f"{service_url}{endpoint}", files=files)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()


@app.post("/analyze/dynamic")
async def analyze_dynamic(file: UploadFile = File(...)):
    path = save_file(file)
    result = await forward(SERVICES["dynamic"], "/analyze", path)
    return {"service": "dynamic_microservice", "result": result}


@app.post("/analyze/speakeasy")
async def analyze_speakeasy(file: UploadFile = File(...)):
    path = save_file(file)
    result = await forward(SERVICES["speakeasy"], "/emulate", path)
    return {"service": "speakeasy_emulator", "result": result}


@app.post("/analyze/ai")
async def analyze_ai(file: UploadFile = File(...)):
    path = save_file(file)
    result = await forward(SERVICES["ai"], "/analyze", path)
    return {"service": "ai_analysis", "result": result}


@app.post("/analyze/report")
async def generate_report(file: UploadFile = File(...)):
    path = save_file(file)
    result = await forward(SERVICES["pdf_png"], "/report", path)
    return {"service": "pdf_png", "result": result}



@app.get("/health")
async def health():
    status = {}
    endpoints = {
        "dynamic":  (SERVICES["dynamic"],  "/health"),
        "speakeasy": (SERVICES["speakeasy"], "/health"),
        "ai":       (SERVICES["ai"],       "/health"),
        "pdf_png":  (SERVICES["pdf_png"],  "/health"),
    }
    async with httpx.AsyncClient(timeout=5) as client:
        for name, (url, path) in endpoints.items():
            try:
                r = await client.get(f"{url}{path}")
                status[name] = "up" if r.status_code == 200 else "degraded"
            except Exception:
                status[name] = "down"
    return {"gateway": "up", "services": status}