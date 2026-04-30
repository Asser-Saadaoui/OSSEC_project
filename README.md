# OSSEC Malware Analysis

A gateway + frontend for orchestrating four malware analysis microservices.


ossec_malware_analysis/
├── backend/
│   ├── main.py            # FastAPI gateway (port 8080)
│   └── requirements.txt
├── frontend/
│   └── index.html         # Single-file UI (no build step)
├── .gitignore
└── README.md


## Architecture

| Service              | Port | Endpoint called by gateway      |
|----------------------|------|---------------------------------|
| dynamic_microservice | 8000 | POST /analyze                   |
| speakeasy_emulator   | 8001 | POST /emulate                   |
| ai_analysis          | 8002 | POST /analyze                   |
| pdf & png            | 8003 | POST /report                    |
| **gateway (this)**   | **8080** | all routes above        

---

## Setup & Run

### 1. Start your four microservices

Make sure each of your existing services is running on its respective port before starting the gateway.

```bash
# Example — adapt to your actual start commands
cd dynamic_microservice && uvicorn main:app --port 8000
cd speakeasy_emulator   && uvicorn main:app --port 8001
cd ai_analysis          && uvicorn main:app --port 8002
cd pdf_png              && uvicorn main:app --port 8003
```

### 2. Set up the gateway

```bash
cd ossec_malware_analysis/backend

# Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Start the gateway

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

The gateway is now running at `http://localhost:8080`.  
Interactive API docs: `http://localhost:8080/docs`

### 4. Open the frontend

No build step needed. Just open the file directly in your browser:

```
ossec_malware_analysis/frontend/index.html
```

Or serve it with any static server:

```bash
cd frontend
python -m http.server 5500
# open http://localhost:5500
```

---

## API Reference

| Method | Route                  | Description                          |
|--------|------------------------|--------------------------------------|
| GET    | /health                | Status of all four microservices     |
| POST   | /analyze/dynamic       | Forward to dynamic_microservice:8000 |
| POST   | /analyze/speakeasy     | Forward to speakeasy_emulator:8001   |
| POST   | /analyze/ai            | Forward to ai_analysis:8002          |
| POST   | /analyze/report        | Forward to pdf_png:8003              |
| POST   | /analyze/full          | Run all four sequentially            |

All POST endpoints accept `multipart/form-data` with a `file` field.

---

## Customisation

- **Change microservice URLs**: edit the `SERVICES` dict at the top of `backend/main.py`.
- **Change gateway port**: pass `--port <N>` to uvicorn, and update `const API` in `frontend/index.html`.
- **Add auth**: drop in FastAPI middleware or a dependency on any route.
