🔐 OSSEC Malware Analysis

A gateway + frontend system orchestrating four malware analysis microservices.

CyberPhoenix Team Project

ossec_malware_analysis/
├── backend/
│   ├── main.py            # FastAPI gateway (port 8080)
│   └── requirements.txt
├── frontend/
│   └── index.html         # Single-file UI (no build step)
├── .gitignore
└── README.md
🧠 Architecture
Service	Port	Endpoint called by gateway
dynamic_microservice	8000	POST /analyze
speakeasy_emulator	8001	POST /emulate
ai_analysis	8002	POST /analyze
pdf & png module	8003	POST /report
gateway (FastAPI)	8080	Orchestrates all services
⚙️ Setup & Run
1. Start all microservices

Make sure each service is running before starting the gateway:

cd dynamic_microservice && uvicorn main:app --port 8000
cd speakeasy_emulator   && uvicorn main:app --port 8001
cd ai_analysis          && uvicorn main:app --port 8002
cd pdf_png              && uvicorn main:app --port 8003
2. Setup gateway (OSSEC core)
cd ossec_malware_analysis/backend

python -m venv .venv
Activate environment:

Windows:

.venv\Scripts\activate

Linux/macOS:

source .venv/bin/activate
Install dependencies:
pip install -r requirements.txt
3. Run gateway
uvicorn main:app --host 0.0.0.0 --port 8080 --reload

Gateway:

http://localhost:8080

Docs:
http://localhost:8080/docs
4. Run frontend

Open directly:

ossec_malware_analysis/frontend/index.html

OR:

cd frontend
python -m http.server 5500

Then open:

http://localhost:5500
🌐 API Reference
Method	Route	Description
GET	/health	Check all services
POST	/analyze/dynamic	dynamic_microservice
POST	/analyze/speakeasy	speakeasy_emulator
POST	/analyze/ai	ai_analysis
POST	/analyze/report	pdf & png module
POST	/analyze/full	Run full pipeline

All POST endpoints accept:

multipart/form-data
file=<upload>
🛡️ CyberPhoenix Team

This project is developed by:

CyberPhoenix Team 🔥
Focused on malware analysis, cybersecurity automation, and AI-driven threat intelligence systems.

---

## Customisation

- **Change microservice URLs**: edit the `SERVICES` dict at the top of `backend/main.py`.
- **Change gateway port**: pass `--port <N>` to uvicorn, and update `const API` in `frontend/index.html`.
- **Add auth**: drop in FastAPI middleware or a dependency on any route.
