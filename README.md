# OSSEC Malware Analysis System

CyberPhoenix Team Project

A microservices-based malware analysis system with a FastAPI gateway and multiple analysis services.

---

## Architecture

- dynamic_microservice → port 8000
- speakeasy_emulator → port 8001
- ai_analysis → port 8002
- pdf_png → port 8003
- gateway (FastAPI) → port 8080

---

## Setup

### 1. Run microservices

cd dynamic_microservice && uvicorn main:app --port 8000  
cd speakeasy_emulator && uvicorn main:app --port 8001  
cd ai_analysis && uvicorn main:app --port 8002  
cd pdf_png && uvicorn main:app --port 8003  

---

### 2. Run gateway

cd ossec_malware_analysis/backend  
python -m venv .venv  
.venv\Scripts\activate  

pip install -r requirements.txt  

uvicorn main:app --host 0.0.0.0 --port 8080 --reload  

---

### 3. Run frontend

Open:
ossec_malware_analysis/frontend/index.html

OR:

cd ossec_malware_analysis/frontend  
python -m http.server 5500  

Open: http://localhost:5500  

---

## API

- /health → check services
- /analyze/dynamic
- /analyze/speakeasy
- /analyze/ai
- /analyze/report
- /analyze/full

All POST requests use:
file upload (multipart/form-data)

---

## Team

CyberPhoenix Team 🔥
