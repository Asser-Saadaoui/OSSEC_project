import os
import time
import subprocess
import urllib.request
from fastapi import FastAPI, UploadFile, File, HTTPException
import engine  # <-- Imports your separate engine.py file

# Initialize the FastAPI web server
app = FastAPI(title="Malware Sandbox Web Interface")

# --- Configuration ---
VM_NAME = "windows10"
SNAPSHOT_NAME = "Clean_Listening_State"
VBOXMANAGE_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
AGENT_URL = "http://192.168.56.103:8000"

# ==========================================
# 1. Health Check Endpoint
# ==========================================
@app.get("/health")
async def health_check():
    """
    Visit http://localhost:8000/health in your browser to test this!
    """
    return {
        "status": "online",
        "message": "The Malware Sandbox Microservice is alive and listening!",
        "port": 8000
    }

# ==========================================
# 2. Main Analysis Web Endpoint
# ==========================================
@app.post("/analyze/")
async def analyze_file(file: UploadFile = File(...)):
    """
    Upload a file via the web UI to trigger the VM analysis and engine.
    """
    print(f"\n[*] Starting Web Sandbox Analysis for: {file.filename}")
    
    temp_xml_path = "sysmon_report.xml"
    
    # --- FIX: Read malware directly into Host RAM! ---
    # This completely bypasses saving it to the host hard drive, 
    # preventing your host AV from deleting it before it sends.
    file_bytes = await file.read()

    try:
        print("[*] Step 0: Ensuring VM is powered off before restoring...")
        subprocess.run([VBOXMANAGE_PATH, "controlvm", VM_NAME, "poweroff"], capture_output=True)
        time.sleep(3) 

        print("[*] Step 1: Restoring clean snapshot...")
        subprocess.run([VBOXMANAGE_PATH, "snapshot", VM_NAME, "restore", SNAPSHOT_NAME])

        print("[*] Step 2: Starting the VM...")
        subprocess.run([VBOXMANAGE_PATH, "startvm", VM_NAME])

        print("[*] Step 3: Waiting 60 seconds for network...")
        time.sleep(60)

        print(f"[*] Step 4: Sending {file.filename} to VM from memory...")
        req = urllib.request.Request(AGENT_URL, data=file_bytes, method='POST')
        req.add_header('Content-Length', str(len(file_bytes)))
        req.add_header('Original-Filename', file.filename)
        urllib.request.urlopen(req, timeout=30)

        print(f"[*] Step 5: {file.filename} is running! Waiting 120 seconds for Sysmon...")
        time.sleep(120)

        print("[*] Step 6: Requesting Sysmon logs from the VM...")
        log_req = urllib.request.Request(f"{AGENT_URL}/logs", method='GET')
        response = urllib.request.urlopen(log_req, timeout=30) 

        with open(temp_xml_path, 'wb') as f:
            f.write(response.read())

        print("[*] Step 7: Running heuristics engine...")
        verdict, indicators, score = engine.analyze_sysmon_logs(temp_xml_path)

        print(f"[*] Analysis Complete! Verdict: {verdict}")

        # Return the JSON response directly to the web interface
        return {
            "filename": file.filename,
            "verdict": verdict,
            "threat_score": score,
            "indicators": indicators,
            "message": f"Success! Logs saved to host as {temp_xml_path}"
        }

    except Exception as e:
        print(f"[X] Error during analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))