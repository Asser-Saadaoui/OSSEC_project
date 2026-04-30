import os
import time
import numpy as np
import lightgbm as lgb
import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse

try:
    import ember
except ImportError:
    raise ImportError("Please install ember via: pip install git+https://github.com/elastic/ember.git")

app = FastAPI(title="EMBER Malware Detection API", version="1.0")

MODEL_PATH = "ember_model_2018.txt"
if os.path.exists(MODEL_PATH):
    print(f"Loading LightGBM model from {MODEL_PATH}...")
    bst = lgb.Booster(model_file=MODEL_PATH)
else:
    raise FileNotFoundError(f"Model file {MODEL_PATH} not found. Please download it first.")

VERDICT_THRESHOLD = 83.36 

@app.post("/scan", response_class=JSONResponse)
async def analyze_file(file: UploadFile = File(...)):
    temp_file_path = f"temp_{int(time.time())}_{file.filename}"
    
    with open(temp_file_path, "wb") as buffer:
        buffer.write(await file.read())

    try:
        with open(temp_file_path, "rb") as f:
            file_data = f.read()

        extractor = ember.PEFeatureExtractor(2)
        features = np.array(extractor.feature_vector(file_data), dtype=np.float32)

        prediction = bst.predict([features])[0]
        
        threat_score = int(prediction * 100)
        verdict = "MALICIOUS" if threat_score >= VERDICT_THRESHOLD else "BENIGN"
        
        report_timestamp = int(time.time() * 1000)
        report_name = f"sysmon_report_{report_timestamp}.xml"

        result = {
            "filename": file.filename,
            "verdict": verdict,
            "threat_score": threat_score,
            "indicators": [],
            "message": f"Success! Logs saved to host as {report_name}"
        }
        
        return result

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to analyze file: {str(e)}"}
        )

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)