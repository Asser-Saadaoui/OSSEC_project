import os
from flask import Flask, request, jsonify
from static_analyzer import static_analyzer # References your static_analyzer.py

app = Flask(__name__)
analyzer = StaticAnalyzer() # Initializes the analyzer logic

@app.route('/health', methods=['GET'])
def health():
    """Service availability check."""
    return jsonify({
        "status": "active",
        "engine": "static-analysis-v1"
    }), 200

@app.route('/scan', methods=['POST'])
def scan():
    """Main analysis endpoint for PDF and PNG files."""
    if 'file' not in request.files:
        return jsonify({"error": "Missing file payload"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    # Define temporary path for processing[cite: 2]
    temp_path = os.path.join(os.getcwd(), f"processing_{file.filename}")
    
    try:
        file.save(temp_path)
        
        # Execute the static analysis logic
        results = analyzer.analyze(temp_path)
        
        return jsonify(results), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    finally:
        # Securely remove the temporary file after analysis[cite: 2]
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == '__main__':
    # Hosted on port 8003 as a standalone microservice[cite: 2]
    app.run(host='0.0.0.0', port=8003, debug=False)