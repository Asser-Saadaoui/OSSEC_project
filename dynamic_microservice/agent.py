import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

# Choose where to save the malware
SAVE_FOLDER = r"C:\Temp"
if not os.path.exists(SAVE_FOLDER):
    os.makedirs(SAVE_FOLDER)

class SandboxAgent(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Read the HTTP header you added in your host_controller!
        filename = self.headers.get('Original-Filename', 'unknown_malware.exe')
        save_path = os.path.join(SAVE_FOLDER, filename)
        
        # 2. Find out how big the file is
        content_length = int(self.headers.get('Content-Length', 0))
        
        # 3. Read the raw bytes sent by the host
        file_bytes = self.rfile.read(content_length)
        
        # 4. Save the file to disk using its EXACT original name
        print(f"[*] Received payload. Saving as {save_path}...")
        with open(save_path, 'wb') as f:
            f.write(file_bytes)
            
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"File received successfully!")
        
        # 5. Execute the malware!
        print(f"[*] Executing {filename}...")
        try:
            subprocess.Popen([save_path])
            print("[+] Execution triggered successfully.")
        except Exception as e:
            print(f"[X] Failed to execute: {e}")

    def do_GET(self):
        # Your host controller uses GET /logs to download the sysmon_report.xml
        if self.path == '/logs':
            print("[*] Host requested Sysmon logs. Exporting...")
            
            # Export Sysmon logs to an XML file using wevtutil
            export_cmd = 'wevtutil qe "Microsoft-Windows-Sysmon/Operational" /f:xml > C:\\Temp\\sysmon.xml'
            subprocess.run(export_cmd, shell=True)
            
            # Send the XML file back to the host
            try:
                with open(r"C:\Temp\sysmon.xml", 'rb') as f:
                    log_data = f.read()
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/xml')
                self.end_headers()
                self.wfile.write(log_data)
                print("[+] Logs sent to host.")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Error reading logs.")
                print(f"[X] Error reading logs: {e}")

if __name__ == "__main__":
    server_address = ('0.0.0.0', 8000)
    httpd = HTTPServer(server_address, SandboxAgent)
    print(f"[*] Sandbox Agent listening on port 8000...")
    print(f"[*] Waiting for host controller to send payload...")
    httpd.serve_forever()