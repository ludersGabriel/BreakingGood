import requests
import sys

class handle_api:
    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"

    def __init__(self, temp_dir, key):
        self.temp_dir = temp_dir
        self.key = key
    
    def file_scan(self, malware):
        if not self.key:
            print("No key passed")
            sys.exit(2)

        params = {"key": self.key}
        files = {"file": (malware, open(malware, "rb"))}
        
        try:
            response = requests.post(self.scan_url, files=files, params=params)
        except:
            print("No valid key passed or invalid virus total response")
            sys.exit(2)

        return response.json()

    def file_report(self, malware_id):
        params = {"key": self.key, "resource": malware_id}
        response = requests.get(self.report_url, params)
        return response.json()
