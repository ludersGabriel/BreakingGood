import requests
import sys

class handle_api:
    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"
    #VIRUS TOTAL PERSONAL KEY AS STRING
    key = "7c4c63de83977f7e28e966435e83d672302ac8d9c07e31741973d572fbaaee00"

    def __init__(self, temp_dir, nsave):
        self.temp_dir = temp_dir
        self.nsave = nsave
    
    def file_scan(self, malware):
        if not self.key:
            print("No key add in libraries/vtapi.py")
            sys.exit(2)

        params = {"key": self.key}
        files = {"file": (malware, open(malware, "rb"))}
        response = requests.post(self.scan_url, files=files, params=params)
        return response.json()

    def file_report(self, malware_id):
        params = {"key": self.key, "resource": malware_id}
        response = requests.get(self.report_url, params)
        return response.json()
