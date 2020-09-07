import requests

class handle_api:
    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"
    #VIRUS TOTAL PERSONAL KEY AS STRING
    key = ""

    def __init__(self, temp_dir, nsave):
        self.temp_dir = temp_dir
        self.nsave = nsave
    
    def file_scan(self, malware):
        params = {"key": self.key}
        files = {"file": (malware, open(malware, "rb"))}
        response = requests.post(self.scan_url, files=files, params=params)
        return response.json()

    def file_report(self, malware_id):
        params = {"key": self.key, "resource": malware_id}
        response = requests.get(self.report_url, params)
        return response.json()
