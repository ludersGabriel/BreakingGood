import sys
import os
import argparse
import time
import json
import pefile
import magic
from libraries import data_treatment, malware_manipulation, vtapi


class Breakingood():
    bgResults = "bgResults"
    injectionPath = "libraries/injection.py"

    def __init__(self, key="", nsave=False, ncolor=False, nprint=False):
        self.key = key
        self.nsave = nsave
        self.ncolor = ncolor
        self.nprint = nprint

    def open_file(self, name, mode):
        file = open(name, mode)
        if file.closed:
            print("Could not open {name}".format(name=name))
            sys.exit(1)
        return file

    
    def check_exe(self, path):
        s = magic.from_file(path)
        s = s.split(" ")

        if s[0] != "PE32" and s[0] != "PE32+":
            print("{file}'s Not a PE executable".format(file=path))
            sys.exit(2)

        try:
            pefile.PE(path, fast_load=True)
        except pefile.PEFormatError as e:
            print("PEFormat error: %s" % e.value)
            sys.exit(2)

        return s[0]

    
    def files_in(self, path):
        files = os.popen("ls {folder}".format(folder=path)).read()
        files = list(files.split("\n"))
        del files[len(files) - 1]

        if not files: return None
        return files

    
    def add_bytes(self, malwarePath, resultsPath):
        malware = malware_manipulation.append(resultsPath)
        malware.add_bytes(malwarePath)

    
    def add_strings(self, malwarePath, goodwarePath, resultsPath):
        malware = malware_manipulation.append(resultsPath)
        malware.add_strings(goodwarePath, malwarePath)

    
    def append_goodware_sections(self, malwarePath, goodwarePath, resultsPath):
        dis =malware_manipulation.disassemble(resultsPath)
        dis.append_goodware_sections(malwarePath, goodwarePath)

    
    def swap_ret_nop(self, malwarePath, offset, resultsPath):
        dis = malware_manipulation.disassemble(resultsPath)
        dis.swap_ret_nop(malwarePath, offset)
    
    
    def replace_int3_addSub(self, malwarePath, resultsPath):
        dis = malware_manipulation.disassemble(resultsPath)
        dis.replace_int3_addSub(malwarePath)

    
    def handle_virus_total(self, resultsPath=bgResults, key=None):
        if key is None:
            key = self.key

        files = self.files_in(resultsPath)
        if not files:
            print("No files to analyze")
            sys.exit(2)
        api = vtapi.handle_api(resultsPath, key)

        for file in files:
            api_file = "{folder}/{file}".format(folder=resultsPath, file=file)
            scan = api.file_scan(api_file)
            
            report = api.file_report(scan["md5"])
            print("[+]Waiting for Virus Total Response..")
            while report["response_code"] != 1:
                time.sleep(60)
                print("[+]Waiting for Virus Total Response..")
                report = api.file_report(scan["md5"])

            name = "{folder}/{file}.vt".format(folder=resultsPath, file=file)
            save_file = self.open_file(name, "w")
            save_file.write(json.dumps(report))
            save_file.close()
            time.sleep(60)

    
    def handle_results_table(self, resultsPath=bgResults, ncolor=None, 
                            nprint=None, nsave=None):
        if ncolor is None:
            ncolor = self.ncolor
        if nprint is None:
            nprint = self.nprint
        if nsave is None:
            nsave = self.nsave

        dm = data_treatment.data_manager(resultsPath, ncolor, nprint, nsave)
        dm.detection_table()

    
    def build_adversaries(self, malwarePath=None, goodwarePath=None, 
                        resultsPath=bgResults, raw=True, strings=True, gwa=True,
                        swap=True, replace=True):
        if not malwarePath:
            print("No malware specified")
            sys.exit(2)
        if not goodwarePath:
            print("No goodware specified")
            sys.exit(2)
        
        if raw:
            print("[+]Working on raw byte append (.BYTE)..")
            self.add_bytes(malwarePath, resultsPath)
        if strings:
            print("[+]Working on goodware string append (.STRING)..")
            self.add_strings(malwarePath, goodwarePath, resultsPath)
        if gwa:
            print("[+]Working on goodware sections append (.GWA)..")
            self.append_goodware_sections(malwarePath, goodwarePath, resultsPath)
        if swap:
            print("[+]Working on swap ret with nop (.SWAP)..")
            self.swap_ret_nop(malwarePath, 3, resultsPath)
        if replace:
            print("[+]Working on replace int3 with addSub (.ADDSUB)..")
            self.replace_int3_addSub(malwarePath, resultsPath)