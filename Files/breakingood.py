import sys
import os
import argparse
import time
import json
import pefile
import magic
from libraries import data_treatment, malware_manipulation, vtapi


class Breakingood():
    @staticmethod
    def open_file(name, mode):
        file = open(name, mode)
        if file.closed:
            print("Could not open {name}".format(name=name))
            sys.exit(1)
        return file


    @staticmethod
    def arg_parser():
        parser = argparse.ArgumentParser(description="Modifies original malware by \
                                    appending bytes of data and strings to it")
        parser.add_argument("folder", type=str, help="name of the temp_folder to save data")
        parser.add_argument("malware", type=str, help="name of the malware")
        parser.add_argument("goodware", type=str, help="name of the goodware")
        parser.add_argument("--nsave", action="store_true", help="Doesnt save files when used")
        parser.add_argument("--ncolor", action="store_true", help="Doesnt display colors in output")
        parser.add_argument("--nprint", action="store_true", help="DOesnt print the output")
        return parser.parse_args()

    @staticmethod
    def check_exe(path):
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

    @staticmethod
    def files_in(path):
        files = os.popen("ls {folder}".format(folder=path)).read()
        files = list(files.split("\n"))
        del files[len(files) - 1]

        if not files: return None
        return files

    @staticmethod
    def add_bytes(malwarePath, resultsPath):
        malware = malware_manipulation.append(resultsPath)
        malware.add_bytes(malwarePath)

    @staticmethod
    def add_strings(malwarePath, goodwarePath, resultsPath):
        malware = malware_manipulation.append(resultsPath)
        malware.add_strings(goodwarePath, malwarePath)

    @staticmethod
    def append_goodware_sections(malwarePath, goodwarePath, resultsPath):
        dis =malware_manipulation.disassemble(resultsPath)
        dis.append_goodware_sections(malwarePath, goodwarePath)

    @staticmethod
    def swap_ret_nop(malwarePath, offset, resultsPath):
        dis = malware_manipulation.disassemble(resultsPath)
        dis.swap_ret_nop(malwarePath, offset)
    
    @staticmethod
    def replace_int3_addSub(malwarePath, resultsPath):
        dis = malware_manipulation.disassemble(resultsPath)
        dis.replace_int3_addSub(malwarePath)

    @staticmethod
    def handle_virus_total(resultsPath, nsave=False):
        files = Breakingood.files_in(resultsPath)
        if not files:
            print("No files to analyze")
            sys.exit(2)
        api = vtapi.handle_api(resultsPath, nsave)

        for file in files:
            api_file = "{folder}/{file}".format(folder=resultsPath, file=file)
            scan = api.file_scan(api_file)
            
            report = api.file_report(scan["md5"])
            print("[+]Waiting for Virus Total Response..")
            while report["response_code"] != 1:
                time.sleep(60)
                print("[+]Waiting for Virus Total Response..")
                report = api.file_report(scan["md5"])

            if not nsave:
                name = "{folder}/{file}.vt".format(folder=resultsPath, file=file)
                save_file = Breakingood.open_file(name, "w")
                save_file.write(json.dumps(report))
                save_file.close()
            time.sleep(60)

    @staticmethod
    def handle_results_table(resultsPath, ncolor, nprint):
        data_manager = data_treatment.data_manager(resultsPath, ncolor, nprint)
        data_manager.detection_table()


    @staticmethod
    def example(malwarePath=None, goodwarePath=None, resultsPath="./bgResults",
                nsave=False, ncolor=False, nprint=False, raw=True, strings=True,
                gwa=True, swap=True, replace=True):
        if not malwarePath:
            print("No malware specified")
            sys.exit(2)
        if not goodwarePath:
            print("No goodware specified")
            sys.exit(2)
        
        if raw:
            print("[+]Working on raw byte append (.BYTE)..")
            Breakingood.add_bytes(malwarePath, resultsPath)
        if strings:
            print("[+]Working on goodware string append (.STRING)..")
            Breakingood.add_strings(malwarePath, goodwarePath, resultsPath)
        if gwa:
            print("[+]Working on goodware sections append (.GWA)..")
            Breakingood.append_goodware_sections(malwarePath, goodwarePath, resultsPath)
        if swap:
            print("[+]Working on swap ret with nop (.SWAP)..")
            Breakingood.swap_ret_nop(malwarePath, 3, resultsPath)
        if replace:
            print("[+]Working on replace int3 with addSub (.ADDSUB)..")
            Breakingood.replace_int3_addSub(malwarePath, resultsPath)

        Breakingood.handle_virus_total(resultsPath, nsave)
        Breakingood.handle_results_table(resultsPath, ncolor, nprint)


def main():

    args = Breakingood.arg_parser()

    Breakingood.example(args.malware, args.goodware, args.folder, args.nsave,
                        args.ncolor, args.nprint)


if __name__ == "__main__":
    main()