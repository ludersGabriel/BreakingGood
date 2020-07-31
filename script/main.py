#!/usr/bin/env python3
#coding: utf-8

import sys, os
import argparse
import time, json, pefile
import magic
import vtapi, data_treatment, malware_manipulation

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

args = arg_parser()

check_exe(args.malware)
check_exe(args.goodware)

malware = malware_manipulation.append(args.folder)
print("[+]Working on raw byte append (BYTE)..")
malware.add_bytes(args.malware)
print("[+]Working on goodware string append (STRING)..")
malware.add_strings(args.goodware, args.malware)

dis = malware_manipulation.disassemble(args.folder)
print("[+]Working on swap ret with nop (SWAP)..")
dis.swap_ret_nop(args.malware, 3)
print("[+]Working on replace int3 with addSub (ADDSUB)..")
dis.replace_int3_addSub(args.malware)
dis.append_goodware_sections(args.malware, args.goodware)

#getting the names of all the files in the temp folder
files = os.popen("ls {folder}".format(folder=args.folder)).read()
files = list(files.split("\n"))
del files[len(files) - 1]

api = vtapi.handle_api(args.folder, args.nsave)
for file in files:    
    api_file = "{folder}/{file}".format(folder=args.folder, file=file)
    scan = api.file_scan(api_file)
    
    report = api.file_report(scan["md5"])
    print("[+]Waiting for Virus Total Response..")
    while report["response_code"] != 1:
        time.sleep(60)
        print("[+]Waiting for Virus Total Response..")
        report = api.file_report(scan["md5"])

    if not api.nsave:
        name = "{folder}/{file}.vt".format(folder=args.folder, file=file)
        save_file = malware.open_file(name, "w")
        save_file.write(json.dumps(report))
        save_file.close()
    time.sleep(60)

data_manager = data_treatment.data_manager(args.folder, args.ncolor, args.nprint)
data_manager.detection_table()