import sys
import os
import argparse
import time
import json
import pefile
import magic
from libraries import data_treatment, injection, malware_manipulation, vtapi


class Breakingood():
    @staticmethod
    def __check_exe(path):
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
    def __files_in(path):
        files = os.popen("ls {folder}".format(folder=path)).read()
        files = list(files.split("\n"))
        del files[len(files) - 1]

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



def main():
    pass

if __name__ == "__main__":
    main()