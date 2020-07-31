#!/usr/bin/env python3
#coding: utf-8

import argparse
import malware_manipulation


def arg_parser():
    parser = argparse.ArgumentParser(description="Modifies original malware by \
                                appending bytes of data and strings to it")
    parser.add_argument("file1", type=str, help="path of the original malware")
    parser.add_argument("file2", type=str, help="path of the modified file")
    return parser.parse_args()

args = arg_parser()

dis = malware_manipulation.disassemble(".")
dis.diff_disasm(args.file1, args.file2)