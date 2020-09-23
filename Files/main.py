#!/usr/bin/env python3
#coding: utf-8

import argparse
from libraries.breakingood import Breakingood as bg

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


def main():
    args = arg_parser()
    bg.example(args.malware, args.goodware, args.folder, args.nsave,
    args.ncolor, args.nprint)


if __name__ == "__main__":
    main()