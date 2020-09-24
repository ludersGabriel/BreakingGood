#!/usr/bin/env python3
#coding: utf-8

import argparse
import configparser
import os
from libraries.breakingood import Breakingood

def config_parser():
    config = configparser.ConfigParser()
    config.read("config.cfg")
    return config


def arg_parser():
    parser = argparse.ArgumentParser(description="Modifies original malware by \
                                appending bytes of data and strings to it")
    parser.add_argument("folder", type=str, help="folder to save the results")
    parser.add_argument("malware", type=str, help="path of the malware")
    parser.add_argument("goodware", type=str, help="path of the goodware")
    parser.add_argument("key", type=str, help="key to the virus total api")
    parser.add_argument("--nsave", action="store_true", help="Doesnt save files when used")
    parser.add_argument("--ncolor", action="store_true", help="Doesnt display colors in output")
    parser.add_argument("--nprint", action="store_true", help="DOesnt print the output")
    return parser.parse_args()


def main():
    print("--------- Breaking Good 2020 - Luders ---------")

    if os.path.isfile("./config.cfg"):
        print("\t\tUsing Config File")
        config = config_parser()
        folder = config["SETTINGS"]["RESULTS_PATH"]
        malware = config["SETTINGS"]["MALWARE_PATH"]
        goodware = config["SETTINGS"]["GOODWARE_PATH"]
        key = config["SETTINGS"]["KEY"]
    else:
        args = arg_parser()
        folder = args.folder
        malware = args.malware
        goodware = args.goodware
        key = args.key

    bg = Breakingood()
    bg.build_adversaries(malware, goodware, folder)
    bg.handle_virus_total(folder, key)
    bg.handle_results_table(folder)

if __name__ == "__main__":
    main()