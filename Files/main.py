#!/usr/bin/env python3
#coding: utf-8

import argparse
import configparser
from libraries.breakingood import Breakingood

def config_parser():
    config = configparser.ConfigParser()
    config.read("config.cfg")
    return config


def arg_parser(config):
    parser = argparse.ArgumentParser(description="Modifies original malware by \
                                appending bytes of data and strings to it")
    parser.add_argument("folder", type=str, nargs="?", 
                        default=config["SETTINGS"]["RESULTS_PATH"],
                        help="folder to save the results")
    parser.add_argument("malware", type=str, nargs="?", 
                        default=config["SETTINGS"]["MALWARE_PATH"], 
                        help="path of the malware")
    parser.add_argument("goodware", type=str, nargs="?",
                        default=config["SETTINGS"]["GOODWARE_PATH"],
                        help="path of the goodware")
    parser.add_argument("--nsave", action="store_true", help="Doesnt save files when used")
    parser.add_argument("--ncolor", action="store_true", help="Doesnt display colors in output")
    parser.add_argument("--nprint", action="store_true", help="DOesnt print the output")
    return parser.parse_args()


def main():
    config = config_parser()
    args = arg_parser(config)


    bg = Breakingood()
    bg.build_adversaries(args.malware,args.goodware)
    bg.handle_virus_total(key=config["SETTINGS"]["KEY"])
    bg.handle_results_table()

if __name__ == "__main__":
    main()