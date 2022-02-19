import os
import argparse

from ips_description import IPSDescrption
from whitelist_generator import WhitelistGenerator

def ips2whitelist(input_desc, output_whitelist):
    with open(input_desc, "rb") as description_file:
        raw_description = description_file.readlines()
    
    description_obj = IPSDescrption(raw_description=raw_description)
    description_obj.display()

    with open(output_whitelist, "w") as whitelist_file:
        for whitelist_rule in WhitelistGenerator(description_obj):
            whitelist_file.write(whitelist_rule + '\n')
            print(whitelist_rule)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Transfer ips output descriptions to whitelist rules.')
    parser.add_argument('input_desc', type=str, help='Input ips output description file')
    parser.add_argument('output_whitelist', type=str, help='Whitelist rules output')

    args = parser.parse_args()
    ips2whitelist(args.input_desc, args.output_whitelist)
