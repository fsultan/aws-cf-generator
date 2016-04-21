# -*- coding: utf-8 -*-
"""
Created on Tue Mar 18 10:35:33 2014

@author: fahd
"""

import json
import argparse
import cfgenerator

def parse_args():
    parser = argparse.ArgumentParser(
        description='aws cloudformation template generator')
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('--config', dest='config_file', required=True)

    return parser.parse_args()


def parse_config(config_file):
    json_config_file = open(config_file)
    config = json.load(json_config_file)
    json_config_file.close()

    return config

def create_template(config):
    g = cfgenerator.Generator("AWS CF Template")
    g.set_defaults(config["defaults"]) 

    g.define_parameters(config["parameters"])
    
    g.define_


def main():
    args = parse_args()
    config = parse_config(args.config_file)
    template = create_template(config)
    print(template.to_json())
    
    
if __name__ == '__main__':
    main()