#!/usr/bin/env python

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
    
    g.define_vpc(config["vpc"])

    for s in config["subnets"]:
        g.define_subnet(s, config["vpc"]["name"])
    
    for rt in config["route_tables"]:
        g.define_route_table(rt, config["vpc"]["name"])
        for r in rt["routes"]:
            g.define_route(r, rt["name"])

    for acl in config["acls"]:
        g.define_network_acl(acl, config["vpc"]["name"])
        
    for sg in config["security_groups"]:
        g.define_security_group(sg, config["vpc"]["name"])
    
    for nat_device in config["nat_devices"]:   
        g.define_nat_device(nat_device)
    for bastion_host in config["bastion_hosts"]:   
        g.define_nat_device(bastion_host)
    
    for cc in config["cache_clusters"]:
        g.define_cache_culster(cc)
    
    return g.template

def main():
    args = parse_args()
    config = parse_config(args.config_file)
    template = create_template(config)
    print(template.to_json())
    
    
if __name__ == '__main__':
    main()
