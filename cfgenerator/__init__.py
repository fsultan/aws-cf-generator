#!/usr/bin/env python

import re
import troposphere.ec2 as ec2
#import troposphere.iam as iam
import troposphere.elasticache as elasticache
import troposphere.elasticbeanstalk as elasticbeanstalk
from troposphere import Template, Tags, Ref, Parameter, Output


IP_CIDR_RE  = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$")

PROTOCOLS = {
    "hopopt": 0,
    "icmp": 1,
    "igmp": 2,
    "ggp": 3,
    "ipv4": 4,
    "st": 5,
    "tcp": 6,
    "cbt": 7,
    "egp": 8,
    "igp": 9,
    "bbn-rcc-mon": 10,
    "nvp-ii": 11,
    "pup": 12,
    "argus": 13,
    "emcon": 14,
    "xnet": 15,
    "chaos": 16,
    "udp": 17,
    "mux": 18,
    "dcn-meas": 19,
    "hmp": 20,
    "prm": 21,
    "xns-idp": 22,
    "trunk-1": 23,
    "trunk-2": 24,
    "leaf-1": 25,
    "leaf-2": 26,
    "rdp": 27,
    "irtp": 28,
    "iso-tp4": 29,
    "netblt": 30,
    "mfe-nsp": 31,
    "merit-inp": 32,
    "dccp": 33,
    "3pc": 34,
    "idpr": 35,
    "xtp": 36,
    "ddp": 37,
    "idpr-cmtp": 38,
    "tp++": 39,
    "il": 40,
    "ipv6": 41,
    "sdrp": 42,
    "ipv6-route": 43,
    "ipv6-frag": 44,
    "idrp": 45,
    "rsvp": 46,
    "gre": 47,
    "dsr": 48,
    "bna": 49,
    "esp": 50,
    "ah": 51,
    "i-nlsp": 52,
    "swipe": 53,
    "narp": 54,
    "mobile": 55,
    "tlsp": 56,
    "skip": 57,
    "ipv6-icmp": 58,
    "ipv6-nonxt": 59,
    "ipv6-opts": 60,
    "any": 61,
    "cftp": 62,
    "any": 63,
    "sat-expak": 64,
    "kryptolan": 65,
    "rvd": 66,
    "ippc": 67,
    "any": 68,
    "sat-mon": 69,
    "visa": 70,
    "ipcv": 71,
    "cpnx": 72,
    "cphb": 73,
    "wsn": 74,
    "pvp": 75,
    "br-sat-mon": 76,
    "sun-nd": 77,
    "wb-mon": 78,
    "wb-expak": 79,
    "iso-ip": 80,
    "vmtp": 81,
    "secure-vmtp": 82,
    "vines": 83,
    "ttp": 84,
    "iptm": 84,
    "nsfnet-igp": 85,
    "dgp": 86,
    "tcf": 87,
    "eigrp": 88,
    "ospfigp": 89,
    "sprite-rpc": 90,
    "larp": 91,
    "mtp": 92,
    "ax.25": 93,
    "ipip": 94,
    "micp": 95,
    "scc-sp": 96,
    "etherip": 97,
    "encap": 98,
    "any": 99,
    "gmtp": 100,
    "ifmp": 101,
    "pnni": 102,
    "pim": 103,
    "aris": 104,
    "scps": 105,
    "qnx": 106,
    "a/n": 107,
    "ipcomp": 108,
    "snp": 109,
    "compaq-peer": 110,
    "ipx-in-ip": 111,
    "vrrp": 112,
    "pgm": 113,
    "any": 114,
    "l2tp": 115,
    "ddx": 116,
    "iatp": 117,
    "stp": 118,
    "srp": 119,
    "uti": 120,
    "smp": 121,
    "sm": 122,
    "ptp": 123,
    "isis": 124,
    "fire": 125,
    "crtp": 126,
    "crudp": 127,
    "sscopmce": 128,
    "iplt": 129,
    "sps": 130,
    "pipe": 131,
    "sctp": 132,
    "fc": 133,
    "rsvp-e2e-ignore": 134,
    "mobility": 135,
    "udplite": 136,
    "mpls-in-ip": 137,
    "manet": 138,
    "hip": 139,
    "shim6": 140,
    "wesp": 141,
    "rohc": 142,
#    "unassigned": 143-252,
#    "exp": 253,
#    "test": 254,
#    "reserved": 255,
}

class Generator(object):
    def __init__(self, name):
        self.name = name
        self.template = Template()
        self.default_tags = None
        self.object_map = {}

    def set_defaults(self, defaults):
        self.default_tags = defaults["tags"]
        self.deletion_policy = defaults["deletion_policy"]

    def _get_tags(self, config):
        tag = {}
        conf_tags = []
        conf_tags.extend(self.default_tags)
        try:
            conf_tags.extend(config["tags"])
        except KeyError:
            pass
        for t in conf_tags:
            k,v = t.split("=")
            tag[k] = v
        tags_list = [t.split("=") for t in conf_tags]
        tags_objects = Tags(**dict(tags_list))

        return tags_objects


    def _protocol_int(self, protocol):
        i = PROTOCOLS[protocol]
        return i


    def _port_range(self, port_range):
        try:
            (_from, _to) =  port_range.split(",")
            p = ec2.PortRange(From=_from,To=_to)
            return p
        except ValueError as e:
            #if isinstance( port_range, ( int, long ) ):
            #    return ec2.PortRange(From=port_range,To=port_range)
            #else:
            print "_port_range: ValueError - input: %s" % port_range
            raise

    def _add_resource(self, resource):
        self.template.add_resource(resource)
        #self.object_map[resource.name] = Ref(resource)


#    def define_role(self,role_config):
#        role = iam.Role(role_config["name"],
#                        DeletionPolicy=self.deletion_policy)
#        pass

    def define_parameter(self, parameter_config):
        """

  "parameters" : [
    {
    "name" : "",
    "type": "",
    "default": "",
    "no_echo": "",
    "allowed_values": "",
    "allowed_pattern": "",
    "max_length": "",
    "min_length": "",
    "max_value": "",
    "min_value": "",
    "description": "",
    "constraint_description": ""
    },

  ],

        """
        p = Parameter(parameter_config["name"])
        p.Type = parameter_config["type"]
        p.Default = parameter_config["default"]
        p.NoEcho = parameter_config["no_echo"]
        p.AllowedValues = parameter_config["allowed_values"]
        p.AllowedPattern = parameter_config["allowed_pattern"]
        p.MaxLength = parameter_config["max_length"]
        p.MinLength = parameter_config["min_length"]
        p.MaxValue = parameter_config["max_value"]
        p.MinValue = parameter_config["min_value"]
        p.Description = parameter_config["description"]
        p.ConstraintDescription = parameter_config["constraint_description"]

        return p


    def define_parameters(self, parameters_config):
        for parameter_config in parameters_config:
            p = self.define_parameter(parameter_config)
            self.add_parameter(p)


    def define_vpc(self, vpc_config):
        vpc = ec2.VPC(vpc_config["name"],
                      DeletionPolicy=self.deletion_policy)
        vpc.CidrBlock = vpc_config["cidr_block"]
        vpc.EnableDnsSupport = vpc_config["dns_support"]
        vpc.EnableDnsHostnames = vpc_config["dns_hostnames"]
        vpc.Tags = self._get_tags(vpc_config)

        self._add_resource(vpc)

        if vpc_config["internet_gateway"]:
            ig = ec2.InternetGateway(vpc_config["internet_gateway"]["name"],
                                     DeletionPolicy=self.deletion_policy)
            ig.Tags = self._get_tags(vpc_config["internet_gateway"])
            self.template.add_resource(ig)

            iga = ec2.VPCGatewayAttachment(
                "%sAttachment" % vpc_config["internet_gateway"]["name"],
                DependsOn=ig.name,
                DeletionPolicy=self.deletion_policy)
            iga.VpcId = Ref(vpc)
            iga.InternetGatewayId = Ref(ig)
            self.template.add_resource(iga)


    def define_network_interface_property(self, _int_config):
        interface = ec2.NetworkInterfaceProperty(_int_config["name"])
        interface.SubnetId = Ref(_int_config["subnet"])
        interface.AssociatePublicIpAddress = _int_config["is_public"]
        interface.DeviceIndex = str(_int_config["index"])

        return interface


    def define_nat_device(self, nat_device_config):
        nat_device = ec2.Instance(
            nat_device_config["name"],
            DeletionPolicy=self.deletion_policy)
        nat_device.InstanceType = nat_device_config["instance_type"]
        nat_device.ImageId = nat_device_config["image_id"]
        nat_device.KeyName = nat_device_config["key_name"]
        if nat_device_config.get("iam_profile"):
            nat_device.IamInstanceProfile = nat_device_config["iam_profile"]
        #nat_device.SecurityGroupIds = [
        #    Ref(x) for x in nat_device_config["security_groups"]]
        nat_device.SourceDestCheck = False
        nat_device.Tags = self._get_tags(nat_device_config)

        if nat_device_config["use_eip"]:
            nat_device.SubnetId = Ref(nat_device_config["subnet"])
            self.define_instance_eip(nat_device_config["eip"], nat_device)
        elif nat_device_config["interfaces"]:
            for _int in nat_device_config["interfaces"]:
                interface = self.define_network_interface_property(_int)
                nat_device.NetworkInterfaces = [interface]
        else:
            nat_device.SubnetId = Ref(nat_device_config["subnet"])

        self._add_resource(nat_device)


    def define_bastion_host(self, bastion_host_config):
        bastion_host = ec2.Instance(
            bastion_host_config["name"],
            DeletionPolicy=self.deletion_policy)
        bastion_host.InstanceType = bastion_host_config["instance_type"]
        bastion_host.ImageId = bastion_host_config["image_id"]
        bastion_host.KeyName = bastion_host_config["key_name"]

        bastion_host.Tags = self._get_tags(bastion_host_config)

        if bastion_host_config["use_eip"]:
            bastion_host.SubnetId = Ref(bastion_host_config["subnet"])
            self.define_instance_eip(bastion_host_config["eip"], bastion_host)
        elif bastion_host_config["interfaces"]:
            for _int in bastion_host_config["interfaces"]:
                interface = self.define_network_interface_property(_int)
                bastion_host.NetworkInterfaces = [interface]
        else:
            bastion_host.SubnetId = Ref(bastion_host_config["subnet"])

        self._add_resource(bastion_host)



    def define_instance_eip(self,nat_ip_config, nat_device):
        nat_ip = ec2.EIP(nat_ip_config["name"],
                         DependsOn="InternetGatewayAttachment",
                         DeletionPolicy=self.deletion_policy)
        nat_ip.InstanceId = Ref(nat_device)
        nat_ip.Domain = "vpc"

        self._add_resource(nat_ip)
        self.assign_instance_eip(nat_device, nat_ip)


    def assign_instance_eip(self, instance, eip):
        name = "%s%s" % (instance.name, eip.name)
        a = ec2.EIPAssociation(name)
        a.EIP = Ref(eip)
        a.InstanceId = Ref(instance)

        self._add_resource(a)


    def assign_subnet_route_table(self, subnet, route_table):
        name = "%s%s" % (subnet, route_table.name)
        a = ec2.SubnetRouteTableAssociation(name,
                                            DeletionPolicy=self.deletion_policy)
        a.SubnetId = Ref(subnet)
        a.RouteTableId = Ref(route_table)

        self._add_resource(a)


    def define_route_table(self, route_table_config, vpc_name):
        route_table = ec2.RouteTable(route_table_config["name"],
                                     DeletionPolicy=self.deletion_policy)
        route_table.VpcId = Ref(self.template.resources[vpc_name])
        route_table.Tags = self._get_tags(route_table_config)

        self._add_resource(route_table)

        for subnet in route_table_config["subnets"]:
            self.assign_subnet_route_table(subnet, route_table)

        return Ref(route_table)


    def define_route(self, route_config, route_table):
        route = ec2.Route(route_config["name"],
                          DependsOn=route_config["target_id"],
                          DeletionPolicy=self.deletion_policy)
        route.RouteTableId = Ref(route_table)
        route.DestinationCidrBlock = route_config["dest_cidr"]
        target = route_config["target_type"]
        if target == "Gateway":
            route.GatewayId = Ref(route_config["target_id"])
            #route.DependsOn = "target_id"
        elif target == "Instance":
            route.InstanceId = Ref(route_config["target_id"])
        elif target == "NetworkInterfaceId":
            route.NetworkInterfaceId = Ref(route_config["target_id"])
        else:
            raise Exception("%s is not a valid target_type", target)

        self._add_resource(route)


    def define_subnet(self, subnet_config, vpc_name):
        subnet = ec2.Subnet(subnet_config["name"],
                            DeletionPolicy=self.deletion_policy)
        #print("creating subnet in %s" % defaults["vpc_id"])
        subnet.VpcId = Ref(self.template.resources[vpc_name])
        subnet.AvailabilityZone = subnet_config["availability_zone"]
        subnet.CidrBlock = subnet_config["cidr_block"]
        subnet.Tags = self._get_tags(subnet_config)

        self._add_resource(subnet)


    def parse_acl_entry(self, acl, line, egress, suffix=""):
        name = "".join([suffix, line[0]])
        entry = ec2.NetworkAclEntry(name,
                                    DependsOn=acl.name,
                                    DeletionPolicy=self.deletion_policy)
        entry.NetworkAclId = Ref(acl)
        entry.RuleNumber = line[0]
        entry.Protocol = self._protocol_int(line[1])
        entry.CidrBlock = line[2]
        entry.PortRange = self._port_range(line[3])
        entry.RuleAction = line[4]
        entry.Egress = egress

        return entry


    def define_subnet_network_acl(self, subnet, acl):
        name = "%s%s" % (subnet, acl.name)
        a = ec2.SubnetNetworkAclAssociation(name,
                                            DeletionPolicy=self.deletion_policy)
        a.SubnetId = Ref(subnet)
        a.NetworkAclId = Ref(acl)

        self._add_resource(a)


    def define_network_acl(self, acl_config, vpc):
        acl = ec2.NetworkAcl(acl_config["name"],
                             DeletionPolicy=self.deletion_policy)
        acl.VpcId = Ref(vpc)
        acl.Tags = self._get_tags(acl_config)

        self._add_resource(acl)

        ingress_suffix = "%s%s" % (acl_config["name"], "Ingress")
        egress_suffix = "%s%s" % (acl_config["name"], "Egress")

        for line in acl_config["ingress"]:
            i_entry = self.parse_acl_entry(acl, line, False, ingress_suffix)
            self._add_resource(i_entry)
        for line in acl_config["egress"]:
            e_entry = self.parse_acl_entry(acl, line, True, egress_suffix)
            self._add_resource(e_entry)

        for subnet in acl_config["subnets"]:
            self.define_subnet_network_acl(subnet, acl)


    def parse_sg_ingress_entry(self, line, suffix=""):
        name = "".join([suffix, line[0], line[2]])
        name = name.replace(",","To")
        name = name.replace("-","")
        entry = ec2.SecurityGroupRule(name)
        entry.IpProtocol = line[0]
        (_from, _to) =  line[2].split(",")
        entry.FromPort = _from
        entry.ToPort = _to
        m = re.match(IP_CIDR_RE, line[1])
        if m:
            entry.CidrIp = line[1]
        else:
            entry.SourceSecurityGroupId = Ref(line[1])

        return entry

    def parse_sg_egress_entry(self, line, suffix=""):
        name = "".join([suffix, line[0], line[2]])
        name = name.replace(",","To")
        name = name.replace("-","")
        entry = ec2.SecurityGroupRule(name)
        entry.IpProtocol = line[0]
        (_from, _to) =  line[2].split(",")
        entry.FromPort = _from
        entry.ToPort = _to
        m = re.match(IP_CIDR_RE, line[1])
        if m:
            entry.CidrIp = line[1]
        else:
            entry.SourceSecurityGroupId = Ref(line[1])

        return entry


    def define_security_group(self, sg_config, vpc_name):
        sg = ec2.SecurityGroup(sg_config["name"],
                               DeletionPolicy=self.deletion_policy)
        sg.VpcId = Ref(self.template.resources[vpc_name])
        sg.GroupDescription = sg_config["description"]
        sg.Tags = self._get_tags(sg_config)

        ingress_suffix = "%s%s" % (sg_config["name"], "Ingress")
        egress_suffix = "%s%s" % (sg_config["name"], "Egress")

        ingress_entries = []
        egress_entries = []

        for line in sg_config["ingress"]:
            i_entry = self.parse_sg_ingress_entry(line, ingress_suffix)
            ingress_entries.append(i_entry)

        try:
            for line in sg_config["egress"]:
                e_entry = self.parse_sg_egress_entry(line, egress_suffix)
                egress_entries.append(e_entry)
        except KeyError:
            pass

        sg.SecurityGroupIngress = ingress_entries
        sg.SecurityGroupEgress = egress_entries

        self._add_resource(sg)

        return Ref(sg)


    def define_cache_subnet_group(self, subnet_group_config):
        sg = elasticache.SubnetGroup(subnet_group_config["name"],
                                     DeletionPolicy=self.deletion_policy)
        sg.Description = subnet_group_config["description"]
        s_ids = []
        for s in subnet_group_config["subnets"]:
            s_ids.append(Ref(s))
        sg.SubnetIds = s_ids

        self._add_resource(sg)

        return Ref(sg)


    def define_cache_culster(self, cluster_config):
        cc = elasticache.CacheCluster(
                cluster_config["name"],
                  DeletionPolicy=self.deletion_policy)
                  #DependsOn=cluster_config["security_groups"][0])
        cc.CacheNodeType = cluster_config["node_type"]
        c_sg = self.define_cache_subnet_group(cluster_config["subnet_group"])
        cc.CacheSubnetGroupName = c_sg
        cc.Engine = cluster_config["engine"]
        cc.EngineVersion = cluster_config["engine_version"]
        cc.NotificationTopicArn = cluster_config["notification_arn"]
        cc.NumCacheNodes = cluster_config["node_count"]
        sg_ids = []
        for s in cluster_config["security_groups"]:
            sg_ids.append(Ref(s))
        cc.VpcSecurityGroupIds = sg_ids
        self._add_resource(cc)

        return Ref(cc)


    def define_ebs_application(self, ebs_app_config):
        """
    "ebs_application" : {
    "application_name": "",
    "description": "",
    "enviroments" : [{
        ...
      }],
  },
        """
        app = elasticbeanstalk.Application(ebs_app_config["name"])
        app.Description = ebs_app_config["description"]
        app.ApplicationVersions = self.ebs_app_versions(
            ebs_app_config["app_versions"])
        app.ConfigurationTemplates = self.ebs_config_template(
            ebs_app_config["config_template"])
        self._add_resource(app)

        for ebs_env_config in ebs_app_config["enviroments"]:
            env = self.define_ebs_enviroment(ebs_env_config)
            self._add_resource(env)


    def define_ebs_enviroment(self, ebs_env_config):
        """
  "ebs_enviroment" : [{
    'application_name': "",
    'cname_prefix': "",
    'description': "",
    'environment_name': "",
    'option_settings': "",
    'options_to_remove': "",
    'stack_name': "",
    'template_name': "",
    'tier': "",
    'version_label': ""
  }],
        """
        env = elasticbeanstalk.Environment(ebs_env_config["application_name"])
        env.CNAMEPrefix = ebs_env_config["cname_prefix"]
        env.Description = ebs_env_config["description"]
        #env. = ebs_env_config["environment_name"]
        #env. = ebs_env_config["option_settings"]
        #env. = ebs_env_config["options_to_remove"]
        #env. = ebs_env_config["stack_name"]
        #env. = ebs_env_config["template_name"]
        #env. = ebs_env_config["tier"]
        #env. = ebs_env_config["version_label"]

        self._add_resource(env)

    def ebs_app_versions(self, app_versions):
        avs = []
        count = 0
        for app_version in app_versions:
            av = elasticbeanstalk.ApplicationVersion()
            av.Description = app_version["description"]
            av.SourceBundle = self.ebs_source_bundle(app_version["source_bundle"])
            av.VersionLabel = app_version["version_label"]
            avs.append(av)
            count += 1


    def ebs_config_template(self, ebs_config_template):
        #name = "Template%s" ebs_config_template["name"]
        ct = elasticbeanstalk.ConfigurationTemplate()
        ct.TemplateName = ebs_config_template["name"]
        ct.Description = ebs_config_template["description"]
        ct.OptionSettings = ebs_config_template["options"]
        ct.SolutionStackName = ebs_config_template["stack_name"]

        return ct


    def ebs_source_bundle(self, source_bundle_config):
        sb = elasticbeanstalk.SourceBundle()
        sb.S3Bucket = source_bundle_config[0]
        sb.S3Key = source_bundle_config[1]

        return sb


    def ebs_option_setting(self, option_config):
        os = elasticbeanstalk.OptionSettings(
            Namespace = 'TODO',
            OptionName = 'TODO',
            Value = 'TODO',
        )
