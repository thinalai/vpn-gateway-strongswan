#!/usr/bin/env python3

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--stack", default="s2svpn", help="stack name")
parser.add_argument("-tf", "--template-file",
                    default="vpn-gateway-strongswan.yml", help="template file name")
parser.add_argument("-org", "--org", default="example", help="pOrg")
parser.add_argument("-sys", "--system", default="infra", help="pSystem")
parser.add_argument("-app", "--app", default="vpngw", help="pApp")
parser.add_argument("-env", "--env", default="auto-heal", help="pEnvPurpose")
parser.add_argument("--use-elastic-ip", default="true", help="pUseElasticIp")
parser.add_argument("-eip1", help="pEipAllocationId")
parser.add_argument("-eip2", help="pEipAllocationId")
parser.add_argument("-vpc-id", help="pVpcId")
parser.add_argument("-vpc-cidr", help="pVpcCidr")
parser.add_argument("-subnet", help="pSubnetId")
parser.add_argument("-dest-vpc-cidr", default="10.0.0.0/16",
                    help="destination vpc cidr")
parser.add_argument("-instance-type", default="t2.micro", help="pInstanceType")
parser.add_argument("-vcf1", "--vpn-connection-file1",
                    help="vpn connection file 1")
parser.add_argument("-vcf2", "--vpn-connection-file2",
                    help="vpn connection file 2")
parser.add_argument("-aftf", "--auto-failover-template-file",
                    default="./vpn-guard/out.yml",
                    help="auto failover template file")


class base(object):
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)


class VPNConnConfiguration(base):
    vpn_id = ""
    vgw_id = ""
    cgw_id = ""


class IPSecTunnel(base):
    method = "psk"
    psk = ""
    vgw_outside_ip = ""
    vgw_inside_ip = ""
    cgw_outside_ip = ""
    cgw_inside_ip = ""
    cgw_asn = "65000"
    vgw_asn = "64512"
    neighbor_ip = ""


class Config(base):
    vpn = VPNConnConfiguration()
    ipsec_tunnel1 = IPSecTunnel()
    ipsec_tunnel2 = IPSecTunnel()


def parse_vpn_connection(data: str) -> VPNConnConfiguration:
    vpn = VPNConnConfiguration()
    for line in data.split("\n"):
        if line.find("Your VPN Connection ID") == 0:
            vpn.vpn_id = line.split(": ")[1]
        elif line.find("Your Virtual Private Gateway ID") == 0:
            vpn.vgw_id = line.split(": ")[1]
        elif line.find("Your Customer Gateway ID") == 0:
            vpn.cgw_id = line.split(": ")[1]
    return vpn


def parse_ipsec_tunnel(data: str) -> IPSecTunnel:
    kv_map = dict()
    for line in data.split("\n"):
        if line[:4] == "  - ":
            try:
                k, v = line[3:].split(": ")
                k = k.strip()
                if k in kv_map:
                    kv_map[k+"2"] = v.strip()
                else:
                    kv_map[k] = v
            except:
                pass
    ipsec_tunnel = IPSecTunnel()
    if kv_map["Authentication Method"] != "Pre-Shared Key":
        raise Exception("not support", kv_map["Authentication Method"])
    ipsec_tunnel.psk = kv_map["Pre-Shared Key"]
    ipsec_tunnel.vgw_outside_ip = kv_map["Virtual Private Gateway"]
    ipsec_tunnel.vgw_inside_ip = kv_map["Virtual Private Gateway2"]
    ipsec_tunnel.cgw_outside_ip = kv_map["Customer Gateway"]
    ipsec_tunnel.cgw_inside_ip = kv_map["Customer Gateway2"]
    ipsec_tunnel.cgw_asn = kv_map["Customer Gateway ASN"]
    ipsec_tunnel.vgw_asn = kv_map["Virtual Private  Gateway ASN"]
    ipsec_tunnel.neighbor_ip = kv_map["Neighbor IP Address"]
    return ipsec_tunnel


def parse(data: str) -> Config:
    arr = data.split("IPSec Tunnel #")
    if len(arr) != 3:
        raise Exception("wrong vpn config")
    config = Config()
    config.vpn = parse_vpn_connection(arr[0])
    config.ipsec_tunnel1 = parse_ipsec_tunnel(arr[1])
    config.ipsec_tunnel2 = parse_ipsec_tunnel(arr[2])
    return config


def create_or_update_secret(psk: str, name: str) -> str:
    client = boto3.client("secretsmanager")
    value = json.dumps({"psk": psk})
    try:
        resp = client.get_secret_value(SecretId=name)
        if resp["SecretString"] != value:
            print("updating secret:", name)
            print(client.update_secret(SecretId=name, SecretString=value))
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("creating secret:", name)
            resp = client.create_secret(
                Name=name, SecretString=value)
            print(resp)
        else:
            raise e
    return name


def get_eip_allocation_id(ip: str) -> str:
    client = boto3.client("ec2")
    resp = client.describe_addresses(PublicIps=[ip])
    return resp["Addresses"][0]["AllocationId"]


def generate_parameters(args, role, vpn_connection_file) -> list:
    with open(vpn_connection_file, "r") as f:
        data = f.read()
    config = parse(data)
    params = [
        {"ParameterKey": "pOrg", "ParameterValue": args.org},
        {"ParameterKey": "pSystem", "ParameterValue": args.system},
        {"ParameterKey": "pApp",
            "ParameterValue": "{}-{}".format(args.app, role)},
        {"ParameterKey": "pEnvPurpose", "ParameterValue": args.env},
        {"ParameterKey": "pAuthType",
            "ParameterValue": config.ipsec_tunnel1.method},
        {"ParameterKey": "pTunnel1PskSecretName", "ParameterValue": create_or_update_secret(
            config.ipsec_tunnel1.psk, "{}-conn-tunnel1-psk".format(role))},
        {"ParameterKey": "pTunnel1VgwOutsideIpAddress",
            "ParameterValue": config.ipsec_tunnel1.vgw_outside_ip},
        {"ParameterKey": "pTunnel1VgwInsideIpAddress",
            "ParameterValue": config.ipsec_tunnel1.vgw_inside_ip},
        {"ParameterKey": "pTunnel1CgwInsideIpAddress",
            "ParameterValue": config.ipsec_tunnel1.cgw_inside_ip},
        {"ParameterKey": "pTunnel1VgwBgpAsn",
            "ParameterValue": config.ipsec_tunnel1.vgw_asn},
        {"ParameterKey": "pTunnel1BgpNeighborIpAddress",
            "ParameterValue": config.ipsec_tunnel1.neighbor_ip},
        {"ParameterKey": "pTunnel2PskSecretName", "ParameterValue": create_or_update_secret(
            config.ipsec_tunnel2.psk, "{}-conn-tunnel2-psk".format(role))},
        {"ParameterKey": "pTunnel2VgwOutsideIpAddress",
            "ParameterValue": config.ipsec_tunnel2.vgw_outside_ip},
        {"ParameterKey": "pTunnel2VgwInsideIpAddress",
            "ParameterValue": config.ipsec_tunnel2.vgw_inside_ip},
        {"ParameterKey": "pTunnel2CgwInsideIpAddress",
            "ParameterValue": config.ipsec_tunnel2.cgw_inside_ip},
        {"ParameterKey": "pTunnel2VgwBgpAsn",
            "ParameterValue": config.ipsec_tunnel2.vgw_asn},
        {"ParameterKey": "pTunnel2BgpNeighborIpAddress",
            "ParameterValue": config.ipsec_tunnel2.neighbor_ip},
        {"ParameterKey": "pVpcId", "ParameterValue": args.vpc_id},
        {"ParameterKey": "pVpcCidr", "ParameterValue": args.vpc_cidr},
        {"ParameterKey": "pSubnetId", "ParameterValue": args.subnet},
        {"ParameterKey": "pUseElasticIp", "ParameterValue": args.use_elastic_ip},
        {"ParameterKey": "pEipAllocationId",
            "ParameterValue": get_eip_allocation_id(config.ipsec_tunnel1.cgw_outside_ip)},
        {"ParameterKey": "pLocalBgpAsn",
            "ParameterValue": config.ipsec_tunnel1.cgw_asn},
        {"ParameterKey": "pInstanceType", "ParameterValue": args.instance_type},
    ]
    return [config, params]


def create_or_update_stack(stack_name: str, template_file: str, parameters: list) -> None:
    with open(template_file, 'r') as f:
        body = f.read()
    client = boto3.client('cloudformation')
    try:
        print("creating stack:", stack_name)
        resp = client.create_stack(
            StackName=stack_name,
            TemplateBody=body,
            Parameters=parameters,
            Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            EnableTerminationProtection=True,
        )
        print(resp)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AlreadyExistsException':
            print("updating stack:", stack_name)
            # TODO: An error occurred (ValidationError) when calling the UpdateStack operation: No updates are to be performed
            resp = client.update_stack(
                StackName=stack_name,
                TemplateBody=body,
                Capabilities=["CAPABILITY_NAMED_IAM",
                              "CAPABILITY_AUTO_EXPAND"],
                Parameters=parameters,
            )
            print(resp)
        else:
            raise e


def create_or_update_auto_failover_stack(args, vpn_id: str, public_ip_main: str, public_ip_backup: str):
    params = [
        {"ParameterKey": "pVpcId", "ParameterValue": args.vpc_id},
        {"ParameterKey": "pVpnId", "ParameterValue": vpn_id},
        {"ParameterKey": "pCGWMainPublicIP", "ParameterValue": public_ip_main},
        {"ParameterKey": "pCGWBackupPublicIP", "ParameterValue": public_ip_backup},
        {"ParameterKey": "pDestinationCidrBlock",
            "ParameterValue": args.dest_vpc_cidr},
    ]
    print(params)
    create_or_update_stack("{}-guard".format(args.stack),
                           args.auto_failover_template_file, params)


def main():
    args = parser.parse_args()
    p_main = generate_parameters(args, "main", args.vpn_connection_file1)
    create_or_update_stack("{}-main".format(args.stack),
                           args.template_file, p_main[1])
    print(p_main[0].toJSON())
    p_backup = generate_parameters(args, "backup", args.vpn_connection_file2)
    create_or_update_stack("{}-backup".format(args.stack),
                           args.template_file, p_backup[1])
    print(p_backup[0].toJSON())
    create_or_update_auto_failover_stack(
        args,
        p_main[0].vpn.vpn_id,
        p_main[0].ipsec_tunnel1.cgw_outside_ip,
        p_backup[0].ipsec_tunnel1.cgw_outside_ip,
    )


if __name__ == "__main__":
    main()
