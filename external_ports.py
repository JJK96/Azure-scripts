from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.core.tools import parse_resource_id
import azure.core.exceptions as exceptions
import os
import logging

sub_id = os.getenv("AZURE_SUBSCRIPTION_ID")
client = NetworkManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
resources = ResourceManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)


def get_ip_ports():
    for ip in client.public_ip_addresses.list_all():
        if not ip.ip_address:
            continue
        if not ip.ip_configuration:
            continue
        parts = parse_resource_id(ip.ip_configuration.id)
        if parts['type'] == 'bastionHosts':
            continue
        provider = resources.providers.get(parts['namespace'])
        type = parts['type']
        rt = next((t for t in provider.resource_types if t.resource_type.lower() == type.lower()), None)
        api_version = rt.api_versions[0]
        split = ip.ip_configuration.id.split('/')
        id = '/'.join(split[:9])
        try:
            resource = resources.resources.get_by_id(id, api_version)
        except exceptions.ResourceNotFoundError as e:
            logging.error(e.message)
            continue
        match resource.type:
            case "Microsoft.Network/loadBalancers":
                rules = resource.properties['loadBalancingRules']
                for rule in rules:
                    yield ip.ip_address, rule['properties']['frontendPort'], ""
            case "Microsoft.Network/networkInterfaces":
                try:
                    id = resource.properties['networkSecurityGroup']['id']
                except KeyError:
                    continue
                if not 'virtualMachine' in resource.properties:
                    continue
                parts = parse_resource_id(id)
                network_security_group = client.network_security_groups.get(resource_group_name=parts['resource_group'], network_security_group_name=parts['resource_name'])
                for rule in network_security_group.security_rules:
                    if rule.direction != 'Inbound' or rule.access != 'Allow':
                        continue
                    extra_info = ""
                    if rule.protocol not in ['TCP','*']:
                        extra_info += f"{rule.protocol} "
                    if rule.source_address_prefix and rule.source_address_prefix != '*':
                        extra_info += "from: {}".format(rule.source_address_prefix)
                    if rule.source_address_prefixes:
                        extra_info += "from: {}".format(','.join(rule.source_address_prefixes))
                    if rule.source_port_range != '*':
                        extra_info += ", ports: {}".format(','.join(rule.source_port_range))
                    yield ip.ip_address, rule.destination_port_range or ','.join(rule.destination_port_ranges), extra_info
            case _:
                raise Exception(f"Type {resource.type} not handled")


if __name__ == "__main__":
    for ip, port, extra_info in get_ip_ports():
        output = f"{ip}:{port}"
        if extra_info:
            output += f" ({extra_info})"
        print(output)
