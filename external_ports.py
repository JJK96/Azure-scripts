from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.core.tools import parse_resource_id
import os

sub_id = os.getenv("AZURE_SUBSCRIPTION_ID")
client = NetworkManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
resources = ResourceManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)

def get_ip_ports():
    for ip in client.public_ip_addresses.list_all():
        parts = parse_resource_id(ip.ip_configuration.id)
        if parts['type'] == 'bastionHosts':
            continue
        provider = resources.providers.get(parts['namespace'])
        type = parts['type']
        rt = next((t for t in provider.resource_types if t.resource_type.lower() == type.lower()), None)
        api_version = rt.api_versions[0]
        split = ip.ip_configuration.id.split('/')
        id = '/'.join(split[:9])
        resource = resources.resources.get_by_id(id, api_version)
        match resource.type:
            case "Microsoft.Network/loadBalancers":
                rules = resource.properties['loadBalancingRules']
                for rule in rules:
                    yield ip.ip_address, rule['properties']['frontendPort']
            case _:
                raise Exception(f"Type {resource.type} not handled")


for ip, port in get_ip_ports():
    print(f"{ip}:{port}")

