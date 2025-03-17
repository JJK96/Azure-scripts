from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.mgmt.purview import PurviewManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.core.tools import parse_resource_id
import azure.core.exceptions as exceptions
import os
import logging
from functools import cache

sub_id = os.getenv("AZURE_SUBSCRIPTION_ID")
client = NetworkManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
resources = ResourceManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
storage_accounts = StorageManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
sql = SqlManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
keyvaults = KeyVaultManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
ml = AzureMachineLearningWorkspaces(credential=AzureCliCredential(), subscription_id=sub_id)
loganalytics = LogAnalyticsManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
purview = PurviewManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)
compute = ComputeManagementClient(credential=AzureCliCredential(), subscription_id=sub_id)


@cache
def get_provider(namespace):
    provider = resources.providers.get(namespace)
    return provider


@cache
def get_api_version(namespace, type):
    provider = get_provider(namespace)
    rt = next((t for t in provider.resource_types if t.resource_type.lower() == type.lower()), None)
    return rt.api_versions[0]


def get_ip_ports():
    for ip in client.public_ip_addresses.list_all():
        if not ip.ip_address:
            continue
        if not ip.ip_configuration:
            continue
        parts = parse_resource_id(ip.ip_configuration.id)
        if parts['type'] == 'bastionHosts':
            continue
        api_version = get_api_version(parts['namespace'], parts['type'])
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


def get_public_network_access_to_resources(only_public=False):
    """

    only_public: Return only the entries that allow complete public access (*)
    """
    for res in storage_accounts.storage_accounts.list():
        access_from = []
        if res.network_rule_set.default_action == "Allow":
            access_from = ["*"]
        elif not only_public:
            for rule in res.network_rule_set.resource_access_rules:
                access_from.append(f"resource {rule.resource_id}")
            for rule in res.network_rule_set.virtual_network_rules:
                if rule.action == 'Allow':
                    access_from.append(f"vnet {rule.virtual_network_resource_id}")
            for rule in res.network_rule_set.ip_rules:
                # TODO
                print("Ip rules not implemented yet")
                print(rule.as_dict())
        if access_from:
            yield {
                'name': res.name,
                'access_from': access_from
            }
    if not only_public:
        # SQL servers cannot be just publicly reachable
        for res in sql.servers.list():
            if res.public_network_access == "Enabled":
                # This does not mean public acccess, but "Selected networks"
                access_from = []
                rg = res.id.split('/')[4]
                for rule in sql.virtual_network_rules.list_by_server(rg, res.name):
                    # TODO this is untested
                    if rule.action == 'Allow':
                        access_from.append(f"vnet {rule.virtual_network_resource_id}")
                for rule in sql.firewall_rules.list_by_server(rg, res.name):
                    if rule.start_ip_address == rule.end_ip_address:
                        access_from.append(f"ip address {rule.start_ip_address}")
                    else:
                        access_from.append(f"ip addresses {rule.start_ip_address}-{rule.end_ip_address}")
                yield {
                    'name': res.name,
                    'access_from': access_from
                }
    for res in keyvaults.vaults.list():
        vault = keyvaults.vaults.get(res.id.split('/')[4], res.name)
        if vault.properties.public_network_access == 'Enabled':
            yield {
                'name': res.name,
                'access_from': ["*"]
            } 
    for res in ml.workspaces.list_by_subscription():
        # workspace = ml.workspaces.get(res.id.split('/')[4], res.name)
        # TODO Workspace object does not contain the publicNetworkAccess flag, manual check required
        if res.private_link_count == 0:
            # No private links, likely publicly accessible
            yield {
                'name': res.name,
                'access_from': ["*"]
            }
    for res in loganalytics.workspaces.list():
        if res.public_network_access_for_ingestion == 'Enabled' or res.public_network_access_for_query == 'Enabled':
            yield {
                'name': res.name,
                'access_from': ["*"]
            }
    for res in purview.accounts.list_by_subscription():
        if res.public_network_access == "Enabled":
            yield {
                'name': res.name,
                'access_from': ["*"]
            }
    for res in compute.disks.list():
        if res.public_network_access == "Enabled":
            yield {
                'name': res.name,
                'access_from': ["*"]
            }
    # TODO azure data factory, application insights, databricks workspace


def print_network_access_to_resources(only_public=False):
    for res in get_public_network_access_to_resources(only_public=only_public):
        if only_public:
            print(res['name'])
        else:
            print(f"{res['name']}:")
            for entry in res['access_from']:
                print(f"    {entry}")

def print_public_ips():
    for ip, port, extra_info in get_ip_ports():
        output = f"{ip}:{port}"
        if extra_info:
            output += f" ({extra_info})"
        print(output)

if __name__ == "__main__":
    print_public_ips()
    print_network_access_to_resources(only_public=True)
