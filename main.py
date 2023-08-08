import os
import boto3
import json
import urllib3


def get_cloudflare_ip_list():
    """ Call the CloudFlare API and return a list of IPs """
    http = urllib3.PoolManager()
    request = http.request('GET', 'https://api.cloudflare.com/client/v4/ips')
    temp = json.loads(request.data.decode('utf-8'))
    
    response = temp['result']
    try:
        additional_ips = os.environ[partner.upper()  + '_ADDITIONAL_IPS']
        response['ipv4_cidrs'].extend(additional_ips.split(','))
    except KeyError:
        pass
    
    if 'result' in temp:
        return temp['result']
    raise Exception("Cloudflare response error")

def get_forge_ip_list():
    """ Open the Forge txt and return a list of IPs """
    print("Checking Forge IPs")
    http = urllib3.PoolManager()
    request = http.request('GET', 'https://forge.laravel.com/ips-v4.txt').data.decode('utf-8')
    ip_addresses = []
    for address in request.split('\n'):
        if len(address) > 0:
            ip_addresses.append(address + '/32')
    response = {
        'ipv4_cidrs': ip_addresses,
        'ipv6_cidrs': []
    }
    try:
        additional_ips = os.environ[partner.upper()  + '_ADDITIONAL_IPS']
        response['ipv4_cidrs'].extend(additional_ips.split(','))
    except KeyError:
        pass

    if len(ip_addresses) > 0:
        return response
    raise Exception("Forge response error")

def get_aws_s3_bucket_policy(s3_id):
    """ Return the Policy of an S3 """
    s3 = boto3.client('s3')
    result = s3.get_bucket_policy(Bucket=s3_id)
    if 'Policy' not in result:
        raise Exception("Failed to retrieve Policy from S3 %s" % (s3_id))
    policy = json.loads(result['Policy'])
    return { 'id' : s3_id, s3_id : policy }

def get_aws_security_group(group_id):
    """ Return the defined Security Group """
    print("get_aws_security_group: %s" % (group_id))
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group
    raise Exception('Failed to retrieve Security Group')

def add_ipv4_rule(group, address, port, partner):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [
                    {
                        'CidrIp': address,
                        'Description': 'from ' + 'https://forge.laravel.com/ips-v4.txt' if partner == 'forge' else 'https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print(("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name)))

def check_ipv4_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False

def delete_ipv4_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpProtocol="tcp",
                         CidrIp=address,
                         FromPort=port,
                         ToPort=port)
    print(("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name)))


def check_ipv6_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv6_rule(group, address, port, partner):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'Ipv6Ranges': [
                    {
                        'CidrIpv6': address,
                        'Description': 'from ' + 'https://forge.laravel.com/ips-v4.txt' if partner == 'forge' else 'https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print(("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name)))


def delete_ipv6_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print(("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name)))

def get_update_ipv6():
    try:
        return bool(int(os.environ['UPDATE_IPV6']))
    except (KeyError, ValueError):
        return True

def update_security_group_policies(ip_addresses, partner):
    """ Update Information of Security Groups """
    print("Checking policies of Security Groups")

    try:
        security_groups = os.environ[partner.upper() + '_SECURITY_GROUP_IDS_LIST']
    except KeyError:
        try:
            security_groups = os.environ[partner.upper() + '_SECURITY_GROUP_ID']
        except KeyError:
            print('Missing environment variables %s and %s. Will not update security groups.' % (partner.upper() + '_SECURITY_GROUP_IDS_LIST', partner.upper() + '_SECURITY_GROUP_ID'))
            return
    print("Security Groups: %s" % (security_groups))
    security_groups = list(map(get_aws_security_group, security_groups.split(',')))

    try:
        ports = os.environ[partner.upper()  + '_PORTS_LIST']
    except KeyError:
        ports = '22' if partner == 'forge' else '80,443'

    ports = list(map(int, ports.split(',')))

    if (not ports) or (not security_groups):
        raise Exception('At least one TCP port and one security group ID are required.')

    ## Security Groups
    for security_group in security_groups:
        current_rules = security_group.ip_permissions
        for port in ports:
            ## IPv4
            # add new addresses
            for ipv4_cidr in ip_addresses['ipv4_cidrs']:
                if not check_ipv4_rule_exists(current_rules, ipv4_cidr, port):
                    add_ipv4_rule(security_group, ipv4_cidr, port, partner)


            # remove old addresses
            for rule in current_rules:
                # is it necessary/correct to check both From and To?
                if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] not in ip_addresses['ipv4_cidrs']:
                            delete_ipv4_rule(security_group, ip_range['CidrIp'], port)

            ## IPv6 -- because of boto3 syntax, this has to be separate
            if get_update_ipv6():
                # add new addresses
                for ipv6_cidr in ip_addresses['ipv6_cidrs']:
                    if not check_ipv6_rule_exists(current_rules, ipv6_cidr, port):
                        add_ipv6_rule(security_group, ipv6_cidr, port, partner)

                # remove old addresses
                for rule in current_rules:
                    if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
                        for ip_range in rule['Ipv6Ranges']:
                            if ip_range['CidrIpv6'] not in ip_addresses['ipv6_cidrs']:
                                delete_ipv6_rule(security_group, ip_range['CidrIpv6'], port)
            else:
                print('Not updating IPv6 ranges in security groups.')

def lambda_handler(event, context):
    """ AWS Lambda main function """
    print("Start")

    ip_addresses = get_cloudflare_ip_list()

    forge_ip_addresses = get_forge_ip_list()

    update_security_group_policies(ip_addresses, 'cloudflare')

    update_security_group_policies(forge_ip_addresses, 'forge')
