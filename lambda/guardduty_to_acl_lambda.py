# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# MIT No Attribution
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import math
import time
import json
import logging
import os
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ======================================================================================================================
# Variables
# ======================================================================================================================

API_CALL_NUM_RETRIES = 1
ACL_METATABLE = os.environ['ACL_METATABLE']
SNS_TOPIC = os.environ['SNS_TOPIC']
CLOUDFRONT_IP_SET_ID = os.environ['CLOUDFRONT_IP_SET_ID']
CLOUDFRONT_IP_SET_NAME = os.environ['CLOUDFRONT_IP_SET_NAME']
ALB_IP_SET_ID = os.environ['ALB_IP_SET_ID']
ALB_IP_SET_NAME = os.environ['ALB_IP_SET_NAME']


# ======================================================================================================================
# Auxiliary Functions
# ======================================================================================================================

# Update WAFv2 IP set
def waf_v2_update_ip_set(waf_v2_type, update_type, ip_set_id, ip_set_name, source_ip):
    scope = 'REGIONAL'
    if waf_v2_type == 'cloudfront':
        scope = 'CLOUDFRONT'
    waf_v2 = boto3.client('wafv2')
    response = waf_v2.get_ip_set(
        Name=ip_set_name,
        Scope=scope,
        Id=ip_set_id
    )
    lock_token = response['LockToken']
    addresses = response['IPSet']['Addresses']
    if f'{source_ip}/32' not in addresses and update_type == 'INSERT':
        addresses.append(f'{source_ip}/32')
    elif f'{source_ip}/32' in addresses and update_type == 'DELETE':
        addresses.remove(f'{source_ip}/32')
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf_v2.update_ip_set(
                Name=ip_set_name,
                Scope=scope,
                Id=ip_set_id,
                Addresses=addresses,
                LockToken=lock_token
            )
            logger.info(
                f"log -- waf_update_ip_set {update_type} IP {source_ip} - "
                "IPset {ip_set_id}, WAF type {wafv2_type} successfully...")
            logger.debug(f"debug -- Update IP Set response: {response}")
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info(f"log -- waf_update_ip_set retrying in {delay} seconds...")
            time.sleep(delay)
        else:
            break
    else:
        logger.info("log -- waf_update_ip_set failed ALL attempts to call WAF API")


# Get the current NACL Id associated with subnet
def get_net_acl_id(subnet_id):
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_network_acls(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [
                        subnet_id,
                    ]
                }
            ]
        )

        net_acls = response['NetworkAcls'][0]['Associations']
        net_acl_id = -1

        for i in net_acls:
            if i['SubnetId'] == subnet_id:
                net_acl_id = i['NetworkAclId']

        return net_acl_id
    except Exception:
        return []


# Get the current NACL rules in the range 71-80
def get_nacl_rules(netacl_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            netacl_id,
        ]
    )

    nacl_rules = []

    for i in response['NetworkAcls'][0]['Entries']:
        nacl_rules.append(i['RuleNumber'])

    nacl_rulesf = list(filter(lambda x: 71 <= x <= 80, nacl_rules))

    return nacl_rulesf


# Get current DDB state data for NACL Id
def get_nacl_meta(net_acl_id):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACL_METATABLE)
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            net_acl_id,
        ]
    )
    logger.debug(f'debug -- Describe network acl response: {response}')

    # Get entries in DynamoDB table
    ddb_response = table.scan()
    # ddb_entries = response['Items']

    net_acl = ddb_response['NetworkAcls'][0]['Entries']
    nacl_entries = []

    for i in net_acl:
        nacl_entries.append(i)

    return nacl_entries


# Update NACL and DDB state table
def update_nacl(net_acl_id, host_ip, region):
    logger.info(f"log -- GD2ACL entering update_nacl, netacl_id={net_acl_id}, host_ip={host_ip}")

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACL_METATABLE)
    # timestamp = int(time.time())

    host_ip_exists = table.query(
        KeyConditionExpression=Key('NetACLId').eq(net_acl_id),
        FilterExpression=Attr('HostIp').eq(host_ip)
    )

    # Is HostIp already in table?
    if len(host_ip_exists['Items']) > 0:
        logger.info(f"log -- host IP {host_ip} already in table... exiting GD2ACL update.")

    else:

        # Get current NACL entries in DDB
        response = table.query(
            KeyConditionExpression=Key('NetACLId').eq(net_acl_id)
        )

        # Get all the entries for NACL
        nacl_entries = response['Items']

        # Find oldest rule and available rule numbers from 71-80
        if nacl_entries:
            rule_count = response['Count']
            rule_range = list(range(71, 81))

            ddb_rule_range = []
            nacl_rule_range = get_nacl_rules(net_acl_id)

            for i in nacl_entries:
                ddb_rule_range.append(int(i['RuleNo']))

            # Check state and exit if NACL rule not in sync with DDB
            ddb_rule_range.sort()
            nacl_rule_range.sort()
            sync_check = set(nacl_rule_range).symmetric_difference(ddb_rule_range)

            if ddb_rule_range != nacl_rule_range:
                logger.info(f"log -- current DDB entries, {ddb_rule_range}.")
                logger.info(f"log -- current NACL entries, {nacl_rule_range}.")
                logger.error(f'NACL rule state mismatch, {sorted(sync_check)} exiting')
                exit()

            # Determine the NACL rule number and create rule
            if rule_count < 10:
                # Get the lowest rule number available in the range
                new_rule_no = min([x for x in rule_range if x not in nacl_rule_range])

                # Create new NACL rule, IP set entries and DDB state entry
                logger.info(f"log -- adding new rule {new_rule_no}, HostIP {host_ip}, to NACL {net_acl_id}.")
                create_net_acl_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no)
                create_ddb_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no, region=region)
                waf_v2_update_ip_set('alb', 'INSERT', ALB_IP_SET_ID, ALB_IP_SET_NAME, host_ip)
                waf_v2_update_ip_set('cloudfront', 'INSERT', CLOUDFRONT_IP_SET_ID, CLOUDFRONT_IP_SET_NAME, host_ip)

                logger.info(f"log -- all possible NACL rule numbers, {rule_range}.")
                logger.info(f"log -- current DDB entries, {ddb_rule_range}.")
                logger.info(f"log -- current NACL entries, {nacl_rule_range}.")
                logger.info(f"log -- new rule number, {new_rule_no}.")
                logger.info(f"log -- rule count for NACL {net_acl_id} is {rule_count + 1}.")

            if rule_count >= 10:
                # Get oldest entry in DynamoDB table
                oldest_rule = table.query(
                    KeyConditionExpression=Key('NetACLId').eq(net_acl_id),
                    ScanIndexForward=True,  # true = ascending, false = descending
                    Limit=1,
                )

                old_rule_no = int(oldest_rule['Items'][0]['RuleNo'])
                old_rule_ts = int(oldest_rule['Items'][0]['CreatedAt'])
                old_host_ip = oldest_rule['Items'][0]['HostIp']
                new_rule_no = old_rule_no

                # Delete old NACL rule and DDB state entry
                logger.info(
                    f"log -- deleting current rule {old_rule_no} for IP {old_host_ip} from NACL {net_acl_id}.")
                delete_net_acl_rule(net_acl_id=net_acl_id, rule_no=old_rule_no)
                delete_ddb_rule(net_acl_id=net_acl_id, created_at=old_rule_ts)

                # check if IP is also recorded in a fresh finding, don't remove IP from blacklist in that case
                response_non_expired = table.scan(
                    FilterExpression=Attr('CreatedAt').gt(old_rule_ts) & Attr('HostIp').eq(host_ip))
                if len(response_non_expired['Items']) == 0:
                    waf_v2_update_ip_set('alb', 'DELETE', ALB_IP_SET_ID, ALB_IP_SET_NAME, old_host_ip)
                    waf_v2_update_ip_set('cloudfront', 'DELETE', CLOUDFRONT_IP_SET_ID, CLOUDFRONT_IP_SET_NAME,
                                         old_host_ip)
                    logger.info(
                        f'log -- deleting ALB and CloudFront WAF IP set entry for host, {old_host_ip} '
                        f'from CloudFront Ip set {CLOUDFRONT_IP_SET_ID} and ALB IP set {ALB_IP_SET_ID}.')

                # Create new NACL rule, IP set entries and DDB state entry
                logger.info(f"log -- adding new rule {new_rule_no}, HostIP {host_ip}, to NACL {net_acl_id}.")
                create_net_acl_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no)
                create_ddb_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no, region=region)
                waf_v2_update_ip_set('alb', 'INSERT', ALB_IP_SET_ID, ALB_IP_SET_NAME, host_ip)
                waf_v2_update_ip_set('cloudfront', 'INSERT', CLOUDFRONT_IP_SET_ID, CLOUDFRONT_IP_SET_NAME, host_ip)

                logger.info(f"log -- all possible NACL rule numbers, {rule_range}.")
                logger.info(f"log -- current DDB entries, {ddb_rule_range}.")
                logger.info(f"log -- current NACL entries, {nacl_rule_range}.")
                logger.info(f"log -- rule count for NACL {net_acl_id} is {int(rule_count)}.")

        else:
            # No entries in DDB Table start from 71
            nacl_rule_range = get_nacl_rules(net_acl_id)
            new_rule_no = 71
            # old_rule_no = []
            rule_count = 0
            nacl_rule_range.sort()

            # Error and exit if NACL rules already present
            if nacl_rule_range:
                logger.error(f"log -- NACL has existing entries, {nacl_rule_range}.")
                exit()

            # Create new NACL rule, IP set entries and DDB state entry
            logger.info(f"log -- adding new rule {new_rule_no}, HostIP {host_ip}, to NACL {net_acl_id}.")
            create_net_acl_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no)
            create_ddb_rule(net_acl_id=net_acl_id, host_ip=host_ip, rule_no=new_rule_no, region=region)
            waf_v2_update_ip_set('alb', 'INSERT', ALB_IP_SET_ID, ALB_IP_SET_NAME, host_ip)
            waf_v2_update_ip_set('cloudfront', 'INSERT', CLOUDFRONT_IP_SET_ID, CLOUDFRONT_IP_SET_NAME, host_ip)

            logger.info(f"log -- rule count for NACL {net_acl_id} is {int(rule_count) + 1}.")

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False


# Create NACL rule
def create_net_acl_rule(net_acl_id, host_ip, rule_no):
    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(net_acl_id)

    response = network_acl.create_entry(
        CidrBlock=f'{host_ip}/32',
        Egress=False,
        PortRange={
            'From': 0,
            'To': 65535
        },
        Protocol='-1',
        RuleAction='deny',
        RuleNumber=rule_no
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info(f"log -- successfully added new rule {rule_no}, HostIP {host_ip}, to NACL {net_acl_id}.")
        return True
    else:
        logger.error(f"log -- error adding new rule {rule_no}, HostIP {host_ip}, to NACL {net_acl_id}.")
        logger.info(response)
        return False


# Delete NACL rule
def delete_net_acl_rule(net_acl_id, rule_no):
    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(net_acl_id)

    response = network_acl.delete_entry(
        Egress=False,
        RuleNumber=rule_no
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully deleted rule %s, from NACL %s." % (rule_no, net_acl_id))
        return True
    else:
        logger.info("log -- error deleting rule %s, from NACL %s." % (rule_no, net_acl_id))
        logger.info(response)
        return False


# Create DDB state entry for NACL rule
def create_ddb_rule(net_acl_id, host_ip, rule_no, region):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACL_METATABLE)
    timestamp = int(time.time())

    response = table.put_item(
        Item={
            'NetACLId': net_acl_id,
            'CreatedAt': timestamp,
            'HostIp': str(host_ip),
            'RuleNo': str(rule_no),
            'Region': str(region)
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info(
            f"log -- successfully added DDB state entry for rule {rule_no}, HostIP {host_ip}, NACL {net_acl_id}.")
        return True
    else:
        logger.error(
            f"log -- error adding DDB state entry for rule {rule_no}, HostIP {host_ip}, NACL {net_acl_id}.")
        logger.info(response)
        return False


# Delete DDB state entry for NACL rule
def delete_ddb_rule(net_acl_id, created_at):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACL_METATABLE)
    timestamp = int(time.time())

    response = table.delete_item(
        Key={
            'NetACLId': net_acl_id,
            'CreatedAt': int(created_at)
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info(f"log -- successfully deleted DDB state entry for NACL {net_acl_id}.")
        return True
    else:
        logger.error(f"log -- error deleting DDB state entry for NACL {net_acl_id}.")
        logger.info(response)
        return False


# Send notification to SNS topic
def admin_notify(ip_host, finding_type, nacl_id, region, instance_id):
    message = (f"GuardDuty to ACL Event Info:\r\n"
               f"Suspicious activity detected from host {ip_host} due to {finding_type}."
               f"The following ACL resources were targeted for update as needed; "
               f"CloudFront IP Set: {CLOUDFRONT_IP_SET_ID}, "
               f"Regional IP Set: {ALB_IP_SET_ID}, "
               f"VPC NACL: {nacl_id}, "
               f"EC2 Instance: {instance_id}, "
               f"Region: {region}. "
               )

    sns = boto3.client(service_name="sns")
    # Try to send the notification.
    try:

        sns.publish(
            TopicArn=SNS_TOPIC,
            Message=message,
            Subject='AWS GD2ACL Alert'
        )
        logger.info(f"log -- send notification sent to SNS Topic: {SNS_TOPIC}")

    # Display an error if something goes wrong.
    except ClientError:
        logger.error('log -- error sending notification.')
        raise


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================


# Lambda handler
def lambda_handler(event, context):
    logger.info(f"log -- Event: {json.dumps(event)}")

    try:

        if event["detail"]["type"] == 'Recon:EC2/PortProbeUnprotectedPort':
            host_ip = []
            region = event["region"]
            subnet_id = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            for i in event["detail"]["service"]["action"]["portProbeAction"]["portProbeDetails"]:
                host_ip.append(str(i["remoteIpDetails"]["ipAddressV4"]))
            instance_id = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            network_acl_id = get_net_acl_id(subnet_id=subnet_id)

        else:
            region = event["region"]
            subnet_id = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            host_ip = [
                event["detail"]["service"]["action"]["networkConnectionAction"]["remoteIpDetails"]["ipAddressV4"]]
            instance_id = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            network_acl_id = get_net_acl_id(subnet_id=subnet_id)

        if network_acl_id:

            # Update VPC NACL, global and regional IP Sets
            for ip in host_ip:
                response = update_nacl(net_acl_id=network_acl_id, host_ip=ip, region=region)
                logger.debug(f'Update NACL response {response}')
            # Send Notification
            admin_notify(str(host_ip), event["detail"]["type"], network_acl_id, region, instance_id=instance_id)

            logger.info("log -- processing GuardDuty finding completed successfully")

        else:
            logger.info(
                f"log -- unable to determine NetworkAclId for instanceID: {instance_id}, "
                f"HostIp: {host_ip}, SubnetId: {subnet_id}. Confirm resources exist.")
            pass

    except Exception:
        logger.error('log -- something went wrong.')
        raise
