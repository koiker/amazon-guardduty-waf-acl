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

import json
import logging
import math
import os
import time

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ======================================================================================================================
# Variables
# ======================================================================================================================

API_CALL_NUM_RETRIES = 1
ACL_METATABLE = os.environ['ACL_METATABLE']
RETENTION = os.environ['RETENTION']
CLOUDFRONT_IP_SET_ID = os.environ['CLOUDFRONT_IP_SET_ID']
CLOUDFRONT_IP_SET_NAME = os.environ['CLOUDFRONT_IP_SET_NAME']
ALB_IP_SET_ID = os.environ['ALB_IP_SET_ID']
ALB_IP_SET_NAME = os.environ['ALB_IP_SET_NAME']


# ======================================================================================================================
# Auxiliary Functions
# ======================================================================================================================


def waf_v2_update_ip_set(waf_v2_type, ip_set_id, ip_set_name, source_ip):
    if waf_v2_type == 'alb':
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
    if f'{source_ip}/32' in addresses:
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
            logger.info(response)
            logger.info(f'successfully deleted ip {source_ip}')
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info(f"log -- waf_update_ip_set retrying in %d seconds... {delay}")
            time.sleep(delay)
        else:
            break
    else:
        logger.info("log -- waf_update_ip_set failed ALL attempts to call WAF API")


def waf_update_ip_set(waf_type, ip_set_id, source_ip):
    if waf_type == 'alb':
        logger.info('creating waf regional object')
        session = boto3.session.Session(region_name=os.environ['AWS_REGION'])
        waf = session.client('waf-regional')
    elif waf_type == 'cloudfront':
        logger.info('creating waf global object')
        waf = boto3.client('waf')
    logger.info(f'type of WAF: {waf_type}')
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(IPSetId=ip_set_id,
                                         ChangeToken=waf.get_change_token()['ChangeToken'],
                                         Updates=[{
                                             'Action': 'DELETE',
                                             'IPSetDescriptor': {
                                                 'Type': 'IPV4',
                                                 'Value': f"{source_ip}/32"
                                             }
                                         }]
                                         )
            logger.info(response)
            logger.info(f'successfully deleted ip {source_ip}')
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info(f"log -- waf_update_ip_set retrying in {delay} seconds... ")
            time.sleep(delay)
        else:
            break
    else:
        logger.error("log -- waf_update_ip_set failed ALL attempts to call API")


def delete_net_acl_rule(net_acl_id, rule_no):
    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(net_acl_id)

    try:
        response = network_acl.delete_entry(
            Egress=False,
            RuleNumber=int(rule_no)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('log -- delete_net_acl_rule successful')
            return True
        else:
            logger.error('log -- delete_net_acl_rule FAILED')
            logger.info(response)
            return False
    except Exception as e:
        logger.error(e)


def delete_ddb_rule(net_acl_id, created_at):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACL_METATABLE)

    response = table.delete_item(
        Key={
            'NetACLId': net_acl_id,
            'CreatedAt': int(created_at)
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info('log -- delete_ddb_rule successful')
        return True
    else:
        logger.error('log -- delete_ddb_rule FAILED')
        logger.info(response['ResponseMetadata'])
        return False


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================


def lambda_handler(event, context):
    logger.debug(f"log -- Event: {json.dumps(event)}")

    try:
        # timestamp is calculated in seconds
        expire_time = int(time.time()) - (int(RETENTION) * 60)
        logger.info(f"log -- expire_time = {expire_time}")

        # scan the ddb table to find expired records
        ddb = boto3.resource('dynamodb')
        table = ddb.Table(ACL_METATABLE)
        response = table.scan(
            FilterExpression=Attr('CreatedAt').lt(expire_time) & Attr('Region').eq(os.environ['AWS_REGION']))

        if response['Items']:
            logger.info(f"log -- attempting to prune entries, {response['Items']}.")

            # process each expired record
            for item in response['Items']:
                logger.info(f"deleting item: {item}")
                logger.info(f"HostIp {item['HostIp']}")
                host_ip = item['HostIp']
                try:
                    logger.info('log -- deleting net_acl rule')
                    delete_net_acl_rule(item['NetACLId'], item['RuleNo'])

                    # check if IP is also recorded in a fresh finding, don't remove IP from blacklist in that case
                    response_non_expired = table.scan(
                        FilterExpression=Attr('CreatedAt').gt(expire_time) & Attr('HostIp').eq(host_ip))
                    if len(response_non_expired['Items']) == 0:
                        # no fresher entry found for that IP
                        logger.info('log -- deleting ALB WAF ip entry')
                        waf_v2_update_ip_set('alb', ALB_IP_SET_ID, ALB_IP_SET_NAME, host_ip)
                        logger.info('log -- deleting CloudFront WAF ip entry')
                        waf_v2_update_ip_set('cloudfront', CLOUDFRONT_IP_SET_ID, CLOUDFRONT_IP_SET_NAME, host_ip)

                    logger.info('log -- deleting dynamodb item')
                    delete_ddb_rule(item['NetACLId'], item['CreatedAt'])

                except Exception as e:
                    logger.error(e)
                    logger.error('log -- could not delete item')

            logger.info("Pruning Completed")

        else:
            retention = int(RETENTION) / 60
            logger.info(f"log -- no entries older than {retention} hours... exiting GD2ACL pruning.")

    except Exception:
        logger.error('something went wrong')
        raise
