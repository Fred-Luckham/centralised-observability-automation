import sys
import logging
import traceback
import json
import jmespath
import boto3
import re
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    event = event_payload_cleaner(event)
    account_alias = get_account_alias(session)
    event['account_alias'] = account_alias

    return event
    
  except Exception as exp:
    exception_type, exception_value, exception_traceback = sys.exc_info()
    traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
    err_msg = json.dumps({
      "errorType": exception_type.__name__,
      "errorMessage": str(exception_value),
      "stackTrace": traceback_string
    })
    logger.error(err_msg)

def assume_role(event):
  sts = boto3.client("sts", region_name=event['region'])
  response = sts.assume_role(
    RoleArn= f"arn:aws:iam::{event['account']}:role/{os.environ['ObservabilityAutomationRole']}-{event['region']}",
    RoleSessionName=os.environ['ObservabilityAutomationTool']
  )
  session = boto3.Session(
    aws_access_key_id=response['Credentials']['AccessKeyId'],
    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
    aws_session_token=response['Credentials']['SessionToken']
  )
  if session:
    logger.info(f"Assumed role: {response['AssumedRoleUser']}")
  else:
    logger.info(f"Failed to assume role")
  return session

def get_account_alias(session):
  iam = session.client('iam')
  account_alias = ""
  paginator = iam.get_paginator('list_account_aliases')
  for response in paginator.paginate():
    logger.info(f"Account Aliases: {response['AccountAliases']}")
    if len(response['AccountAliases']) == 1:
      account_alias = response['AccountAliases'][0]
  return account_alias
  
def event_payload_cleaner(event):
  try:
    service = event['detail']['service']
  except KeyError as e:
    service = 'ec2'
  try:
    resource_type = event['detail']['resource-type']
  except KeyError as e:
    resource_type = 'instance'
  try:
    resource_arn = event['resources'][0]
  except KeyError as e:
    resource_arn = False
  try:
    monitored = event['detail']['tags']['IsMonitored']
  except KeyError as e:
    monitored = False
  try:
    tags = event['detail']['tags']
  except KeyError as e:
    tags = False
  try:
    autoscaling_group = event['detail']['tags']['aws:autoscaling:groupName']
  except KeyError as e:
    autoscaling_group = False
  try:
    state =  event['detail']['state']
  except KeyError as e:
    state = False
  try:
    instance_id =  get_resource_id(event)
  except Exception as e:
    instance_id = event['detail']['instance-id']
  payload = {
    "account": event['account'],
    "region": event['region'],
    "source": event['source'],
    "service": service,
    "resource_type": resource_type,
    "resource_arn": resource_arn,
    "monitored": monitored,
    "tags": tags,
    "autoscaling_group": autoscaling_group,
    "state": state,
    "instance_id": instance_id,
    "pass": False
  }
  logger.info(f"Payload: {payload}")
  return payload
  
def get_resource_id(event):
  if event['detail']['resource-type'] == "instance" and event['detail']['service'] == "ec2":
    instance_id = re.search("([^\/]+$)", event['resources'][0]).group(0)
    logger.info(f"Found EC2 Instance ID: {instance_id}")
    return instance_id
  elif event['detail']['resource-type'] == "vpn-connection" and event['detail']['service'] == "ec2":
    instance_id = re.search("([^\/]+$)", event['resources'][0]).group(0)
    logger.info(f"Found VPN Connection ID: {instance_id}")
    return instance_id
  elif event['detail']['resource-type']  == "db" and event['detail']['service'] == "rds":
    instance_id = re.search("(?<=db:)[^:]+$", event['resources'][0]).group(0)
    logger.info(f"Found RDS Instance: {instance_id}")
    return instance_id
  elif event['detail']['resource-type']  == "function" and event['detail']['service'] == "lambda":
    instance_id = re.search("(?<=function:)[^:]+$", event['resources'][0]).group(0)
    logger.info(f"Found Lambda Function: {instance_id}")
    return instance_id
  elif event['detail']['resource-type']  == "cluster" and event['detail']['service'] == "ecs":
    instance_id = re.search("([^\/]+$)", event['resources'][0]).group(0)
    logger.info(f"Found ECS Cluster: {instance_id}")
    return instance_id
  elif event['detail']['resource-type']  == "loadbalancer" and event['detail']['service'] == "elasticloadbalancing":
    instance_id = re.search("([^\/]+$)", event['resources'][0]).group(0)
    logger.info(f"Found ECS Cluster: {instance_id}")
    return instance_id
  elif event['detail']['resource-type']  == "environment" and event['detail']['service'] == "airflow":
    instance_id = re.search("([^\/]+$)", event['resources'][0]).group(0)
    logger.info(f"Found MWAA Environment: {instance_id}")
    return instance_id
  else:
    instance_id = False
    return instance_id