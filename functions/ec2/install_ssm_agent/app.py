import sys
import logging
import traceback
import json
import boto3
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    wait_for_initialize(event, session)
    ssm_check = check_for_ssm(event, session)
    event['ssm'] = ssm_check
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

def wait_for_initialize(event, session):
  logger.info(f"Waiting for instance to initialize: {event['instance_id']}")
  ec2 = session.client("ec2", region_name=event['region'])
  waiter = ec2.get_waiter('system_status_ok')
  waiter.wait(InstanceIds=[f"{event['instance_id']}"])
  check_for_ssm(event, session)

def check_for_ssm(event, session):
  logger.info(f"Checking for SSM agent on instance: {event['instance_id']}")
  ssm = session.client("ssm", region_name=event['region'])
  response = ssm.get_connection_status(Target=event['instance_id'])
  logger.info(response)
  if response['Status'] == 'connected':
    logger.info(f"Instance has SSM agent. CloudWatch installation can proceed: {event['instance_id']}")
    return "yes"
  else:
    logger.info(f"Instance does not have SSM agent. CloudWatch installation cannot proceed: {event['instance_id']}")
    return "no"