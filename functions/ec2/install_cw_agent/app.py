import sys
import logging
import traceback
import json
import boto3
import time
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    install_cloudwatch_agent(event, session)
    time.sleep(30)
    configure_cloudwatch_agent(event, session)
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
  
def install_cloudwatch_agent(event, session):
  logger.info(f"Installing CloudWatch agent on instance: {event['instance_id']}")
  ssm = session.client("ssm", region_name=event['region'])
  response = ssm.send_command(
    InstanceIds=[f"{event['instance_id']}"],
    DocumentName='AWS-ConfigureAWSPackage',
    Parameters={
      "action": ["Install"],
      "installationType":["Uninstall and reinstall"],
      "name":["AmazonCloudWatchAgent"]
    }
  )
  logger.info(response)

def configure_cloudwatch_agent(event, session):
  logger.info(f"Configuring CloudWatch agent on instance: {event['instance_id']}")
  ssm = session.client("ssm", region_name=event['region'])
  response = ssm.send_command(
    InstanceIds=[f"{event['instance_id']}"],
    DocumentName='AmazonCloudWatch-ManageAgent',
    Parameters={
      "action": ["configure"],
      "mode": ["ec2"],
      "optionalConfigurationSource": ["default"],
      "optionalRestart": ["yes"]
    }
  )
  logger.info(response)