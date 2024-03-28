import sys
import logging
import traceback
import json
import boto3
import jmespath
import os
from dataclasses import dataclass
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'standard'
   }
)

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    list_executions(event, context)
    delete_alarms(event, session)
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

def list_executions(event, context):
  sf = boto3.client('stepfunctions', config=config)
  response = sf.list_executions(
    stateMachineArn= os.environ['ObservabilityAutomationStateMachine'],
    statusFilter='RUNNING',
    maxResults=123,
  )
  logger.info(f"Running Executions: {response}")
  for execution in response['executions']:
    execution_details = describe_execution(sf, execution['executionArn'])
    logger.info(f"Execution Details: {execution_details}")
    if event['resource_arn'] in execution_details['resources'] and "Tag Change on Resource" in execution_details['detail-type']: 
      check_execution_tag(sf, execution['executionArn'], execution_details)
    else:
      logger.info("No matching execution found")
    
def describe_execution(sf, execution_arn):
  response = sf.describe_execution(
    executionArn=execution_arn
  )
  execution_details = json.loads(response['input'])
  return execution_details

def check_execution_tag(sf, execution_arn, execution_details):
  tag_value = jmespath.search("detail.tags.IsMonitored", execution_details)
  logger.info(f"Tag Value: {tag_value}")
  if tag_value == 'Yes':
    logger.info(f"Stopping Execution: {execution_details}")
    stop_execution(sf, execution_arn)
  else:
    pass
  
def stop_execution(sf, execution_arn):
  response = sf.stop_execution(
    executionArn=execution_arn
  )

def delete_alarms(event, session):
  logger.info(f"Deleting alarms for: {event['instance_id']}")
  cloudwatch = session.client('cloudwatch', region_name=event['region'], config=config)
  response = cloudwatch.describe_alarms(
      AlarmNamePrefix = f"{event['account_alias']}-{event['account']}-{event['service']}-{event['resource_type']}-{event['instance_id']}", 
      AlarmTypes = ['MetricAlarm']
      )
  logger.info(f"{response}")
  alarms = response['MetricAlarms']
  alarm_names = [alarm['AlarmName'] for alarm in alarms]
  logger.info(f"Deleting alarms: {alarm_names}")
  cloudwatch.delete_alarms(AlarmNames = alarm_names)