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
    check_event(event)

  except Exception as exp:
    exception_type, exception_value, exception_traceback = sys.exc_info()
    traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
    err_msg = json.dumps({
      "errorType": exception_type.__name__,
      "errorMessage": str(exception_value),
      "stackTrace": traceback_string
    })
    logger.error(err_msg)

def check_event(event):
  if event.has_keys('ssm'):
    ssm_error_event(event)
  else:
    health_event(event)

def ssm_error_event(event):
  subject = f"{event['account']}-{event['service']}-{event['instance_id']}-NoSSM-AlertDeploymentFailed"
  logger.info(subject)
  message = f"""
  The Centralised Observability Automation is unable to setup/access the SSM agent on the following resource: 
    - Instance ID: {event['instance_id']}
    - Account ID: {event['account']}
    - Region: {event['region']}
    - Account Alias: {event['account_alias']}

  Ensure that the SSM agent is setup correctly before retrying the alerting pipeline.
  """
  logger.info(message)
  publish_event(message, subject)

def health_event(event):
  subject = f"{event['account']}-{event['service']}-{event['detail']['eventTypeCode']}"
  logger.info(subject)
  message = f"{jmespath.search('detail.eventDescription[0].latestDescription', event)}"
  logger.info(message)
  publish_event(message, subject)

def publish_event(message, subject):
  sns = boto3.client('sns')
  response = sns.publish(
    TopicArn  = os.environ['ObservabilityAutomationHealthTopic'],
    Message   = message,
    Subject   = subject
  )
  logger.info(response)