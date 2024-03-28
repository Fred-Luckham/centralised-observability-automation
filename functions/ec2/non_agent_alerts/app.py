import sys
import logging
import traceback
import json
import boto3
import os
import jmespath
from dataclasses import dataclass
from botocore.config import Config

#Config Variables
logger = logging.getLogger()
logger.setLevel(logging.INFO)
alarms = []
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'standard'
   }
)

#Alert Variables
EvaluationPeriods = os.environ['EvaluationPeriods']
Period = os.environ['Period']
CPUP1 = os.environ['CPUP1']
CPUP2 = os.environ['CPUP2']
CPUP3 = os.environ['CPUP3']
StatusP1= os.environ['StatusP1']

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    create_status_alarm(event, session)
    create_cpu_alarm(event, session)
    event['alarms'] = alarms
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

def for_each_threshold(event, session, alarm_object):
  for item in alarm_object.thresholds:
    severity = item[0]
    threshold_value = item[1]
    level = item[2]
    alarm_name = f"{event['account_alias']}-{event['account']}-{event['service']}-{event['resource_type']}-{event['instance_id']}-{alarm_object.metric_name}-Severity: {severity}"
    create_alarm(event, session, alarm_name, alarm_object, threshold_value, level)

def create_alarm(event, session, alarm_name, alarm_object, threshold_value, level):
  cloudwatch = session.client('cloudwatch', region_name=event['region'], config=config)
  actions = [f"arn:aws:sns:{event['region']}:{event['account']}:Rebura-CentralisedObservabilityAutomationTopic{level}-{event['region']}"]
  response = cloudwatch.put_metric_alarm(
    AlarmName = alarm_name,
    ComparisonOperator = alarm_object.comparison_operator,
    EvaluationPeriods = alarm_object.evaluation_periods,
    MetricName = alarm_object.metric_name,
    Namespace = alarm_object.namespace,
    Period = alarm_object.period,
    Statistic = alarm_object.statistic,
    Threshold = threshold_value,
    ActionsEnabled = alarm_object.actions_enabled,
    OKActions = actions,
    AlarmActions = actions,
    AlarmDescription = alarm_object.alarm_description,
    TreatMissingData = alarm_object.treat_missing_data,
    Dimensions = alarm_object.dimensions
  )
  alarms.append(alarm_name)
  logger.info(f"Created Alarm: {alarm_name}")

def create_status_alarm(event, session):
  alarm_object = Alarm(
    [["Critical", StatusP1, "P1"]], 
    "GreaterThanThreshold", 
    1, 
    "StatusCheckFailed_Instance", 
    "AWS/EC2", 
    300, 
    "Average", 
    True, 
    "Alarm triggers when instance status check fails or when instance is not reachable", 
    "breaching", 
    [{'Name': 'InstanceId','Value': event['instance_id']}]
  )
  for_each_threshold(event, session, alarm_object)

def create_cpu_alarm(event, session):
  if "P1-CPU" in event['tags']:
    p1 = int(event['tags'].get("P1-CPU"))
  else:
    p1 = CPUP1
  if "P2-CPU" in event['tags']:
    p2 = int(event['tags'].get("P2-CPU"))
  else:
    p2 = CPUP2
  if "P3-CPU" in event['tags']:
    p3 = int(event['tags'].get("P3-CPU"))
  else:
    p3 = CPUP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "CPUUtilization", 
    "AWS/EC2", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when instance CPU exceeds the threshold or when instance is not reachable", 
    "breaching", 
    [{'Name': 'InstanceId','Value': event['instance_id']}]
  )
  for_each_threshold(event, session, alarm_object)

@dataclass
class Alarm:
  thresholds: list
  comparison_operator: str
  evaluation_periods: int
  metric_name: str
  namespace: str
  period: int
  statistic: str
  actions_enabled: bool
  alarm_description: str
  treat_missing_data: str
  dimensions: list