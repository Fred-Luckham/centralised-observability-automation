import sys
import logging
import traceback
import json
import boto3
import os
import jmespath
import re
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
TargetResponseTimeP1 = os.environ['TargetResponseTimeP1']
TargetResponseTimeP2 = os.environ['TargetResponseTimeP2']
TargetResponseTimeP3 = os.environ['TargetResponseTimeP3']
UnhealthyHostCountP1 = os.environ['UnhealthyHostCountP1']
UnhealthyHostCountP2 = os.environ['UnhealthyHostCountP2']
UnhealthyHostCountP3 = os.environ['UnhealthyHostCountP3']

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    list_target_groups(event, session)
    create_targetresponsetime_alarm(event, session)
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
  sts = boto3.client("sts", region_name = event['region'])
  response = sts.assume_role(
    RoleArn = f"arn:aws:iam::{event['account']}:role/{os.environ['ObservabilityAutomationRole']}-{event['region']}",
    RoleSessionName = os.environ['ObservabilityAutomationTool']
  )
  session = boto3.Session(
    aws_access_key_id = response['Credentials']['AccessKeyId'],
    aws_secret_access_key = response['Credentials']['SecretAccessKey'],
    aws_session_token = response['Credentials']['SessionToken']
  )
  if session:
    logger.info(f"Assumed role: {response['AssumedRoleUser']}")
  else:
    logger.info(f"Failed to assume role")
  return session

def list_target_groups(event, session):
  elbv2 = session.client("elbv2", region_name = event['region'])
  response = elbv2.describe_target_groups(
      LoadBalancerArn=event['resource_arn']
  )
  logger.info(f"Target Groups: {response}")
  for target_group in response['TargetGroups']:
    target_group_name = re.search(":[^:]+$", target_group['TargetGroupArn']).group(0).replace(':', '')
    logger.info(f"Target Group Name: {target_group_name}")
    create_unhealthyhostcount_alarm(event, session, target_group_name)

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

def create_targetresponsetime_alarm(event, session):
  if "P1-TargetResponseTime" in event['tags']:
    p1 = int(event['tags'].get("P1-TargetResponseTime"))
  else:
    p1 = TargetResponseTimeP1
  if "P2-TargetResponseTime" in event['tags']:
    p2 = int(event['tags'].get("P2-TargetResponseTime"))
  else:
    p2 = TargetResponseTimeP2
  if "P3-TargetResponseTime" in event['tags']:
    p3 = int(event['tags'].get("P3-TargetResponseTime"))
  else:
    p3 = TargetResponseTimeP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "TargetResponseTime", 
    "AWS/ApplicationELB", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when TargetResponseTime is too high", 
    "notBreaching", 
    [{'Name': 'LoadBalancer','Value': event['instance_id']}]
  )
  for_each_threshold(event, session, alarm_object)

def create_unhealthyhostcount_alarm(event, session, target_group_name):
  if "P1-UnHealthyHostCount" in event['tags']:
    p1 = int(event['tags'].get("P1-UnHealthyHostCount"))
  else:
    p1 = UnhealthyHostCountP1
  if "P2-UnHealthyHostCount" in event['tags']:
    p2 = int(event['tags'].get("P2-UnHealthyHostCount"))
  else:
    p2 = UnhealthyHostCountP2
  if "P3-UnHealthyHostCount" in event['tags']:
    p3 = int(event['tags'].get("P3-UnHealthyHostCount"))
  else:
    p3 = UnhealthyHostCountP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "UnHealthyHostCount", 
    "AWS/ApplicationELB", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when UnhealthyHostCount is too high", 
    "notBreaching", 
    [{'Name': 'LoadBalancer','Value': event['instance_id']},{'Name': 'TargetGroup','Value': target_group_name}]
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