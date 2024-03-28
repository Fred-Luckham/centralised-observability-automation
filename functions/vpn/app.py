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
TunnelStateP1 = os.environ['TunnelStateP1']

def lambda_handler(event, context):
  try:
    logger.info(f'event: {event}')
    session = assume_role(event)
    describe_vpn_connections(event, session)
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

def describe_vpn_connections(event, session):
  ec2 = session.client("ec2", region_name = event['region'])
  response = ec2.describe_vpn_connections(VpnConnectionIds = [f"{event['instance_id']}"])
  tunnel_options = jmespath.search('VpnConnections[*].Options.TunnelOptions', response)
  for tunnel_list in tunnel_options:
    for tunnel in tunnel_list:
      logger.info(f"Tunnel IP: {tunnel['OutsideIpAddress']}")
      create_tunnel_alarm(event, session, tunnel['OutsideIpAddress'])

def for_each_threshold(event, session, alarm_object, tunnel_ip):
  for item in alarm_object.thresholds:
    severity = item[0]
    threshold_value = item[1]
    level = item[2]
    alarm_name = f"{event['account_alias']}-{event['account']}-{event['service']}-{event['resource_type']}-{event['instance_id']}-{tunnel_ip}-{alarm_object.metric_name}-Severity: {severity}"
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

def create_tunnel_alarm(event, session, tunnel_ip):
  alarm_object = Alarm(
    [["Critical", TunnelStateP1, "P1"]],  
    "LessThanThreshold", 
    EvaluationPeriods, 
    "TunnelState", 
    "AWS/VPN", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when VPN Tunnel is not reachable", 
    "breaching", 
    [{'Name': 'TunnelIpAddress','Value': tunnel_ip}]
  )
  for_each_threshold(event, session, alarm_object, tunnel_ip)

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