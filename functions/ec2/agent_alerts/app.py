import sys
import logging
import traceback
import json
import boto3
import jmespath
import os
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
MemoryP1 = os.environ['MemoryP1']
MemoryP2 = os.environ['MemoryP2']
MemoryP3 = os.environ['MemoryP3']
LinuxDiskP1 = os.environ['LinuxDiskP1']
LinuxDiskP2 = os.environ['LinuxDiskP2']
LinuxDiskP3 = os.environ['LinuxDiskP3']
WindowsDiskP1 = os.environ['WindowsDiskP1']
WindowsDiskP2 = os.environ['WindowsDiskP2']
WindowsDiskP3 = os.environ['WindowsDiskP3']

def lambda_handler(event, context):
  try:
    del event['alarms']
    logger.info(f'event: {event}')
    session = assume_role(event)
    get_instance_platform(event, session)
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

def get_instance_platform(event, session):
  ec2 = session.client("ec2", region_name=event['region'])
  response = ec2.describe_instances(
    InstanceIds=[event['instance_id']]
  )
  logger.info(f"Retrieving instance information: {response}")
  if response['Reservations'][0]['Instances'][0]['PlatformDetails'] == "Linux/UNIX":
    get_linux_disk_dimensions(event, session)
    get_linux_memory_dimensions(event, session)
  elif response['Reservations'][0]['Instances'][0]['PlatformDetails'] == "Windows":
    get_windows_disk_dimensions(event, session)
    get_windows_memory_dimensions(event, session)
    
## Linux Disk Alarm ##
def get_linux_disk_dimensions(event, session):
  cloudwatch = session.client("cloudwatch", region_name=event['region'])
  list_metrics_response = cloudwatch.list_metrics(
      Namespace='CWAgent',
      Dimensions=[{'Name': 'InstanceId','Value': event['instance_id']},{'Name': 'path','Value': '/'}]
  )
  logger.info(f"Retrieving available dimensions: {list_metrics_response}")
  ImageId = jmespath.search("Metrics[*].Dimensions[?Name=='ImageId'].Value | [0]", list_metrics_response)
  InstanceType = jmespath.search("Metrics[*].Dimensions[?Name=='InstanceType'].Value | [0]", list_metrics_response)
  device = jmespath.search("Metrics[*].Dimensions[?Name=='device'].Value | [0]", list_metrics_response)
  fstype = jmespath.search("Metrics[*].Dimensions[?Name=='fstype'].Value | [0]", list_metrics_response)
  logger.info(f"ImageID: {ImageId}, InstanceType: {InstanceType}, Device: {device}, fstype: {fstype}")
  dimensions = [
      {
      'Name': 'path',
      'Value': '/'
      },
      {
      'Name': 'InstanceId',
      'Value': event['instance_id']
      },
      {
      'Name': 'ImageId',
      'Value': str(ImageId).strip("[']")
      },
      {
      'Name': 'InstanceType',
      'Value': str(InstanceType).strip("[']")
      },
      {
      'Name': 'device',
      'Value': str(device).strip("[']")
      },
      {
      'Name': 'fstype',
      'Value': str(fstype).strip("[']")
      }
    ]
  if event['autoscaling_group'] != False:
    logger.info(f"Found Autoscaling Group: {event['autoscaling_group']}")
    dimensions.append({'Name': 'AutoScalingGroupName','Value': event['autoscaling_group']})
  create_linux_disk_alarm(event, session, dimensions)

def create_linux_disk_alarm(event, session, dimensions):
  if "P1-Disk" in event['tags']:
    p1 = int(event['tags'].get("P1-Disk"))
  else:
    p1 = LinuxDiskP1
  if "P2-Disk" in event['tags']:
    p2 = int(event['tags'].get("P2-Disk"))
  else:
    p2 = LinuxDiskP2
  if "P3-Disk" in event['tags']:
    p3 = int(event['tags'].get("P3-Disk"))
  else:
    p3 = LinuxDiskP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "disk_used_percent", 
    "CWAgent", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when volume is nearly full or when instance is not reachable", 
    "breaching", 
    dimensions
  )
  for_each_threshold(event, session, alarm_object)

## Linux Memory Alarm ##
def get_linux_memory_dimensions(event, session):
  cloudwatch = session.client("cloudwatch", region_name=event['region'])
  list_metrics_response = cloudwatch.list_metrics(
      Namespace='CWAgent',
      Dimensions=[{'Name': 'InstanceId','Value': event['instance_id']}]
  )
  logger.info(f"Retrieving available dimensions: {list_metrics_response}")
  ImageId = jmespath.search("Metrics[*].Dimensions[?Name=='ImageId'].Value | [0]", list_metrics_response)
  InstanceType = jmespath.search("Metrics[*].Dimensions[?Name=='InstanceType'].Value | [0]", list_metrics_response)
  logger.info(f"ImageID: {ImageId}, InstanceType: {InstanceType}")
  dimensions = [
      {
      'Name': 'InstanceId',
      'Value': event['instance_id']
      },
      {
      'Name': 'ImageId',
      'Value': str(ImageId).strip("[']")
      },
      {
      'Name': 'InstanceType',
      'Value': str(InstanceType).strip("[']")
      }
    ]
  if event['autoscaling_group'] != False:
    logger.info(f"Found Autoscaling Group: {event['autoscaling_group']}")
    dimensions.append({'Name': 'AutoScalingGroupName','Value': event['autoscaling_group']})
  create_linux_memory_alarm(event, session, dimensions)

def create_linux_memory_alarm(event, session, dimensions):
  if "P1-Memory" in event['tags']:
    p1 = int(event['tags'].get("P1-Memory"))
  else:
    p1 = MemoryP1
  if "P2-Memory" in event['tags']:
    p2 = int(event['tags'].get("P2-Memory"))
  else:
    p2 = MemoryP2
  if "P3-Memory" in event['tags']:
    p3 = int(event['tags'].get("P3-Memory"))
  else:
    p3 = MemoryP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "mem_used_percent", 
    "CWAgent", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when instance memory usage is high or when instance is not reachable", 
    "breaching", 
    dimensions
  )
  for_each_threshold(event, session, alarm_object)

## Windows Disk Alarm ##
def get_windows_disk_dimensions(event, session):
  cloudwatch = session.client("cloudwatch", region_name=event['region'])
  list_metrics_response = cloudwatch.list_metrics(
      Namespace='CWAgent',
      MetricName='LogicalDisk % Free Space',
      Dimensions=[{'Name': 'InstanceId','Value': event['instance_id']}]
  )
  logger.info(f"Retrieving available dimensions: {list_metrics_response}")
  for metric in list_metrics_response['Metrics']:
    ImageId = jmespath.search("Metrics[*].Dimensions[?Name=='ImageId'].Value | [0]", list_metrics_response)
    InstanceType = jmespath.search("Metrics[*].Dimensions[?Name=='InstanceType'].Value | [0]", list_metrics_response)
    objectname = jmespath.search("Metrics[*].Dimensions[?Name=='objectname'].Value | [0]", list_metrics_response)
    instance = jmespath.search("Metrics[*].Dimensions[?Name=='instance'].Value | [0]", list_metrics_response)
    logger.info(f"ImageID: {ImageId}, InstanceType: {InstanceType}, ObjectName: {objectname}, Instance: {instance}")
    dimensions = [
        {
        'Name': 'InstanceId',
        'Value': event['instance_id']
        },
        {
        'Name': 'ImageId',
        'Value': str(ImageId).strip("[']")
        },
        {
        'Name': 'InstanceType',
        'Value': str(InstanceType).strip("[']")
        },
        {
        'Name': 'objectname',
        'Value': str(objectname).strip("[']")
        },
        {
        'Name': 'instance',
        'Value': str(instance).strip("[']")
        }
      ]
    if event['autoscaling_group'] != False:
      logger.info(f"Found Autoscaling Group: {event['autoscaling_group']}")
      dimensions.append({'Name': 'AutoScalingGroupName','Value': event['autoscaling_group']})
    create_windows_disk_alarm(event, session, dimensions)

def create_windows_disk_alarm(event, session, dimensions):
  if "P1-Disk" in event['tags']:
    p1 = int(event['tags'].get("P1-Disk"))
  else:
    p1 = WindowsDiskP1
  if "P2-Disk" in event['tags']:
    p2 = int(event['tags'].get("P2-Disk"))
  else:
    p2 = WindowsDiskP2
  if "P3-Disk" in event['tags']:
    p3 = int(event['tags'].get("P3-Disk"))
  else:
    p3 = WindowsDiskP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "LessThanThreshold", 
    EvaluationPeriods, 
    "LogicalDisk % Free Space", 
    "CWAgent", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when volume is nearly full or when instance is not reachable", 
    "breaching", 
    dimensions
  )
  for_each_threshold(event, session, alarm_object)

## Windows Memory Alarm ##
def get_windows_memory_dimensions(event, session):
  cloudwatch = session.client("cloudwatch", region_name=event['region'])
  list_metrics_response = cloudwatch.list_metrics(
      Namespace='CWAgent',
      Dimensions=[{'Name': 'InstanceId','Value': event['instance_id']}]
  )
  logger.info(f"Retrieving available dimensions: {list_metrics_response}")
  ImageId = jmespath.search("Metrics[*].Dimensions[?Name=='ImageId'].Value | [0]", list_metrics_response)
  InstanceType = jmespath.search("Metrics[*].Dimensions[?Name=='InstanceType'].Value | [0]", list_metrics_response)
  logger.info(f"ImageID: {ImageId}, InstanceType: {InstanceType}")
  dimensions = [
      {
      'Name': 'InstanceId',
      'Value': event['instance_id']
      },
      {
      'Name': 'ImageId',
      'Value': str(ImageId).strip("[']")
      },
      {
      'Name': 'InstanceType',
      'Value': str(InstanceType).strip("[']")
      },
      {
      'Name': 'objectname',
      'Value': 'Memory'
      }
    ]
  if event['autoscaling_group'] != False:
    logger.info(f"Found Autoscaling Group: {event['autoscaling_group']}")
    dimensions.append({'Name': 'AutoScalingGroupName','Value': event['autoscaling_group']})
  create_windows_memory_alarm(event, session, dimensions)

def create_windows_memory_alarm(event, session, dimensions):
  if "P1-Memory" in event['tags']:
    p1 = int(event['tags'].get("P1-Memory"))
  else:
    p1 = MemoryP1
  if "P2-Memory" in event['tags']:
    p2 = int(event['tags'].get("P2-Memory"))
  else:
    p2 = MemoryP2
  if "P3-Memory" in event['tags']:
    p3 = int(event['tags'].get("P3-Memory"))
  else:
    p3 = MemoryP3
  alarm_object = Alarm(
    [["Low", p3, "P3"],["High", p2, "P2"],["Critical", p1, "P1"]],
    "GreaterThanThreshold", 
    EvaluationPeriods, 
    "Memory % Committed Bytes In Use", 
    "CWAgent", 
    Period, 
    "Average", 
    True, 
    "Alarm triggers when instance memory usage is high or when instance is not reachable", 
    "breaching", 
    dimensions
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