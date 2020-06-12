import boto3
import logging
from datetime import *
import json



#setup simple logging for INFO
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

#sts_client = boto3.client('sts')
ec2 = boto3.resource('ec2',region_name="us-west-1")
#, region_name="us-west-2")
sns = boto3.resource('sns',region_name="us-west-1")

#platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:us-west-1:132833855232:InstanceStatus')

SNS_TOPIC_NAME='InstanceStatus'
SNS_ARN_OBJECT=sns.create_topic(Name=SNS_TOPIC_NAME)
SNS_ARN= SNS_ARN_OBJECT.arn
platform_endpoint = sns.PlatformEndpoint(SNS_ARN)

#set the date to today for the snapshot
today = datetime.now().date()

#def lambda_handler(event, context):
def stopped_instances():
    c=""
    Report = "Instance ID list stopped in last one hour : \n"
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
    for instance in instances:
        date_text= instance.state_transition_reason
        date_extract_text=date_text[16:35]
        date_extract=datetime.strptime(date_extract_text,'%Y-%m-%d %H:%M:%S')
        current_date=datetime.utcnow().strftime(('%Y-%m-%d %H:%M:%S'))
        current_date=datetime.strptime(current_date,'%Y-%m-%d %H:%M:%S')
        time_diff= current_date - date_extract
        hours = (time_diff.days) * 24 + (time_diff.seconds) // 3600
        if (hours<=1) :
             c+=instance.instance_id + "\n"
    Report = Report + c + "\n"


    response = platform_endpoint.publish(
        Message=Report,
        Subject='Stopped Instance ID list: ' + str(today),
        MessageStructure='string',
    )

stopped_instances()
