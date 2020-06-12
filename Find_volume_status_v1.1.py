import boto3
import logging
from datetime import *
import json


#setup simple logging for INFO
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

#sts_client = boto3.client('sts')
ec2 = boto3.resource('ec2', region_name="us-west-2")
sns = boto3.resource('sns')

platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:us-east-2:132833855232:VolumeStatus')

#set the date to today for the snapshot
today = datetime.now().date()

#def lambda_handler(event, context):
def abc():
    c=""
    Report = "The Volumes status: \n"
    print (Report)
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for instance in instances:
        volumes = instance.volumes.all()
        for volumes in volumes:
            pqr=volumes.describe_status()
            text=str(pqr)
            print (text)
            if (text.find("u\'VolumeStatus\': {u\'Status\': \'ok\'") > 0 ):
                a=text.find("\'VolumeId\'")
                b=text.find("u\'Actions\'")
                c+=text[a:b] + "\n"
                
    Report = Report + "- " + c + "\n"
    response = platform_endpoint.publish(
        Message=Report,
        Subject='Volumes status: ' + str(today),
        MessageStructure='string',
    )

abc()
