import boto3
import logging
from datetime import *
import json


#setup simple logging for INFO
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

#sts_client = boto3.client('sts')
#ec2 = boto3.resource('ec2', region_name="us-east-2")
#sns = boto3.resource('sns')


sts_client = boto3.client('sts')

#Token_code=input('Enter MFA token code:')

assumedRoleObject = sts_client.assume_role(
    RoleArn="arn:aws:iam::132833855232:role/beta1",
    RoleSessionName="AssumeRoleSession1",
#    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
#   TokenCode=Token_code
)

credentials = assumedRoleObject['Credentials']

ec2 = boto3.resource(
    'ec2',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

sns = boto3.resource(
    'sns',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:us-west-2:132833855232:TestSNSMail')

#set the date to today for the snapshot
today = datetime.now().date()

def abc():
    c=""
    Report = "Below is the list of corrupted EBS Volumes: \n"
    Flag = 1
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']},{'Name': 'tag:Name','Values': ['*CokeTeradataNonProd-2*']}])
    for instance in instances:
        volumes = instance.volumes.all()
        for volumes in volumes:
            pqr=volumes.describe_status()
            Name= instance.tags
            for tag in Name:
                            if tag['Key'] == 'Name':
                                      InstanceName=tag['Value']
            text=str(pqr)
            print text
            print text.find("u\'VolumeStatus\': {u\'Status\': \'ok\'")
            if (text.find("u\'VolumeStatus\': {u\'Status\': \'ok\'") > 0 ):
                a=text.find("\'VolumeId\'")
                b=text.find("u\'Actions\'")
                c+=text[a:b] + "\n" + "InstanceName: " + InstanceName + "\n"
                Flag = 0
                
    if (Flag == 0):
        Report = Report + "- " + c + "\n"
        response = platform_endpoint.publish(
            Message=Report,
            Subject=' List of corrupted Volumes : ' + str(today),
            MessageStructure='string',
            )


abc()
