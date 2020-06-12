import boto3
import logging
from datetime import *
import json
import xlwt

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

f= open("NodeIPAddress1.txt","w+")


instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
for instance in instances:
                Name= instance.tags
                try:
                         for tag in Name:
                            if tag['Key'] == 'Name':
                                      InstanceName=tag['Value']

                                      if InstanceName.find('SMP001')>0:
                                           f.write(instance.public_ip_address)
                                           f.write("\n")
                except Exception as e:
                        a=1
f.close
