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
Flag=1


ec2 = boto3.resource(
    'ec2',aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

sns = boto3.resource(
    'sns',
    region_name="us-east-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

r=0
c=0

book = xlwt.Workbook(encoding="utf-8")
sheet1 = book.add_sheet("Instance details")


instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
for instance in instances:
    if instance.id == "i-03def1e32e777522d":
        SG=instance.launch_time
        print SG

                    
'''
        print instance.ami_launch_index,"\n"
        print instance.architecture,"\n"
        print instance.block_device_mappings,"\n"
        print instance.client_token,"\n"
        print instance.ebs_optimized,"\n"
        print instance.ena_support,"\n"
        print instance.hypervisor,"\n"
        print instance.iam_instance_profile,"\n"
        print instance.image_id,"\n"
        print instance.,"\n"
        print instance.instance_lifecycle,"\n"
        print instance.,"\n"
        print instance.kernel_id,"\n"
        print instance.,"\n"
        print instance.,"\n"
        print instance.monitoring,"\n"
        print instance.network_interfaces_attribute,"\n"
        print instance.placement,"\n"
        print instance.platform,"\n"
        print instance.,"\n"
        print instance.,"\n"
        print instance.product_codes,"\n"
        print instance.,"\n"
        print instance.,"\n"
        print instance.ramdisk_id,"\n"
        print instance.root_device_name,"\n"
        print instance.root_device_type,"\n"
        print instance.security_groups,"\n"
        print instance.source_dest_check,"\n"
        print instance.spot_instance_request_id,"\n"
        print instance.sriov_net_support,"\n"
        print instance.state,"\n"
        print instance.state_reason,"\n"
        print instance.state_transition_reason,"\n"
        print instance.subnet_id,"\n"
        print instance.tags,"\n"
        print instance.virtualization_type,"\n"
        print instance.,"\n"
        '''

#book.save("Instance Details.xls")
