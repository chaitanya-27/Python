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

r=0
c=0

book = xlwt.Workbook(encoding="utf-8")
sheet1 = book.add_sheet("Instance details")
sheet1.write(r, c, "Instance Name")
sheet1.write(r, c+1, "Instance ID")
sheet1.write(r, c+2, "VPC ID")
sheet1.write(r, c+3, "Subnet ID")
sheet1.write(r, c+4, "Key Used")
sheet1.write(r, c+5, "Instance Type")
sheet1.write(r, c+6, "Instance Launch Time")
sheet1.write(r, c+7, "Instance Private DNS Name")
sheet1.write(r, c+8, "Instance Private IP Address")
sheet1.write(r, c+9, "Instance Public DNS Name")
sheet1.write(r, c+10, "Instance Public IP Address")
sheet1.write(r, c+11, "Security Group Name")
sheet1.write(r, c+12, "Security Group ID")


i=0
instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
for instance in instances:
        c=0
        r+=1
        r=r+i
    #if instance.id == "i-03def1e32e777522d":
        Name= instance.tags
        for tag in Name:
            if tag['Key'] == 'Name':
              sheet1.write( r,c,tag['Value'])
              c+=1
        sheet1.write(r,c,instance.id)
        c+=1
        sheet1.write(r,c,instance.vpc_id)
        c+=1
        sheet1.write(r,c,instance.subnet_id)
        c+=1        
        sheet1.write(r,c,instance.key_name)
        c+=1
        sheet1.write(r,c,instance.instance_type)
        c+=1
        Time=str(instance.launch_time)
        sheet1.write(r,c,Time)           
        c+=1
        sheet1.write(r,c,instance.private_dns_name)
        c+=1
        sheet1.write(r,c,instance.private_ip_address)
        c+=1
        sheet1.write(r,c,instance.public_dns_name)
        c+=1
        sheet1.write(r,c,instance.public_ip_address)
        c+=1
        SG=instance.security_groups
        i=0
        e=c
        for security_groups in SG:
             SG_Text=str(SG[i])
             a=SG_Text.find("GroupName")
             b=SG_Text.find("', u'GroupId'")
             c=SG_Text.find("GroupId")
             d=SG_Text.find("'}")
             r1=r+i
             text=SG_Text[a+13:b]
             sheet1.write(r1,e,text)
             e+=1
             text=SG_Text[c+11:d]
             sheet1.write(r1,e,text )
             i+=1
             e-=1
        i=i-1

book.save("Instance Details.xls")
