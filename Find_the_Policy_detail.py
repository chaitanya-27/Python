import boto3
import logging
from datetime import *
import json
import xlwt
import sys

sts_client = boto3.client('sts')
iam = boto3.client('iam')

'''

def connection_beta1():

#Token_code=input('Enter MFA token code:')

        assumedRoleObject = sts_client.assume_role(
            RoleArn="arn:aws:iam::132833855232:role/beta1",
            RoleSessionName="AssumeRoleSession1",
#    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
#   TokenCode=Token_code
        )
        credentials = assumedRoleObject['Credentials']
        iam = boto3.client('iam',
#       region_name="us-west-2",
        aws_access_key_id = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token = credentials['SessionToken'],
        )

def connection_beta2():

#Token_code=input('Enter MFA token code:')

        assumedRoleObject = sts_client.assume_role(
            RoleArn="arn:aws:iam::132833855232:role/beta2",
            RoleSessionName="AssumeRoleSession1",
#    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
#   TokenCode=Token_code
        )
        credentials = assumedRoleObject['Credentials']
        iam = boto3.client('iam',
#       region_name="us-west-2",
        aws_access_key_id = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token = credentials['SessionToken'],
        )


def connection_beta3():

#Token_code=input('Enter MFA token code:')

        assumedRoleObject = sts_client.assume_role(
            RoleArn="arn:aws:iam::961017746768:role/beta3",
            RoleSessionName="AssumeRoleSession1",
#    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
#   TokenCode=Token_code
        )
        credentials = assumedRoleObject['Credentials']
        iam = boto3.client('iam',
#       region_name="us-west-2",
        aws_access_key_id = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token = credentials['SessionToken'],
        )
'''


r=0
c=0
book = xlwt.Workbook(encoding="utf-8")
sheet1 = book.add_sheet("Policy details1")
sheet1.write(r, c, "Policy Name")
sheet1.write(r, c+1, "Policy Description")







policy=iam.list_policies(MaxItems=300)

abc= policy.items()
pqr= abc[2]
abc=pqr[1]
for abc in abc :
        c=0
        r+=1
        PN= abc['PolicyName']
        sheet1.write(r,c,PN)
        c+=1
        ArnP= abc['Arn']
        pqr=iam.get_policy(PolicyArn=ArnP)
        fil=pqr['Policy']
        try:
          PD=fil['Description']
          sheet1.write(r,c,PD)
        except Exception as e:
                a=1
        c+=1



book.save("Policy Details1.xls")
