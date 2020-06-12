import boto3
import logging
import xlwt
from datetime import *




sts_client = boto3.client('sts')



#Token_code=input('Enter MFA token code:')

assumedRoleObject = sts_client.assume_role(
    RoleArn="arn:aws:iam::132833855232:role/beta1",
    RoleSessionName="AssumeRoleSession1",
    #SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
    #TokenCode=Token_code
)


credentials = assumedRoleObject['Credentials']

r=0
c=0

book = xlwt.Workbook(encoding="utf-8")
sheet1 = book.add_sheet("Volume details")
sheet1.write(r, c, "Instance Name")
sheet1.write(r, c+1, "Volume ID")
sheet1.write(r, c+2, "Volume Status")

ec2 = boto3.resource(
    'ec2',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

i=0

instances = ec2.instances.filter(
 Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
for instance in instances:
    c=0
    r+=1
    r=r+i
    Name= instance.tags
    for tag in Name:
            if tag['Key'] == 'Name':
              #sheet1.write( r,c,tag['Value'])
               print r,c,tag['Value']
'''
              c+=1
    volumes = instance.volumes.all()
    i=0
    e=c
    for volumes in volumes:
            r1=r+i
            pqr=volumes.describe_status()
            text=str(pqr)
            if (text.find("\'VolumeStatus\': {u\'Status\': \'ok\'") > 0 ):
                a=text.find("\'VolumeId\'")
                b=text.find("u\'Actions'\'")        
                VId=text[a:b]
                sheet1.write(r1,e,VId)
                e+=1
                i+=1




book.save("Volume details.xls")
'''



                    


