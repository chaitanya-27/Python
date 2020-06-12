import boto3
import logging
from datetime import *
import pytz



sts_client = boto3.client('sts')



Token_code=input('Enter MFA token code:')

assumedRoleObject = sts_client.assume_role(
    RoleArn="arn:aws:iam::132833855232:role/beta1",
    RoleSessionName="AssumeRoleSession1",
    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
    TokenCode=Token_code
)


credentials = assumedRoleObject['Credentials']
Flag=1


ec2 = boto3.resource(
    'ec2',aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)


instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
for instance in instances:
    if (instance.instance_id=="i-0f721c016fb03db28") :
        date_text= instance.state_transition_reason
        date_extract_text=date_text[16:35]   
        date_extract=datetime.strptime(date_extract_text,'%Y-%m-%d %H:%M:%S')
        new_tz = pytz.timezone('GMT')
        current_date=datetime.now(new_tz).strftime('%Y-%m-%d %H:%M:%S')
        current_date=datetime.strptime(current_date,'%Y-%m-%d %H:%M:%S')     
        time_diff= current_date - date_extract
        hours = (time_diff.days) * 24 + (time_diff.seconds) // 3600
        print (" Instance description : " ,date_text)
        print( " Instance stopped time : " , date_extract)
        print ("Current time is : ", current_date )
        print ("Time difference is : ", time_diff )

        print ("Hours:",hours)
        if (hours<=1) :
              print ("Stopped instance in last hour is: " , instance.instance_id )
              Flag=0

if (Flag==1):        
 print("There are no instances stopped in lasdt one hour")
                    



