import boto3
import logging
from datetime import *
import json



#setup simple logging for INFO
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

sts_client = boto3.client('sts')



#Token_code=input('Enter MFA token code:')

assumedRoleObject = sts_client.assume_role(
   # RoleArn="arn:aws:iam::132833855232:role/beta1",
    RoleArn="arn:aws:iam::602583143679:role/icaws-stg-cust1",
    RoleSessionName="AssumeRoleSession1",
    #SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
    #TokenCode=Token_code
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

#sts_client = boto3.client('sts')
#ec2 = boto3.resource('ec2', region_name="us-west-1")
#sns = boto3.resource('sns',region_name="us-west-1")
'''
SNS_TOPIC_NAME='InstanceStatus'
SNS_ARN_OBJECT=sns.create_topic(Name=SNS_TOPIC_NAME)
SNS_ARN= SNS_ARN_OBJECT.arn
platform_endpoint = sns.PlatformEndpoint(SNS_ARN)
'''
#platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:us-west-1:132833855232:InstanceStatus')
#Coke SNS Topic: arn:aws:sns:us-west-2:132833855232:CokeTeradataNonProd-2-Notification
platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:us-west-2:132833855232:TestSNSMail')


#set the date to today for the snapshot
today = datetime.now().date()

#def lambda_handler(event, context):


def stopped_instances():
    c=""
    Report = "Instance ID list stopped in last one hour : \n"
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped','terminated']}])
                                              #{'Name': 'tag:Name','Values': ['*CokeTeradataNonProd-2*']}])
    for instance in instances:
        print instance.instance_id
        print instance.state_transition_reason
        date_text= instance.state_transition_reason
        date_extract_text=date_text[16:35]
        print date_extract_text
        try:
         date_extract=datetime.strptime(date_extract_text,'%Y-%m-%d %H:%M:%S')
        except Exception as e:
         date_extract=datetime.utcnow().strftime(('%Y-%m-%d %H:%M:%S'))
         date_extract=datetime.strptime(date_extract,'%Y-%m-%d %H:%M:%S')
        current_date=datetime.utcnow().strftime(('%Y-%m-%d %H:%M:%S'))
        print current_date
        current_date=datetime.strptime(current_date,'%Y-%m-%d %H:%M:%S')
        print current_date
        time_diff= current_date - date_extract
        hours = (time_diff.days) * 24 + (time_diff.seconds) // 3600
        print hours
        if (hours<=1) :
             c+=instance.instance_id + "\n"
    Report+= c 
    print Report
   

  

stopped_instances()




#origional code

'''

def stopped_instances():
    c=""
    Report = "Instance ID list stopped in last one hour : \n"
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
    for instance in instances:
        print instance.instance_id
        date_text= instance.state_transition_reason
        date_extract_text=date_text[16:35]   
        date_extract=datetime.strptime(date_extract_text,'%Y-%m-%d %H:%M:%S')
        current_date=datetime.utcnow().strftime(('%Y-%m-%d %H:%M:%S'))
        current_date=datetime.strptime(current_date,'%Y-%m-%d %H:%M:%S') 
        time_diff= current_date - date_extract
        hours = (time_diff.days) * 24 + (time_diff.seconds) // 3600
        if (hours<=1) :
             c+=instance.instance_id + "\n"
    Report+= c 
    print Report
   
    response = platform_endpoint.publish(
        Message=Report,
        Subject='Stopped Instance ID list: ' + str(today),
        MessageStructure='string',
    )

stopped_instances()


'''
