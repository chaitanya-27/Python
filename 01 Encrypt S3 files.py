import boto3
import logging
from datetime import *
import json
import xlwt
from botocore.client import Config

sts_client = boto3.client('sts')

#Token_code=input('Enter MFA token code:')

assumedRoleObject = sts_client.assume_role(
    RoleArn="arn:aws:iam::132833855232:role/beta1",
    RoleSessionName="AssumeRoleSession1",
#    SerialNumber='arn:aws:iam::103285789555:mfa/chaitanya.devarmani',
#   TokenCode=Token_code
)

credentials = assumedRoleObject['Credentials']

'''
ec2 = boto3.resource(
    'ec2',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

#f= open("NodeIPAddress1.txt","w+")
'''

s3 = boto3.resource(
    's3',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
    config=Config(signature_version='s3v4')
)

client= boto3.client(
    's3',
    region_name="us-west-2",
    aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
    config=Config(signature_version='s3v4')
)

#bucket = s3.Bucket('tmc-bkptest')

#s3.Object(('test-bkp-cd','testcopy.txt').copy_from(CopySource='test-bkp-cd/test.txt')).set_contents_from_string(headers={'x-amz-server-side-encryption':'AES256',})
#s3.Object('test-bkp-cd','test.txt').delete()

#response = client.copy_object(Bucket='test-bkp-cd',CopySource='test-bkp-cd/testcopy.txt',Key='testnew.txt',ServerSideEncryption='AES256')


#response = client.list_objects(Bucket='tmc-bkptest')

'''

abc= response['Contents']


for abc in abc :
    Name=abc['Key']
    if Name.find("newfolder1")>0:
        print abc['Key']
'''


#client.copy_object(Bucket='test-bkp-cd',CopySource='tmc-bkptest/enc_test/ENC_TEST_72_1_file1_data_1488461176226/F00000',Key='new folder/newfolder1/F00000',ServerSideEncryption='AES256')
#client.copy_object(Bucket='tmc-bkptest',CopySource='tmc-bkptest/enc_test/ENC_TEST_72_1_file1_data_1488461176226/F00000',Key='enc_test/ENC_TEST_72_1_file_dict_1488461176226/F00000_pqrs',ServerSideEncryption='AES256')
#client.delete_object(Bucket='tmc-bkptest',Key='enc_test/ENC_TEST_72_1_file_dict_1488461176226/F00000_pqrs')
#client.delete_object(Bucket='test-bkp-cd',Key='new folder/newfolder1/F00000')
'''
bucket = s3.Bucket('test-bkp-cd')
#for obj in bucket.objects.all():
    #key = s3.Object(bucket.name, obj.key)
key = s3.Object('test-bkp-cd','test.txt')    
print key
print key.server_side_encryption
abc=key.server_side_encryption
if abc is None:
    print "hello"
else:
    print" error"
'''
client.delete_object(Bucket='test-bkp-cd',Key='delete.txt')
