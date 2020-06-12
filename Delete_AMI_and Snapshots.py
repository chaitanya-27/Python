import boto3

# The calls to AWS STS AssumeRole must be signed with the access key ID
# and secret access key of an existing IAM user or by using existing temporary 
# credentials such as those from antoher role. (You cannot call AssumeRole 
# with the access key for the root account.) The credentials can be in 
# environment variables or in a configuration file and will be discovered 
# automatically by the boto3.client() function. For more information, see the 
# Python SDK documentation: 
# http://boto3.readthedocs.io/en/latest/reference/services/sts.html#client

# create an STS client object that represents a live connection to the 
# STS service

#session = boto3.Session(profile_name='chaitanya.devarmani')

sts_client = boto3.client('sts')

# Call the assume_role method of the STSConnection object and pass the role
# ARN and a role session name.
assumedRoleObject = sts_client.assume_role(
    RoleArn="arn:aws:iam::XXXXXXXXXX:role/beta1",
    RoleSessionName="AssumeRoleSession1"
)

# From the response that contains the assumed role, get the temporary 
# credentials that can be used to make subsequent API calls
credentials = assumedRoleObject['Credentials']

ec2 = boto3.resource(
    'ec2',aws_access_key_id = credentials['AccessKeyId'],
    aws_secret_access_key = credentials['SecretAccessKey'],
    aws_session_token = credentials['SessionToken'],
)

snapshot = ec2.snapshots.all()

image_list = ec2.images.filter(Filters=[{'Name': 'name', 'Values': ['*AMI-NAME*']}])
for images in image_list :
    print ("AMI name to be deregistred",images.name)
    AMI_ID=images.id
    print ("Ami id is :", AMI_ID)
    images.deregister()
    for snapshots in snapshot :
        SNAP_DSC = snapshots.description
        if SNAP_DSC.find(AMI_ID) > 0:
                print ("Snapshot associated with this AMI will be deleted" ,snapshots.description)
                snapshots.delete()
