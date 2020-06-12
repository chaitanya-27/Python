import boto3

print("Hello World")

session = boto3.Session(profile_name='dev')

ec2 = boto3.resource('ec2')

ids = [ 'i-06df7d6ebf48691d1' ]

instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
for instance in instances:
    print(instance.id, instance.instance_type)

for snapshot in ec2.snapshots.filter(OwnerIds=["103285789555"]):
    print(snapshot.id)



for images in ec2.images.filter(ImageIds=["ami-e2eca482"]):
    print("printing image id",images.id)
        
input("input any string to exit")
