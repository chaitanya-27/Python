#!/usr/bin/python
#This script does the basic security check.
#It checks 
#1.the server hosting, that is, if any server is hosted in VPC Classic, 
#2.if there is any security group which has ports opened for all.
#3.are all IAM keys rotated in 90 days
#4.if MFA is enabled on each user of an account
#5.if Cloudtrail is enabled in all regions
#6.if any s3 bucket has open permissions

#Author : Prashant Shirke


#importing the required package

import csv
import glob
import xlwt
import os
import boto.ec2
import boto.s3
import datetime
import boto.cloudtrail
import boto.iam.connection

#getting all regions
regions= boto.ec2.regions()

#function to check Are ALL the servers created within VPC

def ServerHosting():

	with open('ServerHosting.csv','w+') as fp:
		csvwriter=csv.writer(fp,delimiter=',')
		data=['Region', ' Instance Name', 'Instance Id', 'Remarks' ]
		csvwriter.writerow(data)
		flag=0
#Traversing through all regions

		for region in regions:
			region_name=region.name
			flag=0
#Excluding cn-north-1 and us-gov-west-1 as general public cannot access these regions

			if not (region_name=='cn-north-1' or region_name=='us-gov-west-1'):
				data=[region_name]
				csvwriter.writerow(data)
				connection = boto.ec2.connect_to_region(region_name)
				reservations = connection.get_all_instances()				

#Traversing through all regions to check if every instance is created within VPC
				for reservation in reservations:				
					for instance in reservation.instances:
						detail=instance.__dict__
						count=0
						if detail['vpc_id'] == None:
							count=count+1
						if count!=0:
#Pushing the output in CSV file
							data = [" ",instance.tags['Name'] , instance.id," "]
							csvwriter.writerow(data)
							flag=1
				if flag == 0:
					data= [" ", " ", " ","No server in EC2 Classic"]
					csvwriter.writerow(data)



#Function to check if there any security group which have ports opened for all, and lists all the security groups names, Source Ip adress for which it is open and the to port. 
def Security_group_opened_for_all():

	with open('Security_Groups_open_for_all.csv','w+') as fp:
		data=['Regions','Security Group Name', 'Source', 'Open Port']
		csvwriter = csv.writer(fp,delimiter=',')
		csvwriter.writerow(data)
		for reg in regions:
			r_name=reg.name
			if not (r_name=='cn-north-1' or r_name=='us-gov-west-1'):
				data=[r_name]
				csvwriter.writerow(data)
				connection = boto.ec2.connect_to_region(r_name)
#traversing all security groups to check if any port is open for all
				sg=connection.get_all_security_groups()
				for group in sg:
					for rule in group.rules:
						if '0.0.0.0/0' in str(rule.grants):
							if rule.to_port == None:
								rule.to_port='ALL'
							data = [" ", group.name, rule.grants, rule.to_port ]
							csvwriter.writerow(data)


#this function checksn have all the IAM keys been rotated in last 90 days	

def iam_key_rotate():
        connection=boto.iam.connection.IAMConnection()
        users=connection.get_all_users()
        resp=users['list_users_response']['list_users_result']['users']
        with open('iam_key_rotate.csv','w+') as fp:
                csvwriter=csv.writer(fp,delimiter=',')
                data=[ 'IAM User','Key','Current Status','Active/Inactive' ]
                csvwriter.writerow(data)
#To list all the users in a loop and in a list called val

                val=[]
                for user in range(0,len(resp)):
                        val.append(users['list_users_response']['list_users_result']['users'][user]['user_name'])

#To list all access keys:

                keyval = []
                for accesskey in range (0,len(val)):
                        keyval.append(connection.get_all_access_keys(val[accesskey]))
#List all the details of the keys
                keydetails = []
                for details in range (0,len(keyval)):
                        ab=(keyval[details]['list_access_keys_response']['list_access_keys_result']['access_key_metadata'])
                        keydetails.append(ab)
#list key metadata
                key_det_resp=[]
                for resp in range (0,len(keyval)):
                        for res in range (len(keydetails[resp])):
                                ab=(keyval[resp]['list_access_keys_response']['list_access_keys_result']['access_key_metadata'][res-1]['create_date'])
                                key_det_resp.append(ab)
#Get create time of date
                dates = []
                for i in range (0,len(key_det_resp)):
                        dates.append(datetime.datetime.strptime(key_det_resp[i], '%Y-%m-%dT%H:%M:%SZ'))

                datearr = []
                for i in range (0,len(dates)):
                        datearr.append(dates[i].date())
		
                d1 = datetime.date.today()  # get the current date

                diff = []
                for i in range (0,len(datearr)):
                        	differ = d1 - datearr[i]
                        	diff.append(differ.days)  # find the difference in dates

                activekeys = []
                for value in range (0,len(keyval)):
                        for key_det in range (len(keydetails[value])):
                                ab=(keyval[value]['list_access_keys_response']['list_access_keys_result']['access_key_metadata'][key_det-1]['status'])
                                activekeys.append(ab)

                keys = []
                for key in range (0,len(keyval)):
                        for no_key in range (len(keydetails[key])):
                                ab=(keyval[key]['list_access_keys_response']['list_access_keys_result']['access_key_metadata'][no_key-1]['access_key_id'])	
                                keys.append(ab)

                for value in range (0,len(val)):
                        if diff[value] > 90:
                                data=[ val[value],keys[value],"Key Not rotated from 90 days",activekeys[value] ]
                                csvwriter.writerow(data)
                        else:
                                data=[ val[value],keys[value],"Key is rotated",activekeys[value] ]
                                csvwriter.writerow(data)


#function to check if MFA is enabled on account
def func_MFA_enabled():

	connection=boto.iam.connection.IAMConnection()
	users=connection.get_all_users()
	no_of_users=len(users['list_users_response']['list_users_result']['users'])
	with open('MFA_Enabled.csv','w+') as fp:
		csvwriter=csv.writer(fp,delimiter=',')
		data=['User Name','MFA Status']
		csvwriter.writerow(data)
		for user in range(0,no_of_users):
			user_name=users['list_users_response']['list_users_result']['users'][user]['user_name']
			mfa=connection.get_all_mfa_devices(user_name)
			status=mfa['list_mfa_devices_response']['list_mfa_devices_result']['mfa_devices']
			if len(status)==0:
				data=[user_name,"Not Enabled"]
				csvwriter.writerow(data)
			else:
				data=[user_name,"Enabled"]
				csvwriter.writerow(data)
	


#function to check if cloudtrail is enabled on all regions

def cloudtrail_Status():
        with open("Cloudtrail_Status.csv",'w+') as fp:
                csvwriter=csv.writer(fp,delimiter=',')
                data=['Region', 'Coudtrail Status']
                csvwriter.writerow(data)
                for reg in regions:
                        r_name=reg.name
                        if not (r_name=='cn-north-1' or r_name=='us-gov-west-1') :
                                connection = boto.cloudtrail.connect_to_region(r_name)
                                c_trail=connection.describe_trails()
                                if not c_trail['trailList']:
                                        data=[r_name, "Not Enabled"]
                                        csvwriter.writerow(data)
                                else:
                                        data=[r_name, "Enabled"]
                                        csvwriter.writerow(data)


#Access Permissions on S3 buckets
def func_access_permissions_on_s3():
        with open('access_permissions_on_s3.csv','w+') as fp:
                csvwriter=csv.writer(fp,delimiter=',')
                data=[ ' Bucket Name/ID','User-name (Owner)','User','Access Permissions' ]
                csvwriter.writerow(data)
                connection=boto.connect_s3()
                buckets=connection.get_all_buckets()
                for bucket in buckets:
                        #bucket_policy=bucket.get_acl()
                        #bucket_policy=bucket.get_acl()
                        user_policy=bucket_policy.acl
                        user_grants=user_policy.grants
                        no_of_user=len(user_grants)
                        data=[bucket.name.title(),bucket_policy.owner.display_name," "]
                        csvwriter.writerow(data)
                        for user in user_grants:
                                uname=user.display_name
                                user_permission=user.permission
                                if (uname==None):
                                        u_uri=user.uri
                                        uri_split=u_uri.split('/')
                                        uname=str(uri_split[-1])
                                data=["","",uname,user_permission ]
                                csvwriter.writerow(data)


#Calling the functions

ServerHosting()
Security_group_opened_for_all()
cloudtrail_Status()
func_MFA_enabled()
#func_access_permissions_on_s3()
iam_key_rotate()

#code to add multiple CSV files as different tabs in a CSV file
wb = xlwt.Workbook()
for filename in glob.glob("*.csv"):
	(f_path, f_name)=os.path.split(filename)
	(f_short_name, f_extension)=os.path.splitext(f_name)
	ws=wb.add_sheet(f_short_name)
	spamReader = csv.reader(open(filename, 'rb'))
	for rowx, row in enumerate(spamReader):
		for colx, value in enumerate (row):
			ws.write(rowx, colx, value)
wb.save("SecurityCheck_output.xls")

Deleting the CSV files for clear output
os.remove('Security_Groups_open_for_all.csv')
os.remove('iam_key_rotate.csv')
os.remove('MFA_Enabled.csv')
os.remove("Cloudtrail_Status.csv")
#os.remove('access_permissions_on_s3.csv')
os.remove('ServerHosting.csv')
