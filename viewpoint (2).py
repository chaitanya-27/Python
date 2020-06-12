"""
Helper file for ViewPoint.
"""
import json
import requests
from requests.auth import HTTPBasicAuth


class ViewPointUserRoles:
    """
    CONST: Roles that can be assigned to a ViewPoint user
    """
    User = "User"
    TD_WebServices = "TD_WebServices"
    Administrator = "Administrator"
    TD_SE = "TD_SE"
    TD_TSS = "TD_TSS"


class TaasmetricsUser:
    """
    CONST: User profile that will be created for metrics agent in ViewPoint
    """
    username = "taasmetrics"
    password = "seattle"
    roles = [ViewPointUserRoles.TD_WebServices, ViewPointUserRoles.User]
    first_name = "taas"
    last_name = "metrics"
    email = "void@example.com"


class ViewPoint(object):
    """
    Class for ViewPoint
    """
    BASE_URL = "api/public/systemHealth/systems" # To get system ID
    USER_URL = "api/security/v1/users"           # To create user

    def __init__(self, vp_ip_address, user_name, user_password, https=False):
        """

        :param vp_ip_address: view point ip address
        :param user_name:  username to login to Viewpoint. Admin crednetials may be needed for certain operaions
        :param user_password: password to login to Viewpoint. Admin crednetials may be needed for certain operaions
        :param https: If True all connection to Viewpoint REST API will be made over https
        """
        self.vp_ip_address = str(vp_ip_address)
        self.user_name = str(user_name)
        self.user_password = str(user_password)
        
        if https:
            try:
                #This is causing unit tests to fail on Jenkins server, so wrapping it inside try/except block
                requests.packages.urllib3.disable_warnings() # This is just to supress the warning logs in production.
                                                             # The real thing is when we call requests with 'Verify=False'.
                                                             # Trying to establish https connection to an ip-address 
                                                             # will fail without setting Verify=False.
            except Exception as e:
                # We don't intend to do anything if disabling warning fails (mainly in Jenkins setup)
                pass

            self.protocol = "https"
        else:
            self.protocol = "http"

        self.auth = HTTPBasicAuth(user_name,
                                  user_password)


    def check_system_availability(self):
        """
        Returns list of systems that the viewpoint can see
        :return: status: boolean, List of dict[{system_id, system_name}], status_message:string
        """
        target_url = "%s://%s/%s"%(self.protocol, 
                                   str(self.vp_ip_address), 
                                   str(self.BASE_URL)
                                   )

        print("Info: [check_system_availability] target_url = [%s]"%str(target_url))
        resp_val = requests.get(target_url,
                                auth=self.auth, 
                                verify=False
                                )

        if resp_val.status_code == 200:

            json_res_list = json.loads(resp_val.text)

            if len(json_res_list) == 0:
                sys_error = "Error: No system is visible to the Viewpoint. Try restarting Viewpoint."
                return False, None, sys_error
            else:
                system_list = list()
                for item in json_res_list:
                    if 'systemName' in item and 'systemId' in item:
                        sys = dict()
                        sys['systemId'] = item['systemId']
                        sys['systemName'] = item['systemName']
                        system_list.append(sys)

                # Success path
                return True, system_list, "Success: Total [%s] systems are visible to the Viewpoint" % str(len(json_res_list))

        return False, None, "Error: Something went wrong. Return status code = [%s]. Returned data = [%s]"%(str(resp_val.status_code), 
                                                                                                            str(resp_val.text))

    def get_system_id(self, system_name):
        """

        :param system_name: system name assigned to the Teradata DB cluster
        :return: (system_id:string or None , message:string)
        """
        target_url = "%s://%s/%s"%(self.protocol,
                                   str(self.vp_ip_address), 
                                   str(self.BASE_URL))

        resp_val = requests.get(target_url,
                                auth=self.auth,
                                verify=False
                                )

        if resp_val.status_code != 200:
            return None, "Error: Viewpoint call failed. Status Code - [%s]"%str(resp_val.status_code)

        if resp_val.status_code == 200:
            json_res_list = json.loads(resp_val.text)

            if len(json_res_list) == 0:
                return None, "Error: List Empty"
            else:
                for item in json_res_list:
                    if item['systemName'] == system_name:
                        return str(item['systemId']), "Success"

        return None, "Error"

    def create_user(self, username, password, roles, first_name, last_name, email, external_auth=False):
        """
        Creates a Viewpoint user

        NOTE: The (user_name, user_password) that was used to create the object should be an Admin. 
        Non-admin credentials will fail.

        :param username: string
        :param password: string
        :param roles: a list, example ["User", "TD_WebServices"]
        :param first_name: string
        :param last_name: string
        :param email: string
        :param external_auth: boolean
        :return: status:boolean, return message:string
        """
        data = {"username": username,
                "password": password,
                "externallyAuthenticated": "false",
                "firstName": first_name,
                "lastName" : last_name,
                "email": email,
                "roles": roles
               }

        headers = {'Content-type': 'application/json'}
        target_url = "%s://%s/%s"%(self.protocol, str(self.vp_ip_address), str(self.USER_URL))
        resp_val = requests.post(target_url,
                                 headers=headers,
                                 data=json.dumps(data),
                                 auth=self.auth,
                                 verify=False)

        try:
            json_res_list = json.loads(resp_val.text)
            if str(json_res_list['username']) == username:
                #Success path
                return True, "Success"
        except Exception as e:
            try:
                # With the changes we have made for Ver2 if the service account already exist we
                # have to fail, as the passwords we use are no longer static and are unique.
                if "key already exists" in str(json_res_list['message']):
                    # Success path where the user account already exists
                    return False, "Error: User account already exists"
            except:
                return False, "Error: Something went wrong. Return status code = [%s]"%(str(resp_val.status_code))

        return False, "Error: Something went wrong. Return status code = [%s]"%(str(resp_val.status_code))

    def create_user_taasmetrics(self, service_account_password=None):
        """
        Calls ViewPoint.create_user() to create the default user for
        the Telegraf agent using TaasmetricsUser profile data.

        :return: status:boolean, return message:string
        """

        if service_account_password is None:
            service_account_password = TaasmetricsUser.password

        return self.create_user(TaasmetricsUser.username,
                                service_account_password,
                                TaasmetricsUser.roles,
                                TaasmetricsUser.first_name,
                                TaasmetricsUser.last_name,
                                TaasmetricsUser.email)

    def get_metrics_data(self, system_id):
        """

        Calls ViewPoint http[s]://[vp-ip-address]/api/public/systemHealth/systems/[system_id]/metrics
        And checks and returns metrics data with the "CPU_UTILIZATION" and "TOTAL_DISK_SPACE"
        int it.

        :return: status:boolean, data:metrics data, return message:string
                        data is a json object {'cpu_utilization_percentage': 10, 'disk_space_percentage': 20}
        """
        resp_data = None

        target_url = "%s://%s/%s/%s/metrics"%(self.protocol,
                                              str(self.vp_ip_address),
                                              str(self.BASE_URL),
                                              str(system_id))

        resp_val = requests.get(target_url,
                                auth=self.auth,
                                verify=False)

        if resp_val.status_code != 200:
            return None, None, "Error: Viewpoint call failed. Status Code - [%s]"%str(resp_val.status_code)

        if resp_val.status_code == 200:
            json_res_list = json.loads(resp_val.text)

            if len(json_res_list) == 0:
                return False, resp_data, "Error: Response json list is Empty"
            else:
                try:
                    cpu_metric = False
                    disk_metric = False
                    cpu_data = 0
                    disk_data = 0

                    for item in json_res_list:
                        if item['metricName'] == "CPU_UTILIZATION":
                            if 'data' in item:
                                data = item['data']
                                if len(data) != 0:
                                    cpu_metric = True
                                    cpu_data = data[0]['value']
                        if item['metricName'] == "TOTAL_DISK_SPACE":
                            if 'data' in item:
                                data = item['data']
                                if len(data) != 0:
                                    disk_metric = True
                                    disk_data = data[0]['value']

                    resp_data = {'cpu_utilization_percentage': cpu_data,
                                 'disk_space_percentage': disk_data}

                    if cpu_metric and disk_metric:
                        # Success path
                        return True, resp_data, "Success: API works fine"
                    elif cpu_metric and not disk_metric:
                        return False, resp_data, "Error: Unable to find [TOTAL_DISK_SPACE]"
                    elif not cpu_metric and disk_metric:
                        return False, resp_data, "Error: Unable to find [CPU_UTILIZATION]"
                    elif not cpu_metric and not disk_metric:
                        return False, resp_data, "Error: [CPU_UTILIZATION] & [TOTAL_DISK_SPACE]!"

                except Exception as e:

                    # If the ViewPoint is not working correctly it returns a 'message' item
                    if 'message' in json_res_list:
                        if 'failed' in json_res_list['message']:
                            # Failure path mose specifically when the VP returns
                            # {"message":"Request processing failed; nested exception
                            # is java.lang.NullPointerException"}
                            return False, resp_data, "Error: %s"%str(json_res_list['message'])

        return False, resp_data, "Error: Something went wrong!"

"""
    def check_metrics_api_system_id(self, system_id):
        ###

        # Calls ViewPoint http[s]://[vp-ip-address]/api/public/systemHealth/systems/[system_id]/metrics
        # And checks if it returns metrics data with the "CPU_UTILIZATION" and "TOTAL_DISK_SPACE" in it.

        # Note: Credentials that were used during initializing the Viewpoint object will be used for the call

        # :param system_id: string
        # :return: status:boolean, return message:string
        #          True, "Success" means the ViewPoint metrics API is working fine
        #          False, "Error message"  means something is not right with the ViewPoint metrics API

        ###
        target_url = "%s://%s/%s/%s/metrics"%(self.protocol, str(self.vp_ip_address),
                                                str(self.BASE_URL),
                                                str(system_id))
        resp_val = requests.get(target_url,
                                auth=self.auth, verify=False
                               )
        json_res_list = json.loads(resp_val.text)

        if resp_val.status_code != 200:
            return False, "Error: Viewpoint call failed. Status Code - [%s]"%str(resp_val.status_code)

        if resp_val.status_code == 200:

            if len(json_res_list) == 0:
                return False, "Error: Response json list is Empty"
            else:
                try:
                    cpu_metric = False
                    disk_metric = False
                    for item in json_res_list:
                        if item['metricName'] == "CPU_UTILIZATION":
                            cpu_metric = True
                        if item['metricName'] == "TOTAL_DISK_SPACE":
                            disk_metric = True

                    if cpu_metric and disk_metric:
                        # Success path
                        return True, "Success: API works fine"
                except:
                    # If the ViewPoint is not working correctly it returnsx a 'message' item

                    if 'message' in json_res_list:
                        if 'failed' in json_res_list['message']:
                            # Failure path mose specifically when the VP returns
                            # {"message":"Request processing failed; nested exception
                            # is java.lang.NullPointerException"}
                            return False, "Error: %s"%str(json_res_list['message'])

        return False, "Error: Something went wrong!"

    def health_check(self, system_name=None):
        ###
        # Will perform following checks
        # 1. Check if the viewpoint port 80 is reachable
        # 2. Check if user creation API works
        # 3. Check if health service API to retrieve system ID works fine
        # 4. Check if health service API to retrieve metrics data works fine

        # :param system_name: string (optional) If given will be used to check if we can
        #                     retrieve the system ID for it check #3
        # :return: commons.HealthCheck object
        ###
        health_check = HealthCheck("Viewpoint")

        #Check 1: Viewpoint is reachable at port 80
        try:
            check1_status, check1_message = Network.check_socket_is_alive(self.vp_ip_address, "80")
        except Exception as e1:
            check1_status, check1_message = False, str(e1)
        health_check.add(component_name="viewpoint_socket",
                         check_description="Checks if the viewpoint can be reached at port 80",
                         status=check1_status,
                         status_message=check1_message)

        #Check 2: Viewpoint user creation API works.
        try:
            check2_status, check2_message = self.create_user_taasmetrics()
        except Exception as e2:
            check2_status, check2_message = False, str(e2)
        health_check.add(component_name="viewpoint_user_create",
                         check_description="Checks if [taasmetrics] user can be created in the Viewpoint",
                         status=check2_status,
                         status_message=check2_message)

        #Check 3: Check if any database system is visible in the Viewpoint.
        try:
            check3_status, check3_message = self.check_system_availability()
        except Exception as e3:
            check3_status, check3_message = False, str(e3)
        health_check.add(component_name="viewpoint_db_systems",
                         check_description="Checks if database systems are visible in the Viewpoint",
                         status=check3_status,
                         status_message=check3_message)

        system_id = None
        if system_name:
            system_name = str(system_name)

            #Check 4: Check if we can retrieve the system ID for the given system name.
            try:
                check4_status, check4_message = self.get_system_id(system_name)
                system_id = check4_status
                if system_id:
                    check4_message = "Success: System Id is [%s] for the System Name [%s]" % (str(system_id), str(system_name))
                    check4_status = True
                else:
                    check4_message = "Error: System Id is not found for the System Name [%s]" % (str(system_name))
                    check4_status = False
            except Exception as e4:
                check4_status, check4_message = False, str(e4)
            health_check.add(component_name="viewpoint_get_system_id",
                             check_description="Checks if there is a System ID for given the given System Name",
                             status=check4_status,
                             status_message=check4_message)

            #Check 5: Check if Viewpoint metrics API works fine for the given System Name.
            try:
                if system_id is None:
                    check5_status, check5_message = False, "Error: Unable to get the System ID and so the metrics API will fail"
                else:
                    # We now query metrics health API with 'taasmetrics/seattle'
                    # user account and verify if the CPU and DISK metrics are being returned

                    if check2_status: # Proceed to to check the API only if check2 (account creation) passed
                        check5_status, check5_message = self.check_metrics_api_system_id(system_id)
                    else:
                        check5_status, check5_message = False, "Error: 'taasmetrics' user creation has failed and so the metrics API will fail."

            except Exception as e5:
                check5_status, check5_message = False, str(e5)
            health_check.add(component_name="check_metrics_api",
                             check_description="Checks if Viewpoint metrics API returns CPU and DISK data for the given System Name",
                             status=check5_status,
                             status_message=check5_message)

        return health_check

"""
def main():

    vp_ipaddress = "34.204.52.196"
    vp_admin_user = "admin"
    vp_admin_pass = "i-0976b387dbd807540"

    vp = ViewPoint("52.90.44.46", "taasmetrics", "seattle")

    system_id = 1

    ### test
    ret_status, ret_val, ret_message = vp.get_metrics_data(system_id=system_id)
    print "Metrics Data - %s, %s, %s" % (ret_status, ret_val, ret_message)
    return

    # Test for system availability and all system info
    a, b, c = vp.check_system_availability()
    print a, b, c
    return

    ## test as Admin
    viewpoint_instance_admin = ViewPoint(vp_ipaddress, vp_admin_user, vp_admin_pass)
    a, b = viewpoint_instance_admin.create_user_taasmetrics()
    print "create_user_taasmetrics - %s, %s" % (a, b)

    ## test as Admin
    a, b = viewpoint_instance_admin.get_system_id(system_name="TAASmpp")
    print "get_system_id - %s, %s" % (a, b)

    ### test
    user = TaasmetricsUser.username
    password = TaasmetricsUser.password
    viewpoint_instance = ViewPoint(vp_ipaddress, user, password)

    system_id = 1

    ### test
    ret_status, ret_val, ret_message = viewpoint_instance.get_metrics_data(system_id=system_id)
    print "Metrics Data - %s, %s, %s" % (ret_status, ret_val, ret_message)

if __name__ == "__main__":
    main()
