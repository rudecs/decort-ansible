#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

"""
This is the library of utility functions and classes for managing DECORT cloud platform.

These classes are made aware of Ansible module architecture and designed to be called from the main code of an Ansible
module to fulfill cloud resource management tasks.

Methods defined in this file should NOT implement complex logic like building execution plan for an
upper level Ansible module. However, they do implement necessary sanity checks and may abort upper level module
execution if some fatal error occurs. Being Ansible aware, they usually do so by calling AnsibleModule.fail_json(...)
method with properly configured arguments.

NOTE: this utility library requires DECORT platform version 3.4.0 or higher. 
It is not compatible with older versions.

Requirements:
- python >= 3.8
- PyJWT Python module
- requests Python module
- netaddr Python module
- DECORT cloud platform version 3.6.1 or higher
"""

import json
import jwt
import netaddr
import time
import requests

from ansible.module_utils.basic import AnsibleModule


#
# TODO: the following functionality to be implemented and/or tested
# 4) workflow callbacks
# 5) run phase states
# 6) vm_tags - set/manage VM tags
# 7) vm_attributes - change VM attributes (name, annotation) after VM creation - do we need this in Ansible?
# 9) test vm_restore() method and execution plans that involve vm_restore()
#


class DecortController(object):
    """DecortController is a utility class that holds target controller context and handles API requests formatting
    based on the requested authentication type.
    """

    VM_RESIZE_NOT = 0
    VM_RESIZE_DOWN = 1
    VM_RESIZE_UP = 2

    def __init__(self, arg_amodule):
        """
        Instantiate DecortController() class at the beginning of any DECORT module run to have the following:
        - check authentication parameters to make sure all required parameters are properly specified
        - initiate test connection to the specified DECORT controller and validates supplied credentias
        - store validated authentication information for later use by DECORT API calls
        - store AnsibleModule class instance to keep handy reference to the module context

        If any of the required parameters are missing or supplied authentication information is invalid, an error
        message will be generated and execution aborted in a way, that lets Ansible to pick this information up and
        relay it upstream.
        """

        self.amodule = arg_amodule  # AnsibleModule class instance

        # Note that the value for 'changed' key is by default set to 'False'. If you plan to manage value of 'changed'
        # key outside of DecortController() class, make sure you only update to 'True' when you really change the state
        # of the object being managed.
        # The rare cases to reset it to False again will usually involve either module running in "check mode" or
        # when you detect and error and are about to call exit_json() or fail_json()
        self.result = {'failed': False, 'changed': False, 'waypoints': "Init"}

        self.authenticator = arg_amodule.params['authenticator']
        self.controller_url = arg_amodule.params['controller_url']

        self.jwt = arg_amodule.params['jwt']
        self.app_id = arg_amodule.params['app_id']
        self.app_secret = arg_amodule.params['app_secret']
        self.oauth2_url = arg_amodule.params['oauth2_url']
        self.password = arg_amodule.params['password']
        self.user = arg_amodule.params['user']
        self.session_key = ''
        # self.iconf = arg_iconf
        self.verify_ssl = arg_amodule.params['verify_ssl']
        self.workflow_callback_present = False
        self.workflow_callback = arg_amodule.params['workflow_callback']
        self.workflow_context = arg_amodule.params['workflow_context']
        if self.workflow_callback != "":
            self.workflow_callback_present = True

        # The following will be initialized to the name of the user in DECORT controller, who corresponds to
        # the credentials supplied as authentication information parameters.
        self.decort_username = ''

        # self.run_phase may eventually be deprecated in favor of self.results['waypoints']
        self.run_phase = "Run phase: Initializing DecortController instance."

        if self.authenticator == "jwt":
            if not self.jwt:
                self.result['failed'] = True
                self.result['msg'] = ("JWT based authentication requested, but no JWT specified. "
                                      "Use 'jwt' parameter or set 'DECORT_JWT' environment variable")
                self.amodule.fail_json(**self.result)
        elif self.authenticator == "legacy":
            if not self.password:
                self.result['failed'] = True
                self.result['msg'] = ("Legacy user authentication requested, but no password specified. "
                                      "Use 'password' parameter or set 'DECORT_PASSWORD' environment variable.")
                self.amodule.fail_json(**self.result)
            if not self.user:
                self.result['failed'] = True
                self.result['msg'] = ("Legacy user authentication requested, but no user specified. "
                                      "Use 'user' parameter or set 'DECORT_USER' environment variable.")
                self.amodule.fail_json(**self.result)
        elif self.authenticator == "oauth2":
            if not self.app_id:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 based authentication requested, but no application ID specified. "
                                      "Use 'app_id' parameter or set 'DECORT_APP_ID' environment variable.")
                self.amodule.fail_json(**self.result)
            if not self.app_secret:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 based authentication requested, but no application secret specified. "
                                      "Use 'app_secret' parameter or set 'DECORT_APP_SECRET' environment variable.")
                self.amodule.fail_json(**self.result)
            if not self.oauth2_url:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 base authentication requested, but no Oauth2 provider URL specified. "
                                      "Use 'oauth2_url' parameter or set 'DECORT_OAUTH2_URL' environment variable.")
                self.amodule.fail_json(**self.result)
        else:
            # Unknown authenticator type specified - notify and exit
            self.result['failed'] = True
            self.result['msg'] = "Error: unknown authentication type '{}' requested.".format(self.authenticator)
            self.amodule.fail_json(**self.result)

        self.run_phase = "Run phase: Authenticating to DECORT controller."

        if self.authenticator == "jwt":
            # validate supplied JWT on the DECORT controller
            self.validate_jwt()  # this call will abort the script if validation fails
            jwt_decoded = jwt.decode(self.jwt, algorithms=["ES384"], options={"verify_signature": False})
            self.decort_username = jwt_decoded['username'] + "@" + jwt_decoded['iss']
        elif self.authenticator == "legacy":
            # obtain session id from the DECORT controller and thus validate the the legacy user
            self.validate_legacy_user()  # this call will abort the script if validation fails
            self.decort_username = self.user
        else:
            # self.authenticator == "oauth2" - Oauth2 based authorization mode
            # obtain JWT from Oauth2 provider and validate on the DECORT controller
            self.obtain_oauth2_jwt()
            self.validate_jwt()  # this call will abort the script if validation fails
            jwt_decoded = jwt.decode(self.jwt, algorithms=["ES384"], options={"verify_signature": False})
            self.decort_username = jwt_decoded['username'] + "@" + jwt_decoded['iss']

        # self.run_phase = "Initializing DecortController instance complete."
        return

    def check_amodule_argument(self, arg_name, abort=True):
        """Checks if the argument identified by the arg_name is defined in the module parameters.

        @param arg_name: string that defines the name of the module parameter (aka argument) to check.
        @param abort: boolean flag that tells if module should abort its execution on failure to locate the
        specified argument.

        @return: True if argument is found, False otherwise (in abort=False mode).
        """

        # Note that if certain module argument is defined in the dictionary, corresponding key will
        # still be found in the module.params. However, if no default value for the argument is
        # declared in the dictionary, it will be set to None upon module initialization.
        if arg_name not in self.amodule.params or self.amodule.params[arg_name] == None:
            if abort:
                self.result['failed'] = True
                self.result['msg'] = "Missing conditionally required argument: {}".format(arg_name)
                self.amodule.fail_json(**self.result)
            else:
                return False
        else:
            return True

    def obtain_oauth2_jwt(self):
        """Obtain JWT from the Oauth2 provider using application ID and application secret provided , as specified at
         class instance init method.

        If method fails to obtain JWT it will abort the execution of the script by calling AnsibleModule.fail_json()
        method.

        @return: JWT as string.
        """

        token_get_url = self.oauth2_url + "/v1/oauth/access_token"
        req_data = dict(grant_type="client_credentials",
                        client_id=self.app_id,
                        client_secret=self.app_secret,
                        response_type="id_token",
                        validity=3600, )
        # TODO: Need standard code snippet to handle server timeouts gracefully
        # Consider a few retries before giving up or use requests.Session & requests.HTTPAdapter
        # see https://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request

        # catch requests.exceptions.ConnectionError to handle incorrect oauth2_url case
        try:
            token_get_resp = requests.post(token_get_url, data=req_data, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError as errco:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' to obtain JWT access token: {}".format(token_get_url, errco)
            self.amodule.fail_json(**self.result)
        except requests.exceptions.Timeout as errti:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' to obtain JWT access token: {}".format(
                token_get_url, errti)
            self.amodule.fail_json(**self.result)

        # alternative -- if resp == requests.codes.ok
        if token_get_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to obtain JWT access token from oauth2_url '{}' for app_id '{}': "
                                  "HTTP status code {}, reason '{}'").format(token_get_url,
                                                                             self.amodule.params['app_id'],
                                                                             token_get_resp.status_code,
                                                                             token_get_resp.reason)
            self.amodule.fail_json(**self.result)

        # Common return values: https://docs.ansible.com/ansible/2.3/common_return_values.html
        self.jwt = token_get_resp.content.decode('utf8')
        return self.jwt

    def validate_jwt(self, arg_jwt=None):
        """Validate JWT against DECORT controller. JWT can be supplied as argument to this method. If None supplied as
        argument, JWT will be taken from class attribute. DECORT controller URL will always be taken from the class
        attribute assigned at instantiation.
        Validation is accomplished by attempting API call that lists accounts for the invoking user.

        @param arg_jwt: the JWT to validate. If set to None, then JWT from the class instance will be validated.

        @return: True if validation succeeds. If validation fails, method aborts the execution by calling
        AnsibleModule.fail_json() method.
        """

        if self.authenticator not in ('oauth2', 'jwt'):
            # sanity check - JWT is relevant in oauth2 or jwt authentication modes only
            self.result['msg'] = "Cannot validate JWT for incompatible authentication mode '{}'".format(
                self.authenticator)
            self.amodule.fail_json(**self.result)
            # The above call to fail_json will abort the script, so the following return statement will 
            # never be executed
            return False

        if not arg_jwt:
            # If no JWT is passed as argument to this method, we will validate JWT stored in the class 
            # instance (if any)
            arg_jwt = self.jwt

        if not arg_jwt:
            # arg_jwt is still None - it mans self.jwt is also None, so generate error and abort the script
            self.result['failed'] = True
            self.result['msg'] = "Cannot validate empty JWT."
            self.amodule.fail_json(**self.result)
            # The above call to fail_json will abort the script, so the following return statement will 
            # never be executed
            return False

        req_url = self.controller_url + "/restmachine/cloudapi/account/list"
        req_header = dict(Authorization="bearer {}".format(arg_jwt), )

        try:
            api_resp = requests.post(req_url, headers=req_header, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' while validating JWT".format(req_url)
            self.amodule.fail_json(**self.result)
            return False  # actually, this directive will never be executed as fail_json exits the script
        except requests.exceptions.Timeout:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' while validating JWT".format(req_url)
            self.amodule.fail_json(**self.result)
            return False

        if api_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to validate JWT access token for DECORT controller URL '{}': "
                                  "HTTP status code {}, reason '{}', header '{}'").format(api_resp.url,
                                                                                          api_resp.status_code,
                                                                                          api_resp.reason, req_header)
            self.amodule.fail_json(**self.result)
            return False

        # If we fall through here, then everything went well.
        return True

    def validate_legacy_user(self):
        """Validate legacy user by obtaining a session key, which will be used for authenticating subsequent API calls
        to DECORT controller.
        If successful, the session key is stored in self.session_key and True is returned. If unsuccessful for any
        reason, the method will abort.

        @return: True on successful validation of the legacy user.
        """

        if self.authenticator != 'legacy':
            self.result['failed'] = True
            self.result['msg'] = "Cannot validate legacy user for incompatible authentication mode '{}'".format(
                self.authenticator)
            self.amodule.fail_json(**self.result)
            return False

        req_url = self.controller_url + "/restmachine/cloudapi/user/authenticate"
        req_data = dict(username=self.user,
                        password=self.password, )

        try:
            api_resp = requests.post(req_url, data=req_data, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' while validating legacy user".format(req_url)
            self.amodule.fail_json(**self.result)
            return False  # actually, this directive will never be executed as fail_json exits the script
        except requests.exceptions.Timeout:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' while validating legacy user".format(req_url)
            self.amodule.fail_json(**self.result)
            return False

        if api_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to validate legacy user access to DECORT controller URL '{}': "
                                  "HTTP status code {}, reason '{}'").format(req_url,
                                                                             api_resp.status_code,
                                                                             api_resp.reason)
            self.amodule.fail_json(**self.result)
            return False

        # Assign session key to the corresponding class attribute.
        # Note that the above API call returns session key as a string with double quotes, which we need to
        # remove before it can be used as 'session=...' parameter to DECORT controller API calls
        self.session_key = api_resp.content.decode('utf8').replace('"', '')

        return True

    def decort_api_call(self, arg_req_function, arg_api_name, arg_params):
        """Wrapper around DECORT API calls. It uses authorization mode and credentials validated at the class
        instance creation to properly format API call and send it to the DECORT controller URL.
        If connection errors are detected, it aborts execution of the script and relay error messages to upstream
        Ansible process.
        If HTTP 503 error is detected the method will retry with increasing timeout, and if after max_retries there
        still is HTTP 503 error, it will abort as above.
        If any other HTTP error is detected, the method will abort immediately as above.

        @param arg_req_function: function object to be called as part of API, e.g. requests.post or requests.get
        @param arg_api_name: a string containing the path to the API name under DECORT controller URL
        @param arg_params: a dictionary containing parameters to be passed to the API call

        @return: api call response object as returned by the REST functions from Python "requests" module
        """

        max_retries = 5
        retry_counter = max_retries

        http_headers = dict()
        api_resp = None

        req_url = self.controller_url + arg_api_name

        if self.authenticator == 'legacy':
            arg_params['authkey'] = self.session_key
        elif self.authenticator in ('jwt', 'oauth2'):
            http_headers['Authorization'] = 'bearer {}'.format(self.jwt)

        while retry_counter > 0:
            try:
                api_resp = arg_req_function(req_url, params=arg_params, headers=http_headers, verify=self.verify_ssl)
            except requests.exceptions.ConnectionError:
                self.result['failed'] = True
                self.result['msg'] = "Failed to connect to '{}' when calling DECORT API.".format(api_resp.url)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script
            except requests.exceptions.Timeout:
                self.result['failed'] = True
                self.result['msg'] = "Timeout when trying to connect to '{}' when calling DECORT API.".format(
                    api_resp.url)
                self.amodule.fail_json(**self.result)
                return None

            if api_resp.status_code == 200:
                return api_resp
            elif api_resp.status_code == 503:
                retry_timeout = 5 + 10 * (max_retries - retry_counter)
                time.sleep(retry_timeout)
                retry_counter = retry_counter - 1
            else:
                self.result['failed'] = True
                self.result['msg'] = ("Error when calling DECORT API '{}', HTTP status code '{}', "
                                      "reason '{}', parameters '{}'.").format(api_resp.url,
                                                                              api_resp.status_code,
                                                                              api_resp.reason, arg_params)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script

        # if we get through here, it means that we were getting HTTP 503 while retrying - generate error
        self.result['failed'] = True
        self.result['msg'] = "Error when calling DECORT API '{}', HTTP status code '{}', reason '{}'.". \
            format(api_resp.url, api_resp.status_code, api_resp.reason)
        self.amodule.fail_json(**self.result)
        return None

    ###################################
    # Compute and KVM VM resource manipulation methods
    ###################################
    def compute_bootdisk_size(self, comp_dict, new_size):
        """Manages size of the boot disk. Note that the size of the boot disk can only grow. This method will issue
        a warning if you try to reduce the size of the boot disk.

        @param (int) comp_dict: dictionary with Compute facts. It identifies the Compute for which boot disk 
        size change is requested.
        @param (int) new_size: new size of boot disk in GB. If new size is the same as the current boot disk size, 
        the method will do nothing. If new size is smaller, an error will occur. 
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_bootdisk_size")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("compute_bootdisk_size() in check mode: change boot disk size for Compute "
                                  "ID {} was requested.").format(comp_dict['id'])
            return

        # Values that are specified via Jinja templating engine (e.g. "{{ new_size }}") may come 
        # as strings. To make sure comparison of new values against current compute size is done 
        # correcly, we explicitly cast them to type int here.
        new_size = int(new_size)

        bdisk_size = 0
        bdisk_id = 0
        for disk in comp_dict['disks']:
            if disk['type'] == 'B':
                bdisk_size = disk['sizeMax']
                bdisk_id = disk['id']
                break
        else:
            self.result['failed'] = True
            self.result['msg'] = ("compute_bootdisk_size(): cannot identify boot disk for Compute "
                                  "ID {}.").format(comp_dict['id'])
            return

        if new_size == bdisk_size:
            self.result['failed'] = False
            self.result['warning'] = ("compute_bootdisk_size(): new size {} is the same as current for "
                                      "Compute ID {}, nothing to do.").format(new_size, comp_dict['id'])
            return
        elif new_size < bdisk_size:
            self.result['failed'] = False
            self.result['warning'] = ("compute_bootdisk_size(): new size {} is less than current {} for "
                                      "Compute ID {}, skipping change.").format(new_size, bdisk_size, comp_dict['id'])
            return

        api_params = dict(diskId=bdisk_id,
                          size=new_size)
        # NOTE: we are using API "resize2", as in this module we are managing 
        # disks attached to compute(s) (DSF ver.2 only)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/resize2", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        for disk in comp_dict['disks']:
            if disk['type'] == 'B':
                disk['sizeMax'] = new_size
                break
        return

    def compute_data_disks(self, comp_dict, new_data_disks):
        """Manage attachment of data disks to the Compute instance.

        @param (dict) comp_dict: dictionary with Compute facts, that identifies the Compute instance 
        to manage data disks for.
        @param (list of int) new_data_disks: list of integer IDs for the disks that must be attached to 
        this Compute instance. If some disk IDs appear in this list, but are not present in comp_dict, 
        these disks will be attached. Vice versa, if some disks appear in comp_dict but are not present
        in data_disks, such disks will be detached.

        Note:
        1) you cannot control boot disk attachment, so including this Compute's boot disk ID
           into data_disk list will have no effect (as well as not listing it there).
        2) this function may modify data_disks by removing from it an ID that corresponds to 
           this Compute's boot disk (if found).
        3) In view of #2, upstream code may need to reread compute facts (com_dict) so that it
           contains updated information about attached disks.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_data_disks")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("compute_data_disks() in check mode: managing data disks on Compute "
                                  "ID {} was requested.").format(comp_dict['id'])
            return

        bdisk_id = 0
        current_list = []
        detach_list = []
        attach_list = []

        # 'data_disks' argument for decort_kvmvm module expects list of integer disk IDs.
        # However, if the value for disk ID comes via Jinja templating like this:
        #   data_disks:
        #      - "{{ my_disk.facts.id }}"  <= will come as string, which is WRONG!!!
        #      - 4571                      <= no Jinja templae, will come as int - OK
        #
        # then all values when entering this method will be of type string. We need to 
        # explicitly cast int type on all of them.
        if new_data_disks is not None:
            for idx, repair in enumerate(new_data_disks):
                new_data_disks[idx] = int(repair)
        else:
            new_data_disks = []

        for disk in comp_dict['disks']:
            if disk['type'] == 'B':
                bdisk_id = disk['id']
                if bdisk_id in new_data_disks:
                    # If boot disk ID is listed in data_disks - remove it
                    new_data_disks.remove(bdisk_id)
            elif disk['type'] == 'D':
                # build manipulation sets for 'D' type disks only
                current_list.append(disk['id'])
                if disk['id'] not in new_data_disks:
                    detach_list.append(disk['id'])

        attach_list = [did for did in new_data_disks if did not in current_list]

        for did in detach_list:
            api_params = dict(computeId=comp_dict['id'], diskId=did)
            self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/diskDetach", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['changed'] = True

        for did in attach_list:
            api_params = dict(computeId=comp_dict['id'], diskId=did)
            self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/diskAttach", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['changed'] = True

        self.result['failed'] = False

        return

    def compute_delete(self, comp_id, permanently=False):
        """Delete a Compute instance identified by its ID. It is assumed that the Compute with the specified 
        ID exists.

        @param (int) comp_id: ID of the Compute instance to be deleted
        @param (bool) permanently: a bool that tells if deletion should be permanent. If False, the Compute 
        will be marked as deleted and placed into a "trash bin" for predefined period of time (usually, for a
        few days). Until this period passes the Compute can be restored by calling 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "compute_delete() in check mode: delete Compute ID {} was requested.".format(comp_id)
            return

        api_params = dict(computeId=comp_id,
                          permanently=permanently, )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return

    def _compute_get_by_id(self, comp_id):
        """Helper function that locates compute instance by ID and returns Compute facts.

        @param (int) comp_id: ID of the Compute instance to find and return facts for.

        @return: (int) Compute ID, dictionary of Compute facts and RG ID where this Compute is located. Note
        that if it fails to find the Compute for the specified ID, it may return 0 for ID and None for the
        dictionary. So it is suggested to check the return values accordingly.
        """
        ret_comp_id = 0
        ret_comp_dict = None
        ret_rg_id = 0

        api_params = dict(computeId=comp_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/get", api_params)
        if api_resp.status_code == 200:
            ret_comp_id = comp_id
            ret_comp_dict = json.loads(api_resp.content.decode('utf8'))
            ret_rg_id = ret_comp_dict['rgId']
        else:
            self.result['warning'] = ("compute_get_by_id(): failed to get Compute by ID {}. HTTP code {}, "
                                      "response {}.").format(comp_id, api_resp.status_code, api_resp.reason)

        return ret_comp_id, ret_comp_dict, ret_rg_id

    def compute_find(self, comp_id,
                     comp_name="", rg_id=0,
                     check_state=True):
        """Tries to find Compute instance according to the specified parameters. On success returns non-zero
        Compute ID and a dictionary with Compute details, or 0 for ID and None for the dictionary on failure.

        @param (int) comp_id: ID of the Compute to locate. If non zero comp_id is passed, it is assumed that
        this Compute exists (check_state flag is ignored). Also comp_name and rg_id are ignored, when searching
        by Compute ID.
        @param (string) comp_name: name of the Compute to locate. Locating Compute instance by name requires 
        that comp_id is set to 0 and non-zero rg_id is specified.
        @param (int) rg_id: ID of the RG to locate Compute instance in. This parameter is used when locating 
        Compute by name and ignored otherwise. Note that this method does not validate RG ID.
        @param (bool) check_state: check that VM in valid state if True. Note that this check is skpped if 
        non-zero comp_id is passed to the method.

        @return: (int) ret_comp_id - ID of the Compute on success (if the Compute was found), 0 otherwise.
        @return: (dict) ret_comp_dict - dictionary with Compute details on success as returned by 
        /cloudapi/compute/get, None otherwise.
        @return: (int) ret_rg_id - ID of the RG, where this Compute instance was found.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_find")

        COMP_INVALID_STATES = ["DESTROYED", "DELETED", "ERROR", "DESTROYING"]

        ret_comp_id = 0
        ret_comp_dict = None
        # validated_rg_id = 0
        # validated_rg_facts = None

        if comp_id:
            # locate Compute instance by ID - if there is no Compute with such ID, the method will abort
            # upstream Ansible module execution by calling fail_json(...)
            # Note that in this mode check_state argument is ignored.
            ret_comp_id, ret_comp_dict, ret_rg_id = self._compute_get_by_id(comp_id)
            if not ret_comp_id:
                self.result['failed'] = True
                self.result['msg'] = "compute_find(): cannot locate Compute with ID {}.".format(comp_id)
                self.amodule.fail_json(**self.result)
                # fail the module - exit
        else:
            # If no comp_id specified, then we have to locate Compute by combination of compute name and RG ID
            # Therefore, RG ID cannot be zero and compute name cannot be empty.
            if not rg_id and comp_name == "":
                self.result['failed'] = True
                self.result[
                    'msg'] = "compute_find(): cannot find Compute by name when either name is empty or RG ID is zero."
                self.amodule.fail_json(**self.result)
                # fail the module - exit

            api_params = dict(includedeleted=True, )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/list", api_params)
            if api_resp.status_code == 200:
                comp_list = json.loads(api_resp.content.decode('utf8'))
            else:
                self.result['failed'] = True
                self.result['msg'] = ("compute_find(): failed to get list Computes. HTTP code {}, "
                                      "response {}.").format(api_resp.status_code, api_resp.reason)
                self.amodule.fail_json(**self.result)
                # fail the module - exit

            # if we have validated RG ID at this point, look up Compute by name in this RG
            # rg.vms list contains IDs of compute instances registered with this RG until compute is
            # destroyed. So we may see here computes in "active" and DELETED states.
            for runner in comp_list:
                if runner['name'] == comp_name and runner['rgId'] == rg_id:
                    if not check_state or runner['status'] not in COMP_INVALID_STATES:
                        ret_comp_id = runner['id']
                        # we still need to get compute info from the model to make sure
                        # compute dictionary contains complete data in correct format
                        _, ret_comp_dict, _ = self._compute_get_by_id(ret_comp_id)
                        break

        # NOTE: if there were no errors, but compute was not found, ret_comp_id=0 is returned
        return ret_comp_id, ret_comp_dict, rg_id

    def compute_powerstate(self, comp_facts, target_state, force_change=True):
        """Manage Compute power state transitions or its guest OS restarts.

        @param (dict) comp_facts: dictionary with Compute instance facts, which power state change is
        requested.
        @param (string) target_state: desired power state of this Compute. Allowed values are: 
        'poweredon', 'poweredoff', 'paused', 'halted', 'restarted', 
        @param (bool) force_change: tells if it is allowed to force power state transition for certain
        cases (e.g. for transition into 'stop' state).

        NOTE: this method may return before the actual change of Compute's power state occurs.
        """

        # @param wait_for_change: integer number that tells how many 5 seconds intervals to wait for the power state
        # change before returning from this method.

        INVALID_MODEL_STATES = ["MIGRATING", "DELETED", "DESTROYING", "DESTROYED", "ERROR", "REDEPLOYING"]
        INVALID_TECH_STATES = ["STOPPING", "STARTING", "PAUSING"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_powerstate")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("compute_powerstate() in check mode. Power state change of Compute ID {} "
                                  "to '{}' was requested.").format(comp_facts['id'], target_state)
            return

        if comp_facts['status'] in INVALID_MODEL_STATES:
            self.result['failed'] = False
            self.result['msg'] = ("compute_powerstate(): no power state change possible for Compute ID {} "
                                  "in its current state '{}'.").format(comp_facts['id'], comp_facts['status'])
            return

        if comp_facts['techStatus'] in INVALID_TECH_STATES:
            self.result['failed'] = False
            self.result['msg'] = ("compute_powerstate(): no power state change possible for Compute ID {} "
                                  "in its current techState '{}'.").format(comp_facts['id'], comp_facts['techStatus'])
            return

        powerstate_api = ""  # this string will also be used as a flag to indicate that API call is necessary
        api_params = dict(computeId=comp_facts['id'])
        expected_state = ""

        if comp_facts['techStatus'] == "STARTED":
            if target_state == 'paused':
                powerstate_api = "/restmachine/cloudapi/compute/pause"
                expected_techState = "PAUSED"
            elif target_state in ('poweredoff', 'halted', 'stopped'):
                powerstate_api = "/restmachine/cloudapi/compute/stop"
                api_params['force'] = force_change
                expected_techState = "STOPPED"
            elif target_state == 'restarted':
                powerstate_api = "/restmachine/cloudapi/compute/reboot"
                expected_techState = "STARTED"
        elif comp_facts['techStatus'] == "PAUSED" and target_state in ('poweredon', 'restarted', 'started'):
            powerstate_api = "/restmachine/cloudapi/compute/resume"
            expected_techState = "STARTED"
        elif comp_facts['techStatus'] == "STOPPED" and target_state in ('poweredon', 'restarted', 'started'):
            powerstate_api = "/restmachine/cloudapi/compute/start"
            expected_techState = "STARTED"

        if powerstate_api != "":
            self.decort_api_call(requests.post, powerstate_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            comp_facts['techStatus'] = expected_techState
        else:
            self.result['failed'] = False
            self.result['warning'] = ("compute_powerstate(): no power state change required for Compute ID {} from its "
                                      "current state '{}' to desired state '{}'.").format(comp_facts['id'],
                                                                                          comp_facts['techStatus'],
                                                                                          target_state)
        return

    def kvmvm_provision(self, rg_id,
                        comp_name, arch,
                        cpu, ram,
                        boot_disk, image_id,
                        annotation="",
                        userdata=None,
                        start_on_create=True):
        """Manage KVM VM provisioning. To remove existing KVM VM compute instance use compute_remove method, 
        to resize use compute_resize, to manage power state use compute_powerstate method.

        @param (int) rg_id: ID of the RG where the VM will be provisioned.
        @param (string) comp_name: that specifies the name of the VM.
        @param (string) arch: hardware architecture of KVM VM. Supported values are: "X86_64" for Intel x86
        and "PPC64_LE" for IBM PowerPC.
        @param (int) cpu: how many virtual CPUs to allocate.
        @param (int) ram: volume of RAM in MB to allocate (i.e. pass 4096 to allocate 4GB RAM).
        @param (int) boot_disk: boot disk size in GB.
        @param (int) image_id: ID of the OS image to base this Compute on.
        @param (string) annotation: optional text description for the VM.
        @param (string) userdata: additional paramters to pass to cloud-init facility of the guest OS.
        @param (bool) start_on_create: set to False if you want the VM to be provisioned in HALTED state.

        @return (int) ret_kvmvm_id: ID of provisioned VM. 
        Note: when Ansible is run in check mode method will return 0.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "kvmvm_provision2")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("kvmvm_provision() in check mode. Provision KVM VM '{}' in RG ID {} "
                                  "was requested.").format(comp_name, rg_id)
            return 0

        api_url = ""
        if arch == "X86_64":
            api_url = "/restmachine/cloudapi/kvmx86/create"
        elif arch == "PPC64_LE":
            api_url = "/restmachine/cloudapi/kvmppc/create"
        else:
            self.result['failed'] = True
            self.result['msg'] = "Unsupported architecture '{}' requested for KVM VM name '{}'".format(arch, comp_name)
            self.amodule.fail_json(**self.result)
            # fail the module - exit

        api_params = dict(rgId=rg_id,
                          name=comp_name,
                          cpu=cpu, ram=ram,
                          imageId=image_id,
                          bootDisk=boot_disk,
                          start=start_on_create,  # start_machine parameter requires DECORT API ver 3.3.1 or higher
                          netType="NONE")  # we create VM without any network connections
        if userdata:
            api_params['userdata'] = json.dumps(userdata)  # we need to pass a string object as "userdata" 

        if annotation:
            api_params['decs'] = annotation

        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vm_id = int(api_resp.content)

        return ret_vm_id

    def compute_networks(self, comp_dict, new_networks):
        """Manage network configuration of Compute instance.

        @param (dict) comp_dict: dictionary, which identifies this Compute instance, formatted 
        as returned by previous call to compute_find(...).
        @param (list of dicts) new_networks: list of dictionaries with network specs, which defines
        new network configuration for the Compute. Keys in the network specification dictionary:
           (string) type - one of "VINS" or "EXTNET", to connect to either private or public
                network respectively. 
           (int) id - ID of the ViNS or external network, interpreted based on net_type value.
           (string) ip_addr - optional IP address to assign to this connection. If empty string is
                specified, the platform will assign the address automatically. 

        Note: as this method may change network configuration of the compute instance, comp_dict
        will no longer contain actual info about interfaces. It is recommended that compute
        facts are updated in the upstream code.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_networks")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("compute_networks() in check mode: network reconfig for Compute "
                                  "ID {} was requested.").format(comp_dict['id'])
            return

        # 'networks' dictionary for decort_kvmvm module has 'id' parameter, which is expected
        # to be interger.
        # However, if the value for 'id' comes via Jinja templating like this:
        #   networks:
        #      - type: VINS                    <= will come as string, which is OK.
        #        id: "{{ my_vins.facts.id }}"  <= will come as string, which is WRONG!!!
        #      - type: VINS                    <= will come as string, which is OK
        #        id: 37                        <= no Jinja templae, will come as int - OK
        #
        # then all values (including those for 'id' key) when entering this method will be of 
        # type string. We need to explicitly cast int type on all of them.

        for repair in new_networks:
            repair['id'] = int(repair['id'])

        api_params = dict(accountId=comp_dict['accountId'])
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/search", api_params)
        vins_list = json.loads(api_resp.content.decode('utf8'))
        #
        # We should not fail the module if ViNS list is empty - it is not an error, as in case of
        # API failure "decort_api_call" will abort the module execution on its own. Hence the 
        # following code fragment is commented out
        #
        # if not len(vins_list):
        #    self.result['failed'] = True
        #    self.result['msg'] = ("compute_networks() cannot obtain VINS list for Account ID {}, "
        #                        "Compute ID {}.").format(comp_dict['accountId'], comp_dict['id'])
        #    return

        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/extnet/list", api_params)
        extnet_list = json.loads(
            api_resp.content.decode('utf8'))  # list of dicts: "name" holds "NET_ADDR/NETMASK", "id" is ID
        #
        # Empty extnet_list does not constitute error condition, so we should not fail the module in 
        # this case. Therefore the following code fragment is commented out.
        #
        # if not len(extnet_list):
        #    self.result['failed'] = True
        #    self.result['msg'] = ("compute_networks() cannot obtain External networks list for Account ID {}, "
        #                        "Compute ID {}.").format(comp_dict['accountId'], comp_dict['id'])
        #    return

        # Prepare the lists of network interfaces for the compute instance:
        vins_iface_list = []  # will contain dict(id=<int>, ipAddress=<str>, mac=<str>) for ifaces connected to ViNS(es)
        enet_iface_list = []  # will contain dict(id=<int>, ipAddress=<str>, mac=<str>) for ifaces connected to Ext net(s)
        for iface in comp_dict['interfaces']:
            if iface['connType'] == 'VXLAN':
                for vrunner in vins_list:
                    if vrunner['vxlanId'] == iface['connId']:
                        iface_data = dict(id=vrunner['id'],
                                          ipAddress=iface['ipAddress'],
                                          mac=iface['mac'])
                        vins_iface_list.append(iface_data)
            elif iface['connType'] == 'VLAN':
                ip_addr = netaddr.IPAddress(iface['ipAddress'])
                for erunner in extnet_list:
                    # match by IP address range
                    # if iface['ipAddress'] <-> erunner['name']
                    # enet_iface_list.append(erunner['id'])
                    ip_extnet = netaddr.IPNetwork(erunner['ipcidr'])
                    if ip_addr.value >= ip_extnet.first and ip_addr.value <= ip_extnet.last:
                        iface_data = dict(id=erunner['id'],
                                          ipAddress=iface['ipAddress'],
                                          mac=iface['mac'])
                        enet_iface_list.append(iface_data)

        # If at this point compt_dict["interfaces"] lists some interfaces, but neither vins_iface_list
        # nor enet_iface_list contain any members, it means that none of the ViNS or Ext Nets currently 
        # available to us match existing interfaces of the Compute instance.
        # This is abnormal condition and we should not proceed any further.
        if len(comp_dict['interfaces']) and (not len(vins_iface_list) and not len(enet_iface_list)):
            self.result['failed'] = True
            self.result['msg'] = ("compute_networks() no match between {} interface(s) of Compute ID {}"
                                  "and available {} ViNS(es) or {} ExtNet(s).").format(len(comp_dict['interfaces']),
                                                                                       comp_dict['id'],
                                                                                       len(vins_list),
                                                                                       len(extnet_list))
            return

        vins_id_list = [rec['id'] for rec in vins_iface_list]

        enet_id_list = [rec['id'] for rec in enet_iface_list]

        # Build attach list by looking for ViNS/Ext net IDs that appear in new_networks, but do not appear in current lists
        attach_list = []  # attach list holds both ViNS and Ext Net attachment specs, as API handles them the same way
        for netrunner in new_networks:
            if netrunner['type'] == 'VINS' and (netrunner['id'] not in vins_id_list):
                net2attach = dict(computeId=comp_dict['id'],
                                  netType='VINS',
                                  netId=netrunner['id'],
                                  ipAddr=netrunner.get('ip_addr', ""))
                attach_list.append(net2attach)
            elif netrunner['type'] == 'EXTNET' and (netrunner['id'] not in enet_id_list):
                net2attach = dict(computeId=comp_dict['id'],
                                  netType='EXTNET',
                                  netId=netrunner['id'],
                                  ipAddr=netrunner.get('ip_addr', ""))
                attach_list.append(net2attach)

        # detach is meaningful only if compute's interfaces list was not empty
        if vins_id_list or enet_id_list:
            # Build detach list by looking for ViNS/Ext net IDs that appear in current lists, but do not appear in new_networks
            detach_list = []  # detach list holds both ViNS and Ext Net detachment specs, as API handles them the same way

            target_list = [rec['id'] for rec in new_networks if rec['type'] == 'VINS']

            for netrunner in vins_iface_list:
                if netrunner['id'] not in target_list:
                    net2detach = dict(computeId=comp_dict['id'],
                                      ipAddr=netrunner['ipAddress'],
                                      mac=netrunner['mac'])
                    detach_list.append(net2detach)

            target_list = [rec['id'] for rec in new_networks if rec['type'] == 'EXTNET']

            for netrunner in enet_iface_list:
                if netrunner['id'] not in target_list:
                    net2detach = dict(computeId=comp_dict['id'],
                                      ipAddr=netrunner['ipAddress'],
                                      mac=netrunner['mac'])
                    detach_list.append(net2detach)

            for api_params in detach_list:
                self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/netDetach", api_params)
                # On success the above call will return here. On error it will abort execution by calling fail_json.
                self.result['changed'] = True

        for api_params in attach_list:
            self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/netAttach", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['changed'] = True

        self.result['failed'] = False

        return

    def compute_resize_vector(self, comp_dict, new_cpu, new_ram):
        """Check if the Compute new size parameters passed to this function are different from the 
        current Compute configuration.
        This method is intended to be called to see if the Compute would be resized in the course 
        of module run, as sometimes resizing may happen implicitly (e.g. when state = present and 
        the specified size is different from the current configuration of per-existing target VM.

        @param (dict) comp_dict: dictionary of the Compute parameters as returned by previous call 
        to compute_find(...).
        @param (int) new_cpu: new CPU count.
        @param (int) new_ram: new RAM size in MBs.

        @return: VM_RESIZE_NOT if no change required, VM_RESIZE_DOWN if sizing down (this will 
        require Compute to be in one of the stopped states), VM_RESIZE_UP if sizing Compute up 
        (no guest OS restart is generally required for the majority of modern OS-es).
        """

        # NOTE: This method may eventually be deemed as redundant and as such may be removed.

        if comp_dict['cpus'] == new_cpu and comp_dict['ram'] == new_ram:
            return DecortController.VM_RESIZE_NOT

        if comp_dict['cpus'] < new_cpu or comp_dict['ram'] < new_ram:
            return DecortController.VM_RESIZE_UP

        if comp_dict['cpus'] > new_cpu or comp_dict['ram'] > new_ram:
            return DecortController.VM_RESIZE_DOWN

        return DecortController.VM_RESIZE_NOT

    def compute_resource_check(self):
        """Check available resources (in case limits are set on the target VDC and/or account) to make sure 
        that this Compute instance can be deployed.

        @return: True if enough resources, False otherwise.
        @return: Dictionary of remaining resources estimation after the specified Compute instance would 
        have been deployed.
        """

        # self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_resource_check")

        #
        # TODO - This method is under construction
        #

        return

    def compute_restore(self, comp_id):
        """Restores a deleted Compute instance identified by ID.

        @param compid: ID of the Compute to restore.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "compute_restore() in check mode: restore Compute ID {} was requested.".format(comp_id)
            return

        api_params = dict(computeId=comp_id,
                          reason="Restored on user {} request by Ansible DECORT module.".format(self.decort_username))
        self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def compute_resize(self, comp_dict, new_cpu, new_ram, wait_for_state_change=0):
        """Resize existing VM.

        @param (dict) comp_dict: dictionary with the facts about the Compute to resize.
        @param (int) new_cpu: new vCPU count to set.
        @param (int) ram: new RAM size in MB.
        @param (int) wait_for_state_change: integer number that tells how many 5 seconds intervals to wait 
        for the Compute instance power state to change so that the resize operation can be carried out. Set 
        this to non zero value if you expect that the state of Compute will change shortly (usually, when 
        you call this method after compute_powerstate(...))
        """

        #
        # TODO: need better cooperation from OS image attributes as returned by API "images/list".
        # Now it is assumed that VM hot resize up is always possible, while hot resize down is not.
        #

        INVALID_STATES_FOR_HOT_DOWNSIZE = ["RUNNING", "MIGRATING", "DELETED"]

        # Values that are specified via Jinja templating engine (e.g. "{{ new_ram_size }}") may come 
        # as strings. To make sure comparison of new values against current compute size is done 
        # correcly, we explicitly cast them to type int here.
        new_cpu = int(new_cpu)
        new_ram = int(new_ram)

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_resize")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("compute_resize() in check mode: resize of Compute ID {} from CPU:RAM {}:{} to {}:{} "
                                  "was requested.").format(comp_dict['id'],
                                                           comp_dict['cpus'], comp_dict['ram'],
                                                           new_cpu, new_ram)
            return

        # We need to handle a situation when either of 'cpu' or 'ram' parameter was not supplied. This is acceptable
        # when we manage state of the VM or request change to only one parameter - cpu or ram.
        # In such a case take the "missing" value from the current configuration of the VM.
        if not new_cpu and not new_ram:
            # if both are 0 or Null - return immediately, as user did not mean to manage size
            self.result['failed'] = False
            self.result['warning'] = ("compute_resize: new CPU count and RAM size are both zero for Compute ID {}"
                                      " - nothing to do.").format(comp_dict['id'])
            return

        if not new_cpu:
            new_cpu = comp_dict['cpus']
        elif not new_ram:
            new_ram = comp_dict['ram']

        # stupid hack?
        if new_ram > 1 and new_ram < 512:
            new_ram = new_ram * 1024

        if comp_dict['cpus'] == new_cpu and comp_dict['ram'] == new_ram:
            # no need to call API in this case, as requested size is not different from the current one
            self.result['failed'] = False
            self.result['warning'] = ("compute_resize: new CPU count and RAM size are the same for Compute ID {}"
                                      " - nothing to do.").format(comp_dict['id'])
            return

        if ((comp_dict['cpus'] > new_cpu or comp_dict['ram'] > new_ram) and
                comp_dict['status'] in INVALID_STATES_FOR_HOT_DOWNSIZE):
            while wait_for_state_change:
                time.sleep(5)
                fresh_comp_dict = self.compute_find(arg_vm_id=comp_dict['id'])
                comp_dict['status'] = fresh_comp_dict['status']
                if fresh_comp_dict['status'] not in INVALID_STATES_FOR_HOT_DOWNSIZE:
                    break
                wait_for_state_change = wait_for_state_change - 1
            if not wait_for_state_change:
                self.result['failed'] = True
                self.result['msg'] = ("compute_resize(): downsize of Compute ID {} from CPU:RAM {}:{} to {}:{} was "
                                      "requested, but its current state '{}' is incompatible with downsize operation."). \
                    format(comp_dict['id'],
                           comp_dict['cpus'], comp_dict['ram'],
                           new_cpu, new_ram, comp_dict['status'])
                return

        api_params = dict(computeId=comp_dict['id'],
                          ram=new_ram,
                          cpu=new_cpu, )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/resize", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        comp_dict['cpus'] = new_cpu
        comp_dict['ram'] - new_ram
        return

    def compute_wait4state(self, comp_id, pwstate, num_checks=6, sleep_time=5):
        """Helper method to wait for the Compute instance to enter the specified state. Intended 
        usage of this method is check if specified Compute is already in HALTED state after 
        calling compute_powerstate(...), as compute_powerstate() may return before Compute instance
        actually enters the target state.

        @param (int) comp_id: ID of the Compute to monitor.
        @param (string) pwstate: target powerstate of the Compute. Make sure that you specify valid 
        state, or the method will return immediately with False.
        @param num_checks: how many check attempts to take before giving up and returning False.
        @param sleep_time: sleep time in seconds between checks.

        @return: True if the target state is detected within the specified number of checks. False 
        otherwise or if an invalid target state is specified.

        Note: this method will abort module execution if no target VM is found. 
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_wait4state")

        validated_comp_id, comp_dict, _ = self.compute_find(comp_id)
        if not validated_comp_id:
            self.result['failed'] = True
            self.result['msg'] = "Cannot find the specified Compute ID {}".format(comp_id)
            self.amodule.fail_json(**self.result)

        if pwstate not in ['RUNNING', 'PAUSED', 'HALTED', 'DELETED', 'DESTROYED']:
            self.result['warning'] = "compute_wait4state: invalid target state '{}' specified.".format(pwstate)
            return False

        if comp_dict['status'] == pwstate:
            return True

        if sleep_time < 1:
            sleep_time = 1

        for _ in range(0, num_checks):
            time.sleep(sleep_time)
            _, comp_dict, _ = self.compute_find(comp_id)
            if comp_dict['status'] == pwstate:
                return True

        return False
    
    def compute_affinity(self,comp_dict,tags,aff,aaff,label=""):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "compute_affinity")

        api_params = dict(computeId=comp_dict['id'])
        self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/affinityRulesClear", api_params)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/antiAffinityRulesClear", api_params)
        if tags:
            for tag in tags:
                api_params = dict(computeId=comp_dict['id'],
                            key=tag['key'],
                            value=tag['value'], )
                self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/tagAdd", api_params)
        if label:
            api_params = dict(computeId=comp_dict['id'],
                          affinityLabel=label,)
            self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/affinityLabelSet", api_params)
        if aff:
            if len(aff)>0:
                for rule in aff:
                    api_params = dict(computeId=comp_dict['id'],
                                key=rule['key'],
                                value=rule['value'], 
                                topology=rule['topology'],
                                mode=rule['mode'],
                                policy=rule['policy'],)
                    self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/affinityRuleAdd", api_params)
        if aaff:
            if len(aaff)>0:
                for rule in aaff:
                    api_params = dict(computeId=comp_dict['id'],
                                key=rule['key'],
                                value=rule['value'], 
                                topology=rule['topology'],
                                mode=rule['mode'],
                                policy=rule['policy'],)
                    self.decort_api_call(requests.post, "/restmachine/cloudapi/compute/antiAffinityRuleAdd", api_params)     
        
        self.result['failed'] = False
        self.result['changed'] = True

    ###################################
    # OS image manipulation methods
    ###################################
    def _image_get_by_id(self, image_id):
        # TODO: update once cloudapi/image/get is implemented, see ticket #2963

        api_params = dict(imageId=image_id,
                          showAll=False)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/get", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        ret_image_dict = json.loads(api_resp.content.decode('utf8'))

        return image_id, ret_image_dict

    def image_find(self, image_id, image_name, account_id, rg_id=0, sepid=0, pool=""):
        """Locates image specified by name and returns its facts as dictionary.
        Primary use of this function is to obtain the ID of the image identified by its name and,
        optionally SEP ID and/or pool name. Also note that only images in status CREATED are
        returned.

        @param (string) image_id: ID of the OS image to find. If non-zero ID is specified, then
        image_name is ignored.
        @param (string) image_name: name of the OS image to find. This argument is ignored if non-zero
        image ID is passed.
         @param (int) account_id: ID of the account for which the image will be looked up. If set to 0,
        the account ID will be obtained from the specified RG ID.
        @param (int) rg_id: ID of the RG to use as a reference when listing OS images. This argument is
        ignored if non-zero image id and/or non-zero account_id are specified.
        @param (int) sepid: ID of the SEP where the image should be present. If set to 0, there will be no
        filtering by SEP ID and the first matching image will be returned.
        @param (string) pool: name of the pool where the image should be present. If set to empty string, there
        will be no filtering by pool name and first matching image will be returned.

        @return: image ID and dictionary with image specs. If no matching image found, 0 for ID and None for
        dictionary are returned, and self.result['failed']=True.
        """
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "image_find")

        if image_id > 0:
            ret_image_id, ret_image_dict = self._image_get_by_id(image_id)
            if (ret_image_id and
                    (sepid == 0 or sepid == ret_image_dict['sepId']) and
                    (pool == "" or pool == ret_image_dict['pool'])):
                return ret_image_id, ret_image_dict
        else:
            validated_acc_id = account_id
            if account_id == 0:
                validated_rg_id, rg_facts = self._rg_get_by_id(rg_id)
                if not validated_rg_id:
                    self.result['failed'] = True
                    self.result['msg'] = ("Failed to find RG ID {}, and account ID is zero.").format(rg_id)
                    return 0, None
                validated_acc_id = rg_facts['accountId']

            api_params = dict(accountId=validated_acc_id)
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/list", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            images_list = json.loads(api_resp.content.decode('utf8'))
            for image_record in images_list:
                if image_record['name'] == image_name and image_record['status'] == "CREATED":
                    if sepid == 0 and pool == "":
                        # if no filtering by SEP ID or pool name is requested, return the first match
                        return image_record['id'], image_record
                    # if positive SEP ID and/or non-emtpy pool name are passed, match by them
                    full_match = True
                    if sepid > 0 and sepid != image_record['sepId']:
                        full_match = False
                    if pool != "" and pool != image_record['pool']:
                        full_match = False
                    if full_match:
                        return image_record['id'], image_record
            self.result['failed'] = False

        self.result['failed'] = True
        self.result['msg'] = ("Failed to find OS image by name '{}', SEP ID {}, pool '{}' for "
                              "account ID '{}'.").format(image_name,
                                                         sepid, pool,
                                                         account_id)
        return 0, None

    def virt_image_find(self, image_id, virt_name, account_id, rg_id=0, sepid=0, pool=""):
        """Locates  virtual image specified by name and returns its facts as dictionary.
        Primary use of this function is to obtain the ID of the image identified by its name and,
        optionally SEP ID and/or pool name. Also note that only virtual images in status CREATED are
        returned.

        @param (string) image_id: ID of the OS image to find. If non-zero ID is specified, then
        virt_name is ignored.
        @param (string) virt_name: name of the OS image to find. This argument is ignored if non-zero
        image ID is passed.
         @param (int) account_id: ID of the account for which the image will be looked up. If set to 0,
        the account ID will be obtained from the specified RG ID.
        @param (int) rg_id: ID of the RG to use as a reference when listing OS images. This argument is
        ignored if non-zero image id and/or non-zero account_id are specified.
        @param (int) sepid: ID of the SEP where the image should be present. If set to 0, there will be no
        filtering by SEP ID and the first matching image will be returned.
        @param (string) pool: name of the pool where the image should be present. If set to empty string, there
        will be no filtering by pool name and first matching image will be returned.

        @return: image ID and dictionary with image specs. If no matching image found, 0 for ID and None for
        dictionary are returned, and self.result['failed']=True.
        """
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "virt_image_find")



        if image_id > 0:
            ret_image_id, ret_image_dict = self._image_get_by_id(image_id)
            if (ret_image_id and
                    (sepid == 0 or sepid == ret_image_dict['sepId']) and
                    (pool == "" or pool == ret_image_dict['pool'])):
                return ret_image_id, ret_image_dict
        else:
            validated_acc_id = account_id
            if account_id == 0:
                validated_rg_id, rg_facts = self._rg_get_by_id(rg_id)
                if not validated_rg_id:
                    self.result['failed'] = True
                    self.result['msg'] = ("Failed to find RG ID {}, and account ID is zero.").format(rg_id)
                    return 0, None
                validated_acc_id = rg_facts['accountId']

            api_params = dict(accountId=validated_acc_id)
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/list", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            images_list = json.loads(api_resp.content.decode('utf8'))
            for image_record in images_list:
                if image_record['name'] == virt_name and image_record['status'] == "CREATED" and image_record['type'] == "virtual":
                    if sepid == 0 and pool == "":
                        # if no filtering by SEP ID or pool name is requested, return the first match
                        return image_record['id'], image_record
                    full_match = True
                    if full_match:
                        return image_record['id'], image_record

        self.result['failed'] = True
        self.result['msg'] = ("Failed to find virtual OS image by name '{}', SEP ID {}, pool '{}' for "
                              "account ID '{}'.").format(virt_name,
                                                         sepid, pool,
                                                         account_id)

        return 0, None

    def virt_image_create(self, name, targetId):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "virt_image_create")

        api_params = dict(name=name, targetId=targetId,)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/createVirtual", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        virt_image_dict = json.loads(api_resp.content.decode('utf8'))

        self.result['failed'] = False
        self.result['changed'] = True
        return 0, None

    def image_delete(self, imageId, permanently):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "image_delete")

        api_params = dict(imageId=imageId, permanently=permanently,)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        image_dict = json.loads(api_resp.content.decode('utf8'))

        self.result['changed'] = True
        return 0, None


    def image_create(self,img_name,url,gid,boottype,imagetype,architecture,drivers,hotresize,username,password,account_Id,usernameDL,passwordDL,sepId,poolName):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "image_create")

        api_params = dict(name=img_name, url=url,
                            gid=gid, boottype=boottype,
                            imagetype=imagetype, architecture=architecture,
                            drivers=drivers, accountId=account_Id,
                            hotresize=hotresize, username=username,
                            password=password, usernameDL=usernameDL,
                            passwordDL=passwordDL, sepId=sepId,
                            poolName=poolName,
                            )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        virt_image_dict = json.loads(api_resp.content.decode('utf8'))
        self.result['failed'] = False
        self.result['changed'] = True
        return 0, None

    def virt_image_link(self, imageId, targetId):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "virt_image_link")

        api_params = dict(imageId=imageId, targetId=targetId,)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/link", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        link_image_dict = json.loads(api_resp.content.decode('utf8'))
        self.result['failed'] = False
        self.result['changed'] = True


        return 0, None

    def image_rename(self, imageId, name):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "image_rename")
        api_params = dict(imageId=imageId, name=name,)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/image/rename", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        link_image_dict = json.loads(api_resp.content.decode('utf8'))
        self.result['failed'] = False
        self.result['changed'] = True

    ###################################
    # Resource Group (RG) manipulation methods
    ###################################
    def rg_delete(self, rg_id, permanently):
        """Deletes specified VDC.

        @param (int) rg_id: integer value that identifies the RG to be deleted.
        @param (bool) permanently: a bool that tells if deletion should be permanent. If False, the RG will be
        marked as deleted and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes the RG can be restored by calling the corresponding 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "rg_delete() in check mode: delete RG ID {} was requested.".format(rg_id)
            return

        #
        # TODO: need decision if deleting a VDC with VMs in it is allowed (aka force=True) and implement accordingly.
        #

        api_params = dict(rgId=rg_id,
                          # force=True | False,
                          permanently=permanently, )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return

    def _rg_get_by_id(self, rg_id):
        """Helper function that locates RG by ID and returns RG facts.

        @param (int) )rg_id: ID of the RG to find and return facts for.

        @return: RG ID and a dictionary of RG facts as provided by rg/get API call. Note that if it fails
        to find the RG with the specified ID, it may return 0 for ID and empty dictionary for the facts. So
        it is suggested to check the return values accordingly.
        """
        ret_rg_id = 0
        ret_rg_dict = dict()

        if not rg_id:
            self.result['failed'] = True
            self.result['msg'] = "rg_get_by_id(): zero RG ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(rgId=rg_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/get", api_params)
        if api_resp.status_code == 200:
            ret_rg_id = rg_id
            ret_rg_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("rg_get_by_id(): failed to get RG by ID {}. HTTP code {}, "
                                      "response {}.").format(rg_id, api_resp.status_code, api_resp.reason)

        return ret_rg_id, ret_rg_dict

    def rg_access(self, arg_rg_id, arg_access):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_access")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("rg_access() in check mode: access to RG id '{}' was "
                                  "requested with '{}'.").format(arg_rg_id, arg_access)
            return 0

        api_params=dict(rgId=arg_rg_id,)
        if arg_access['action'] == "grant":
            api_params['user']=arg_access['user'],
            api_params['right']=arg_access['right'],
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/accessGrant", api_params)
        else:
            api_params['user']=arg_access['user'],
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/accessRevoke", api_params)
        self.result['changed'] = True
        return

    def rg_find(self, arg_account_id, arg_rg_id, arg_rg_name="", arg_check_state=True):
        """Returns non zero RG ID and a dictionary with RG details on success, 0 and empty dictionary otherwise.
        This method does not fail the run if RG cannot be located by its name (arg_rg_name), because this could be
        an indicator of the requested RG never existed before.
        However, it does fail the run if RG cannot be located by arg_rg_id (if non zero specified) or if API errors
        occur.

        @param (int) arg_account_id: ID of the account where to look for the RG. Set to 0 if RG is to be located by
        its ID.
        @param (int) arg_rg_id: integer ID of the RG to be found. If non-zero RG ID is passed, account ID and RG name
        are ignored. However, RG must be present in this case, as knowing its ID implies it already exists, otherwise
        method will fail.
        @param (string) arg_rg_name: string that defines the name of RG to be found. This parameter is case sensitive.
        @param (bool) arg_check_state: tells the method to report RGs in valid states only.

        @return: ID of the RG, if found. Zero otherwise.
        @return: dictionary with RG facts if RG is present. Empty dictionary otherwise. None on error.
        """

        # Resource group can be in one of the following states:
        # MODELED, CREATED, DISABLING, DISABLED, ENABLING, DELETING, DELETED, DESTROYED, DESTROYED 
        #
        # Transient state (ending with ING) are invalid from RG manipulation viewpoint 
        #

        RG_INVALID_STATES = ["MODELED"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_find")

        ret_rg_id = arg_rg_id
        api_params = dict()
        ret_rg_dict = None

        if arg_rg_id > 0:
            ret_rg_id, ret_rg_dict = self._rg_get_by_id(arg_rg_id)
            if not ret_rg_id:
                self.result['failed'] = True
                self.result['msg'] = "rg_find(): cannot find RG by ID {}.".format(arg_rg_id)
                self.amodule.fail_json(**self.result)
        elif arg_rg_name != "":
            # TODO: cloudapi/rg/list will be implemented per Ticket #2848. 
            # Until then use a three # step approach: 
            #   1) validate Account ID and obtain the account details (this may fail if user has no
            #      rights on the specified account);
            #   1) get RG list from the specified account;
            #   2) try to match RG by name.
            if arg_account_id <= 0:
                self.result['failed'] = True
                self.result['msg'] = "rg_find(): cannot find RG by name if account ID is zero or less."
                self.amodule.fail_json(**self.result)
            # try to locate RG by name - start with getting all RGs IDs within the specified account
            api_params['accountId'] = arg_account_id
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/account/listRG", api_params)
            if api_resp.status_code == 200:
                account_specs = json.loads(api_resp.content.decode('utf8'))
                api_params.pop('accountId')
                for rg_item in account_specs:
                    got_id, got_specs = self._rg_get_by_id(rg_item['id'])
                    if got_id and got_specs['name'] == arg_rg_name:
                        # name matches
                        if not arg_check_state or got_specs['status'] not in RG_INVALID_STATES:
                            ret_rg_id = got_id
                            ret_rg_dict = got_specs
                            break
            # Note: we do not fail the run if RG cannot be located by its name, because it could be a new RG
            # that never existed before. In this case ret_rg_id=0 and empty ret_rg_dict will be returned.
        else:
            # Both arg_rg_id and arg_rg_name are empty - there is no way to locate RG in this case
            self.result['failed'] = True
            self.result['msg'] = "rg_find(): either non-zero ID or a non-empty name must be specified."
            self.amodule.fail_json(**self.result)

        return ret_rg_id, ret_rg_dict

    def rg_setDefNet(self, arg_rg_id, arg_net_type, arg_net_id):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_setDefNet")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("rg_setDefNet() in check mode: setDefNet RG id '{}' was "
                                  "requested.").format(arg_rg_id)
            return 0

        if arg_net_type == "NONE":
            arg_net_type = "PRIVATE"
        api_params = dict(rgId=arg_rg_id,
                          netType=arg_net_type,
                          netId=arg_net_id,)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/setDefNet", api_params)
        self.result['changed'] = True
        return

        
    def rg_enable(self, arg_rg_id, arg_state):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_enable")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("rg_enable() in check mode: '{}' RG id '{}' was "
                                  "requested.").format(arg_state, arg_rg_id)
            return 0

        api_params = dict(rgId=arg_rg_id)

        if arg_state == "enabled":
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/enable", api_params)
        else:
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/disable", api_params)
        self.result['changed'] = True
        return

    def rg_provision(self, arg_account_id, arg_rg_name, arg_username, arg_desc, restype, arg_net_type, ipcidr, arg_extNetId, arg_extIp, arg_quota={}, location=""):
        """Provision new RG according to the specified arguments.
        If critical error occurs the embedded call to API function will abort further execution of the script
        and relay error to Ansible.
        Note that RG is created with default network set to NONE, which means that no ViNS is created along
        with the new RG.

        @param (int) arg_account_id: the non-zero ID of the account under which the new RG will be created.
        @param (string) arg_rg_name: the name of the RG to be created.
        @param (string) arg_username: the name of the user under DECORT controller, who will have primary 
        access to the newly created RG.
        @param arg_quota: dictionary that defines quotas to set on the RG to be created. Valid keys are: cpu, ram,
        disk and ext_ips.
        @param (string) location: location code, which identifies the location where RG will be created. If 
        empty string is passed, the first location under current DECORT controller will be selected.
        @param (string) arg_desc: optional text description of this resource group.

        @return: ID of the newly created RG (in check mode 0 is returned).
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("rg_provision() in check mode: provision RG name '{}' was "
                                  "requested.").format(arg_rg_name)
            return 0

        target_gid = self.gid_get(location)
        if not target_gid:
            self.result['failed'] = True
            self.result['msg'] = ("rg_provision() failed to obtain valid Grid ID for location '{}'").format(
                location)
            self.amodule.fail_json(**self.result)

        api_params = dict(accountId=arg_account_id,
                          gid=target_gid,
                          name=arg_rg_name,
                          owner=arg_username,
                          def_net=arg_net_type,
                          extNetId=arg_extNetId,
                          extIp=arg_extIp,
                          # maxMemoryCapacity=-1, maxVDiskCapacity=-1,
                          # maxCPUCapacity=-1, maxNumPublicIP=-1,
                          # maxNetworkPeerTransfer=-1,
                          )
        if arg_quota:
            if 'ram' in arg_quota:
                api_params['maxMemoryCapacity'] = arg_quota['ram']
            if 'disk' in arg_quota:
                api_params['maxVDiskCapacity'] = arg_quota['disk']
            if 'cpu' in arg_quota:
                api_params['maxCPUCapacity'] = arg_quota['cpu']
            if 'ext_ips' in arg_quota:
                api_params['maxNumPublicIP'] = arg_quota['ext_ips']
            if 'net_transfer' in arg_quota:
                api_params['maxNetworkPeerTransfer'] = arg_quota['net_transfer']

        if restype:
            api_params['resourceTypes'] = restype

        if arg_desc:
            api_params['desc'] = arg_desc
        
        api_params['def_net'] = arg_net_type
        if arg_net_type == "PRIVATE" and ipcidr !="":
            api_params['ipcidr'] = ipcidr            



        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        # API /restmachine/cloudapi/rg/create returns ID of the newly created RG on success
        self.result['failed'] = False
        self.result['changed'] = True
        ret_rg_id = int(api_resp.content.decode('utf8'))
        return ret_rg_id

    # TODO: this method will not work in its current implementation. Update it for new .../rg/update specs.

    def rg_update(self, arg_rg_dict, arg_quotas, arg_res_types, arg_newname):
        """Manage quotas for an existing RG.

        @param arg_rg_dict: dictionary with RG facts as returned by rg_find(...) method or .../rg/get API
        call to obtain the data.
        @param arg_quotas: dictionary with quota settings. Valid keys are cpu, ram, disk and ext_ips. Not all keys must
        be present. Current quota settings for the missing keys will be retained on the RG.
        """

        #
        # TODO: what happens if user requests quota downsize, and what is currently deployed turns above the new quota?
        # TODO: this method may need update since we introduced GPU functionality and corresponding GPU quota management.
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_update")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("rg_update() in check mode: setting quotas on RG ID {}, RG name '{}' was "
                                  "requested.").format(arg_rg_dict['id'], arg_rg_dict['name'])
            return

        update_required = False
        api_params = dict(rgId=arg_rg_dict['id'],)

        if arg_res_types:
            if arg_rg_dict['resourceTypes'] != arg_res_types:
                api_params['resourceTypes'] = arg_res_types
                update_required = True
            else:
                api_params['resourceTypes'] = arg_rg_dict['resourceTypes']
        
        if arg_newname != "" and arg_newname!=arg_rg_dict['name']:
            api_params['name'] = arg_newname
            update_required = True

        # One more inconsistency in API keys:
        # - when setting resource limits, the keys are in the form 'max{{ RESOURCE_NAME }}Capacity'
        # - when quering resource limits, the keys are in the form of cloud units (CU_*)
        query_key_map = dict(cpu='CU_C',
                             ram='CU_M',
                             disk='CU_D',
                             ext_ips='CU_I', 
                             net_transfer='CU_NP',)
        set_key_map = dict(cpu='maxCPUCapacity',
                           ram='maxMemoryCapacity',
                           disk='maxVDiskCapacity',
                           ext_ips='maxNumPublicIP', 
                           net_transfer='maxNetworkPeerTransfer',)

        for new_limit in ('cpu', 'ram', 'disk', 'ext_ips', 'net_transfer'):
            if arg_quotas:
                if new_limit in arg_quotas:
                    # If this resource type limit is found in the desired quotas, check if the desired setting is
                    # different from the current settings of VDC. If it is different, set the new one.
                    if arg_quotas[new_limit] != arg_rg_dict['resourceLimits'][query_key_map[new_limit]]:
                        api_params[set_key_map[new_limit]] = arg_quotas[new_limit]
                        update_required = True
                    elif arg_quotas[new_limit] == arg_rg_dict['resourceLimits'][query_key_map[new_limit]]:
                        api_params[set_key_map[new_limit]] = arg_quotas[new_limit]
                else:
                    api_params[set_key_map[new_limit]] = arg_rg_dict['resourceLimits'][query_key_map[new_limit]]
            else:
                # if quotas dictionary is None, it means that no quotas should be set - reset the limits
                api_params[set_key_map[new_limit]] = arg_rg_dict['resourceLimits'][query_key_map[new_limit]]

        if update_required:
            self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/update", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True

        return

    def rg_restore(self, arg_rg_id):
        """Restores previously deleted RG identified by its ID. For restore to succeed 
        the RG must be in 'DELETED' state.

        @param arg_rg_id: ID of the RG to restore.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "rg_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "rg_restore() in check mode: restore RG ID {} was requested.".format(arg_rg_id)
            return

        api_params = dict(rgId=arg_rg_id,
                          reason="Restored on user {} request by DECORT Ansible module.".format(self.decort_username), )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def account_find(self, account_name, account_id=0):
        """Find cloud account specified by the name and return facts about the account. Knowing account is 
        required for certain cloud resource management tasks (e.g. creating new RG).

        @param (string) account_name: name of the account to find. Pass empty string if you want to
        find account by ID and make sure you specifit posisite arg_account_id.
        @param (int) ccount_id: ID of the account to find. If arg_account_name is empty string, then
        arg_account_id must be positive, and method will look for account by the specified ID.

        Returns non zero account ID and a dictionary with account details on success, 0 and empty 
        dictionary otherwise.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "account_find")

        if account_name == "" and account_id == 0:
            self.result['failed'] = True
            self.result['msg'] = "Cannot find account if account name is empty and account ID is zero."
            self.amodule.fail_json(**self.result)

        api_params = dict()

        if account_name == "":
            api_params['accountId'] = account_id
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/account/get", api_params)
            if api_resp.status_code == 200:
                account_details = json.loads(api_resp.content.decode('utf8'))
                return account_details['id'], account_details
        else:
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/account/list", api_params)
            if api_resp.status_code == 200:
                # Parse response to see if a account matching arg_account_name is found in the output
                # If it is found, assign its ID to the return variable and copy dictionary with the facts
                accounts_list = json.loads(api_resp.content.decode('utf8'))
                for runner in accounts_list:
                    if runner['name'] == account_name:
                        # get detailed information about the account from "accounts/get" call as 
                        # "accounts/list" does not return all necessary fields
                        api_params['accountId'] = runner['id']
                        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/account/get", api_params)
                        if api_resp.status_code == 200:
                            account_details = json.loads(api_resp.content.decode('utf8'))
                            return account_details['id'], account_details

        return 0, None

    ###################################
    # GPU resource manipulation methods
    ###################################
    def gpu_attach(self, arg_vmid, arg_type, arg_mode):
        """Attach GPU of specified type and mode to the VM identidied by ID.

        @param arg_vmid: ID of the VM.
        @param arg_type: type of GPU to allocate. Valid types are: NVIDIA, AMD, INTEL or DUMMY.
        @param arg_mode: GPU mode to requues. Valid modes are: VIRTUAL or PASSTHROUGH.

        @returns: non-zero integer ID of the attached vGPU resource on success.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "gpu_attach")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("gpu_attach() in check mode: attaching GPU of type {} & mode {} to VM ID {} was "
                                  "requested.").format(arg_type, arg_mode, arg_vmid)
            return 0

        api_params = dict(
            machineId=arg_vmid,
            gpu_type=arg_type,
            gpu_mode=arg_mode,
        )

        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/machines/attachGpu", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vgpuid = int(api_resp.content)

        return ret_vgpuid

    def gpu_detach(self, arg_vmid, arg_vgpuid=-1):
        """Detach specified vGPU resource from the VM identidied by ID.

        @param arg_vmid: ID of the VM.
        @param arg_vgpuid: ID of the vGPU to detach. If -1 is specified, all vGPUs (if any) will be detached.

        @returns: True on success. On failure this method will abort playbook execution.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "gpu_detach")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("gpu_detach() in check mode: detaching GPU ID {} from VM ID {} was "
                                  "requested.").format(arg_vgpuid, arg_vmid)
            return True

        api_params = dict(
            machineId=arg_vmid,
            vgpuid=arg_vgpuid,
        )

        self.decort_api_call(requests.post, "/restmachine/cloudapi/machines/detachGpu", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return True

    def gpu_list(self, arg_vmid, arg_list_destroyed=False):
        """Lists GPU resrouces (if any) attached to the specified VM.

        @param arg_vmid: ID of the VM.
        @param arg_list_destroyed: flag to control listing of vGPU resources in DESTROYED state that were once 
        attached to this VM.

        @returns: list of GPU object dictionaries, currently attached to the specified VM. If there are no GPUs, 
        an emtpy list will be returned.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "gpu_list")

        api_params = dict(
            machineId=arg_vmid,
            list_destroyed=arg_list_destroyed,
        )

        ret_gpu_list = []

        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/machines/listGpu", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        if api_resp.status_code == 200:
            ret_gpu_list = json.loads(api_resp.content.decode('utf8'))

        return ret_gpu_list

    ###################################
    # Workflow callback stub methods - not fully implemented yet
    ###################################
    def workflow_cb_set(self, arg_workflow_callback, arg_workflow_context=None):
        """Set workflow callback and workflow context value.
        """

        self.workflow_callback = arg_workflow_callback
        if arg_workflow_callback != "":
            self.workflow_callback_present = True
        else:
            self.workflow_callback_present = False

        if arg_workflow_context != "":
            self.workflow_context = arg_workflow_context
        else:
            self.workflow_context = ""

        return

    def workflow_cb_call(self):
        """Invoke workflow callback if it was specified earlyer with workflow_cb_set(...) method.
        """
        #
        # TODO: under construction
        #
        if self.workflow_callback_present:
            pass
        return

    def run_phase_set(self, arg_phase_name):
        """Set run phase name for module run progress reporting"""
        self.run_phase = arg_phase_name
        return

    def gid_get(self, location_code=""):
        """Get Grid ID for the specified location code.

        @param (string) location_code: location code for the Grid ID. If empty string is passed,
        the first Grid ID found will be returned.

        @returns: integer Grid ID corresponding to the specified location. If no Grid matches specified
        location, 0 is returned.
        """

        ret_gid = 0
        api_params = dict()
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/locations/list", api_params)

        

        if api_resp.status_code == 200:
            locations = json.loads(api_resp.content.decode('utf8'))
            if location_code == "" and locations:
                ret_gid = locations[0]['gid']
            else:
                for runner in locations:
                    if runner['locationCode'] == location_code:
                        # location code matches
                        ret_gid = runner['gid']
                        break

        return ret_gid

    ##############################
    #
    # ViNS management
    #
    ##############################
    def vins_delete(self, vins_id, permanently=False):
        """Deletes specified ViNS.

        @param (int) vins_id: integer value that identifies the ViNS to be deleted.
        @param (bool) arg_permanently: a bool that tells if deletion should be permanent. If False, the ViNS will be
        marked as DELETED and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes this ViNS can be restored by calling the corresponding 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "vins_delete() in check mode: delete ViNS ID {} was requested.".format(vins_id)
            return

        #
        # TODO: need decision if deleting a VINS with connected computes is allowed (aka force=True)
        # and implement this decision accordingly.
        #

        api_params = dict(vinsId=vins_id,
                          # force=True | False,
                          permanently=permanently, )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def _vins_get_by_id(self, vins_id):
        """Helper function that locates ViNS by ID and returns ViNS facts. This function
        expects that the ViNS exists (albeit in DELETED or DESTROYED state) and will return
        0 ViNS ID if not found.

        @param (int) vins_id: ID of the ViNS to find and return facts for.

        @return: ViNS ID and a dictionary of ViNS facts as provided by vins/get API call. 
        
        Note that if it fails to find the ViNS with the specified ID, it may return 0 for ID 
        and empty dictionary for the facts. So it is suggested to check the return values 
        accordingly in the upstream code.
        """
        ret_vins_id = 0
        ret_vins_dict = dict()

        if not vins_id:
            self.result['failed'] = True
            self.result['msg'] = "vins_get_by_id(): zero ViNS ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(vinsId=vins_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/get", api_params)
        if api_resp.status_code == 200:
            ret_vins_id = vins_id
            ret_vins_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("vins_get_by_id(): failed to get VINS by ID {}. HTTP code {}, "
                                      "response {}.").format(vins_id, api_resp.status_code, api_resp.reason)

        return ret_vins_id, ret_vins_dict
    def _rg_listvins(self,rg_id):
        """List all ViNS in the resource group
            @param (int) rg_id: id onr resource group
        """
        if not rg_id:
            self.result['failed'] = True
            self.result['msg'] = "_rg_listvins(): zero RG ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(rgId=rg_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/listVins", api_params)
        if api_resp.status_code == 200:
            ret_rg_vins_list = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("rg_listvins(): failed to get RG by ID {}. HTTP code {}, "
                                      "response {}.").format(rg_id, api_resp.status_code, api_resp.reason)
            return []

        return ret_rg_vins_list
    
    def vins_find(self, vins_id, vins_name="", account_id=0, rg_id=0, rg_facts="", check_state=True):
        """Find specified ViNS. 
       
        @param (int) vins_id: ID of the ViNS. If non-zero vins_id is specified, all other arguments 
        are ignored, ViNS must exist and is located by its ID only. 
        @param (string) vins_name: If vins_id is 0, then vins_name is mandatory. Further search for 
        ViNS is based on combination of account_id and rg_id. If account_id is non-zero, then rg_id 
        is ignored and ViNS is supposed to exist at account level. 
        @param (int) account_id: set to non-zero value to search for ViNS by name at this account level.
        @param (int) rg_id: set to non-zero value to search for ViNS by name at this RG level. Note, that
        in this case account_id should be set to 0.
        @param (bool) check_state: tells the method to report ViNSes in valid states only. Set check_state 
        to False if you want to check if specified ViNS exists at all without failing the module execution. 

        @returns: ViNS ID and dictionary with ViNS facts. It may return zero ID and empty dictionary
        if no ViNS found and check_state=False, so make sure to check return values in the upstream
        code accordingly.
        """

        # transient and deleted/destroyed states are deemed invalid
        VINS_INVALID_STATES = ["ENABLING", "DISABLING", "DELETING", "DELETED", "DESTROYING", "DESTROYED"]

        ret_vins_id = 0
        # api_params = dict()
        ret_vins_facts = None

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_find")

        if vins_id > 0:
            ret_vins_id, ret_vins_facts = self._vins_get_by_id(vins_id)
            if not ret_vins_id:
                self.result['failed'] = True
                self.result['msg'] = "vins_find(): cannot find ViNS by ID {}.".format(vins_id)
                self.amodule.fail_json(**self.result)
            if not check_state or ret_vins_facts['status'] not in VINS_INVALID_STATES:
                return ret_vins_id, ret_vins_facts
            else:
                return 0, None
        elif vins_name != "":
            if rg_id > 0:
                # search for ViNS at RG level
                # validated_id, validated_facts = self._rg_get_by_id(rg_id)
                # if not validated_id:
                #     self.result['failed'] = True
                #     self.result['msg'] = "vins_find(): cannot find RG ID {}.".format(rg_id)
                #     self.amodule.fail_json(**self.result)
                # # NOTE: RG's 'vins' attribute does not list destroyed ViNSes! 
                list_vins = self._rg_listvins(rg_id)
                for vins in list_vins:
                    if vins['name'] == vins_name:
                        ret_vins_id, ret_vins_facts = self._vins_get_by_id(vins['id'])
                        if not check_state or ret_vins_facts['status'] not in VINS_INVALID_STATES:
                            return ret_vins_id, ret_vins_facts
                        else:
                            return 0, None
            elif account_id > 0:
                # search for ViNS at account level
                # validated_id, validated_facts = self.account_find("", account_id)
                # if not validated_id:
                #     self.result['failed'] = True
                #     self.result['msg'] = "vins_find(): cannot find Account ID {}.".format(account_id)
                #     self.amodule.fail_json(**self.result)
                # NOTE: account's 'vins' attribute does not list destroyed ViNSes! 
                for runner in rg_facts['vins']:
                    # api_params['vinsId'] = runner
                    ret_vins_id, ret_vins_facts = self._vins_get_by_id(runner)
                    if ret_vins_id and ret_vins_facts['name'] == vins_name:
                        if not check_state or ret_vins_facts['status'] not in VINS_INVALID_STATES:
                            return ret_vins_id, ret_vins_facts
                        else:
                            return 0, None
            else:  # both Account ID and RG ID are zero - fail the module
                self.result['failed'] = True
                self.result['msg'] = ("vins_find(): cannot find ViNS by name '{}' "
                                      "when no account ID or RG ID is specified.").format(vins_name)
                self.amodule.fail_json(**self.result)
        else:  # ViNS ID is 0 and ViNS name is emtpy - fail the module
            self.result['failed'] = True
            self.result['msg'] = "vins_find(): cannot find ViNS by zero ID and empty name."
            self.amodule.fail_json(**self.result)

        return 0, None

    def vins_provision(self, vins_name, account_id, rg_id=0, ipcidr="", ext_net_id=-1, ext_ip_addr="", desc=""):
        """Provision ViNS according to the specified arguments.
        If critical error occurs the embedded call to API function will abort further execution of 
        the script and relay error to Ansible.
        Note, that when creating ViNS at account level, default location under DECORT controller 
        will be selected automatically.

        @param (int) account_id: ID of the account where ViNS will be created. To create ViNS at account 
        level specify non-zero account ID and zero RG ID.
        @param (string) rg_id: ID of the RG where ViNS will be created. If non-zero RG ID is specified, 
        ViNS will be created at this RG level.
        @param (string) ipcidr: optional IP network address to use for internal ViNS network.
        @param (int) ext_net_id: optional ID of the external network to connect this ViNS to. Specify -1
        to created isolated ViNS, 0 to let platform select default external network, or ID of the network
        to ust. Note: this parameter is ignored for ViNS created at account level.
        @param (string) ext_ip_addr: optional IP address of the external network connection for this ViNS. If
        emtpy string is passed when ext_net_id >= 0, the platform will assign IP address automatically. If
        explicitly specified IP address is invalid or already occupied, the method will fail. Note: this 
        parameter is ignored for ViNS created at account level.
        @param (string) desc: optional text description of this ViNS. 

        @return: ID of the newly created ViNS (in Ansible check mode 0 is returned).
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_provision() in check mode: provision ViNS name '{}' was "
                                  "requested.").format(vins_name)
            return 0

        if vins_name == "":
            self.result['failed'] = True
            self.result['msg'] = "vins_provision(): ViNS name cannot be empty."
            self.amodule.fail_json(**self.result)

        api_url = ""
        api_params = None
        if account_id and not rg_id:
            api_url = "/restmachine/cloudapi/vins/createInAccount"
            target_gid = self.gid_get("")
            if not target_gid:
                self.result['failed'] = True
                self.result['msg'] = "vins_provision() failed to obtain Grid ID for default location."
                self.amodule.fail_json(**self.result)
            api_params = dict(
                name=vins_name,
                accountId=account_id,
                gid=target_gid,
            )
        elif rg_id:
            api_url = "/restmachine/cloudapi/vins/createInRG"
            api_params = dict(
                name=vins_name,
                rgId=rg_id,
                extNetId=ext_net_id,
            )
            if ext_ip_addr:
                api_params['extIp'] = ext_ip_addr
        else:
            self.result['failed'] = True
            self.result['msg'] = "vins_provision(): either account ID or RG ID must be specified."
            self.amodule.fail_json(**self.result)

        if ipcidr != "":
            api_params['ipcidr'] = ipcidr
            api_params['desc'] = desc

        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        # API /restmachine/cloudapi/vins/create*** returns ID of the newly created ViNS on success
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vins_id = int(api_resp.content.decode('utf8'))
        return ret_vins_id

    def vins_restore(self, vins_id):
        """Restores previously deleted ViNS identified by its ID. For restore to succeed 
        the ViNS must be in 'DELETED' state.

        @param vins_id: ID of the ViNS to restore.

        @returns: nothing on success. On error this method will abort module execution.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "vins_restore() in check mode: restore ViNS ID {} was requested.".format(vins_id)
            return

        api_params = dict(vinsId=vins_id,
                          reason="Restored on user {} request by DECORT Ansible module.".format(self.decort_username), )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vins_state(self, vins_dict, desired_state):
        """Enable or disable ViNS.

        @param vins_dict: dictionary with the target ViNS facts as returned by vins_find(...) method or
        .../vins/get API call.
        @param desired_state: the desired state for this ViNS. Valid states are 'enabled' and 'disabled'.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_state")

        NOP_STATES_FOR_VINS_CHANGE = ["MODELED", "DISABLING", "ENABLING", "DELETING", "DELETED", "DESTROYING",
                                      "DESTROYED"]
        VALID_TARGET_STATES = ["enabled", "disabled"]

        if vins_dict['status'] in NOP_STATES_FOR_VINS_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("vins_state(): no state change possible for ViNS ID {} "
                                  "in its current state '{}'.").format(vins_dict['id'], vins_dict['status'])
            return

        if desired_state not in VALID_TARGET_STATES:
            self.result['failed'] = False
            self.result['warning'] = ("vins_state(): unrecognized desired state '{}' requested "
                                      "for ViNS ID {}. No ViNS state change will be done.").format(desired_state,
                                                                                                   vins_dict['id'])
            return

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_state() in check mode: setting state of ViNS ID {}, name '{}' to "
                                  "'{}' was requested.").format(vins_dict['id'], vins_dict['name'],
                                                                desired_state)
            return

        vinsstate_api = ""  # this string will also be used as a flag to indicate that API call is necessary
        api_params = dict(vinsId=vins_dict['id'],
                          reason='Changed by DECORT Ansible module, vins_state method.')
        expected_state = ""

        if vins_dict['status'] in ["CREATED", "ENABLED"] and desired_state == 'disabled':
            vinsstate_api = "/restmachine/cloudapi/vins/disable"
            expected_state = "DISABLED"
        elif vins_dict['status'] == "DISABLED" and desired_state == 'enabled':
            vinsstate_api = "/restmachine/cloudapi/vins/enable"
            expected_state = "ENABLED"

        if vinsstate_api != "":
            self.decort_api_call(requests.post, vinsstate_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            vins_dict['status'] = expected_state
        else:
            self.result['failed'] = False
            self.result['msg'] = ("vins_state(): no state change required for ViNS ID {} from current "
                                  "state '{}' to desired state '{}'.").format(vins_dict['id'],
                                                                              vins_dict['status'],
                                                                              desired_state)
        return

    def vins_update_extnet(self, vins_dict, ext_net_id, ext_ip_addr=""):
        """Update ViNS. Currently only updates to the external network connection settings and
        external IP address assignment are implemented.
        Note that as ViNS created at account level cannot have external connections, attempt 
        to update such ViNS will have no effect.

        @param (dict) vins_dict: dictionary with target ViNS details as returned by vins_find() method.
        @param (int) ext_net_id: sets ViNS network connection status. Pass -1 to disconnect ViNS from 
        external network or positive network ID to connect to the specified external network.
        @param (string) ext_ip_addr: optional IP address to assign to the external network connection 
        of this ViNS.

        Note: on success vins_dict may no longer contain actual info about this ViNS, so it is
        recommended to update ViNS facts in the upstream code.
        """

        api_params = dict(vinsId=vins_dict['id'], )

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_update")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_update_extnet() in check mode: updating ViNS ID {}, name '{}' "
                                  "was requested.").format(vins_dict['id'], vins_dict['name'])
            return

        if not vins_dict['rgId']:
            # this ViNS exists at account level - no updates are possible
            self.result['warning'] = ("vins_update(): no update is possible for ViNS ID {} "
                                      "as it exists at account level.").format(vins_dict['id'])
            return

        gw_config = None
        if vins_dict['vnfs'].get('GW'):
            gw_config = vins_dict['vnfs']['GW']['config']

        if ext_net_id < 0:
            # Request to have ViNS disconnected from external network
            if gw_config:
                # ViNS is connected to external network indeed - call API to disconnect; otherwise - nothing to do
                self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/extNetDisconnect", api_params)
                self.result['failed'] = False
                self.result['changed'] = True
                # On success the above call will return here. On error it will abort execution by calling fail_json.
        elif ext_net_id > 0:
            if gw_config:
                # Request to have ViNS connected to the specified external network
                # First check that if we are not connected to the same network already; otherwise - nothing to do
                if gw_config['ext_net_id'] != ext_net_id:
                    # disconnect from current, we already have vinsId in the api_params
                    self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/extNetDisconnect", api_params)
                    self.result['changed'] = True
                    # connect to the new
                    api_params['netId'] = ext_net_id
                    api_params['ip'] = ext_ip_addr
                    self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/extNetConnect", api_params)
                    self.result['failed'] = False
                    # On success the above call will return here. On error it will abort execution by calling fail_json.
                else:
                    self.result['failed'] = False
                    self.result['warning'] = ("vins_update(): ViNS ID {} is already connected to ext net ID {}, "
                                              "ignore ext IP address change if any.").format(vins_dict['id'],
                                                                                             ext_net_id)
        else:  # ext_net_id = 0, i.e. connect ViNS to default network
            # we will connect ViNS to default network only if it is NOT connected to any ext network yet
            if not gw_config:
                api_params['netId'] = 0
                self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/extNetConnect", api_params)
                self.result['changed'] = True
                self.result['failed'] = False
            else:
                self.result['failed'] = False
                self.result['warning'] = ("vins_update(): ViNS ID {} is already connected to ext net ID {}, "
                                          "no reconnection to default network will be done.").format(vins_dict['id'],
                                                                                                     gw_config[
                                                                                                         'ext_net_id']) 
        return
    def vins_update_mgmt(self, vins_dict, mgmtaddr=[]):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_update_mgmt")
        
        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_update_mgmt() in check mode: updating ViNS ID {}, name '{}' "
                                  "was requested.").format(vins_dict['id'], vins_dict['name'])
            return

        if self.amodule.params['config_save'] and vins_dict['VNFDev']['customPrecfg']:
            # only save config,no other modifictaion
            self.result['changed'] = True
            self._vins_vnf_config_save(vins_dict['VNFDev']['id'])
            self.result['changed'] = True
            self.result['failed'] = False
            return
        
        for iface in vins_dict['VNFDev']['interfaces']:
            if iface['ipAddress'] in mgmtaddr and not iface['listenSsh']:
                self._vins_vnf_addmgmtaddr(vins_dict['VNFDev']['id'],iface['ipAddress'])
                self.result['changed'] = True
                self.result['failed'] = False
            elif iface['ipAddress'] not in mgmtaddr and iface['listenSsh']:
                if iface['name'] != "ens9":
                    self._vins_vnf_delmgmtaddr(vins_dict['VNFDev']['id'],iface['ipAddress'])
                    self.result['changed'] = True
                    self.result['failed'] = False
        if self.amodule.params['custom_config']:
            if not vins_dict['VNFDev']['customPrecfg']:
                self._vins_vnf_config_save(vins_dict['VNFDev']['id'])
                self._vins_vnf_customconfig_set(vins_dict['VNFDev']['id'])
                self.result['changed'] = True
                self.result['failed'] = False
        else: 
            if vins_dict['VNFDev']['customPrecfg']:
                self._vins_vnf_customconfig_set(vins_dict['VNFDev']['id'],False)
                self.result['changed'] = True
                self.result['failed'] = False
        return
    
    def vins_update_ifaces(self,vins_dict,vinses=""):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vins_update_ifaces")
        
        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_update_iface() in check mode: updating ViNS ID {}, name '{}' "
                                  "was requested.").format(vins_dict['id'], vins_dict['name'])
            return
        
        list_ifaces_ip = [rec['ipaddr'] for rec in vinses]   
        vinsid_not_existed = []
        for iface in vins_dict['VNFDev']['interfaces']:
            if iface['connType'] == "VXLAN" and iface['type'] == "CUSTOM":
                if iface['ipAddress'] not in list_ifaces_ip:
                    self._vnf_iface_remove(vins_dict['VNFDev']['id'],iface['name'])
                    self.result['changed'] = True
                    self.result['failed'] = False
                else:
                    #existed_conn_ip.append(iface['ipAddress'])
                    vinses = list(filter(lambda i: i['ipaddr']!=iface['ipAddress'],vinses))

        if not vinses:
            return
        list_account_vins = self._get_all_account_vinses(vins_dict['VNFDev']['accountId'])
        list_account_vinsid = [rec['id'] for rec in list_account_vins]
        for vins in vinses:
            if vins['id'] in list_account_vinsid:
                _,v_dict = self._vins_get_by_id(vins['id'])
                    #TODO: vins reservation
                self._vnf_iface_add(vins_dict['VNFDev']['id'],v_dict['vxlanId'],vins['ipaddr'],vins['netmask'])
                self.result['changed'] = True
                self.result['failed'] = False
            else:
                vinsid_not_existed.append(vins['id'])
        if vinsid_not_existed:   
            self.result['warning'] = ("List ViNS id: {} that not created on account id: {}").format(
                                    vinsid_not_existed,
                                    vins_dict['VNFDev']['accountId']
                                    )
        return

    def _vnf_iface_add(self,arg_devid,arg_vxlanid,arg_ipaddr,arg_netmask="24",arg_defgw=""):
        api_params = dict(
            devId=arg_devid,
            ifType="CUSTOM",
            connType="VXLAN",
            connId=arg_vxlanid,
            ipAddr=arg_ipaddr,
            netMask=arg_netmask,
            defGw=arg_defgw
        )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/ifaceAdd", api_params)
        conn_dict = json.loads(api_resp.content.decode('utf8'))
        return 

    def _vnf_iface_remove(self,arg_devid,arg_iface_name):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "_vnf_iface_add")
        api_params = dict(
            devId=arg_devid,
            name=arg_iface_name,

        )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/ifaceRemove", api_params)
        return 

    def _get_vnf_by_id(self,vnf_id):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "get_vnf_by_id")
        api_params = dict(devId=vnf_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/get", api_params)
        if api_resp.status_code == 200:
            ret_vnf_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("get_all_account_vinses(): failed to configuration of the specified VNF device ID{}. HTTP code {}, "
                                      "response {}.").format(vnf_id, api_resp.status_code, api_resp.reason)
        return ret_vnf_dict

    def _get_all_account_vinses(self,acc_id):
        api_params = dict(accountId=acc_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/account/listVins", api_params)
        if api_resp.status_code == 200:
            ret_listvins_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("get_all_account_vinses(): failed to get list VINS in Account ID {}. HTTP code {}, "
                                      "response {}.").format(acc_id, api_resp.status_code, api_resp.reason)
        return ret_listvins_dict

    def _vins_vnf_addmgmtaddr(self,dev_id,mgmtip):
        api_params = dict(devId=dev_id,ip=mgmtip)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/addMgmtAddr", api_params)
        if api_resp.status_code == 200:
            self.result['changed'] = True
            self.result['failed'] = False
        else:
            self.result['warning'] = ("_vins_vnf_addmgmtaddr(): failed to add MGMT addr VNFID {} iface ADDR {}. HTTP code {}, "
                                      "response {}.").format(dev_id,mgmtip,api_resp.status_code, api_resp.reason)
        return
    
    def _vins_vnf_delmgmtaddr(self,dev_id,mgmtip):
        api_params = dict(devId=dev_id,ip=mgmtip)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/delMgmtAddr", api_params)
        if api_resp.status_code == 200:
            self.result['changed'] = True
            self.result['failed'] = False
        else:
            self.result['warning'] = ("_vins_vnf_delmgmtaddr(): failed to delete MGMT addr VNFID {} iface ADDR {}. HTTP code {}, "
                                      "response {}.").format(dev_id,mgmtip,api_resp.status_code, api_resp.reason)
        return

    def _vins_vnf_customconfig_set(self,dev_id,arg_mode=True):
        api_params = dict(devId=dev_id,mode=arg_mode)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/customSet", api_params)
        if api_resp.status_code == 200:
            self.result['changed'] = True
            self.result['failed'] = False
        else:
            self.result['warning'] = ("_vins_vnf_customconfig_set(): failed to enable or disable Custom pre-config mode on the VNF device. {}. HTTP code {}, "
                                      "response {}.").format(dev_id,api_resp.status_code, api_resp.reason)
        return
    
    def _vins_vnf_config_save(self,dev_id):
        api_params = dict(devId=dev_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudbroker/vnfdev/configSave", api_params)
        if api_resp.status_code == 200:
            self.result['changed'] = True
            self.result['failed'] = False
        else:
            self.result['warning'] = ("_vins_vnf_config_set(): failed to Save configuration on the VNF device. {}. HTTP code {}, "
                                      "response {}.").format(dev_id,api_resp.status_code, api_resp.reason)
        return

    ##############################
    #
    # Disk management
    #
    ##############################

    def disk_delete(self, disk_id, permanently, detach, reason):
        """Deletes specified Disk.

        @param (int) disk_id: ID of the Disk to be deleted.
        @param (bool) arg_permanently: a bool that tells if deletion should be permanent. If False, the Disk will be
        marked as DELETED and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes such a Disk can be restored by calling the corresponding 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "disk_delete() in check mode: delete Disk ID {} was requested.".format(disk_id)
            return

        api_params = dict(diskId=disk_id,
                          detach=detach,
                          permanently=permanently,
                          reason=reason)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def _disk_get_by_id(self, disk_id):
        """Helper function that locates Disk by ID and returns Disk facts. This function
        expects that the Disk exists (albeit in DELETED or DESTROYED or PURGED state) and 
        will return zero ID if Disk is not found.

        @param (int) disk_id: ID of the disk to find and return facts for.

        @return: Disk ID and a dictionary of disk facts as provided by disks/get API call. 
        
        Note that if it fails to find the Disk with the specified ID, it may return 0 for ID 
        and empty dictionary for the facts. So it is suggested to check the return values 
        accordingly in the upstream code.
        """
        ret_disk_id = 0
        ret_disk_dict = dict()

        if not disk_id:
            self.result['failed'] = True
            self.result['msg'] = "disk_get_by_id(): zero Disk ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(diskId=disk_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/get", api_params)
        if api_resp.status_code == 200:
            ret_disk_id = disk_id
            ret_disk_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("disk_get_by_id(): failed to get Disk by ID {}. HTTP code {}, "
                                      "response {}.").format(disk_id, api_resp.status_code, api_resp.reason)

        return ret_disk_id, ret_disk_dict

    def disk_find(self, disk_id, name, account_id, check_state=False):
        """Find specified Disk. 
       
        @param (int) disk_id: ID of the Disk. If non-zero disk_id is specified, all other arguments 
        are ignored, Disk must exist and is located by its ID only. 
        @param (string) disk_name: If disk_id is 0, then disk_name is mandatory, and the disk is looked
        up in the specified account. 
        @param (int) account_id: id of the account that owns this disk. Ignored if non-zero disk_id is
        specified, but becomes mandatory otherwise. 
        @param (bool) check_state: tells the method to report Disk(s) in valid states only. Set check_state 
        to False if you want to check if specified Disk exists at all without failing the module execution. 

        @returns: Disk ID and dictionary with Disk facts. It may return zero ID and empty dictionary
        if no Disk found and check_state=False, so make sure to check return values in the upstream
        code accordingly.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_find")

        DISK_INVALID_STATES = ["MODELED", "CREATING", "DELETING", "DESTROYING"]

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "disk_find() in check mode: find Disk ID {} / name '{}' was requested.".format(disk_id,
                                                                                                                disk_name)
            return

        ret_disk_id = 0
        ret_disk_facts = None

        if disk_id > 0:
            ret_disk_id, ret_disk_facts = self._disk_get_by_id(disk_id)
            if not ret_disk_id:
                self.result['failed'] = True
                self.result['msg'] = "disk_find(): cannot find Disk by ID {}.".format(disk_id)
                self.amodule.fail_json(**self.result)
            if not check_state or ret_disk_facts['status']:
                return ret_disk_id, ret_disk_facts
            else:
                return 0, None
        elif name != "":
            if account_id > 0:
                api_params = dict(accountId=account_id)
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/list", api_params)
                # the above call may return more than one matching disk
                disks_list = json.loads(api_resp.content.decode('utf8'))
                for runner in disks_list:
                    # return the first disk of the specified name that fulfills status matching rule
                    if runner['name'] == name:
                        if not check_state or runner['status']:
                            return runner['id'], runner
                else:
                    return 0, None
            else:  # we are missing meaningful account_id - fail the module
                self.result['failed'] = True
                self.result['msg'] = ("disk_find(): cannot find Disk by name '{}' "
                                      "when no account ID specified.").format(name)
                self.amodule.fail_json(**self.result)
        else:  # Disk ID is 0 and Disk name is emtpy - fail the module
            self.result['failed'] = True
            self.result['msg'] = "disk_find(): cannot find Disk by zero ID and empty name."
            self.amodule.fail_json(**self.result)

        return 0, None

    def disk_create(self, accountId, gid, name, description, size, type, iops, sep_id, pool):
        """Provision Disk according to the specified arguments.
        Note that disks created by this method will be of type 'D' (data disks).
        If critical error occurs the embedded call to API function will abort further execution 
        of the script and relay error to Ansible.

        @param (string) name: name to assign to the Disk.
        @param (int) size: size of the disk in GB.
        @param (int) accountId: ID of the account where disk will belong.
        @param (int) sep_id: ID of the SEP (Storage Endpoint Provider), where disk will be created.
        @param (string) pool: optional name of the pool, where this disk will be created.
        @param (string) description: optional text description of this disk. 
        @param (int) gid: optional Grid id, if specified the disk will be created in selected
        location.

        @return: ID of the newly created Disk (in Ansible check mode 0 is returned).
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_creation")
        api_params = dict(accountId=accountId,
                          gid=gid,
                          name=name,
                          description=description,
                          size=size,
                          type=type,
                          iops=iops,
                          sepId=sep_id,
                          pool=pool )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/create", api_params)
        if api_resp.status_code == 200:
            ret_disk_id = json.loads(api_resp.content.decode('utf8'))

        self.result['failed'] = False
        self.result['changed'] = True
        return ret_disk_id

    def disk_resize(self, disk_facts, new_size):
        """Resize Disk. Only increasing disk size is allowed.

        @param (dict) disk_dict: dictionary with target Disk details as returned by ../disks/get
        API call or disk_find() method.
        @param (int) new_size: new size of the disk in GB. It must be greater than current disk 
        size for the method to succeed.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_resize")

        # Values that are specified via Jinja templating engine (e.g. "{{ new_size }}") may come 
        # as strings. To make sure comparison of new values against current compute size is done 
        # correcly, we explicitly cast them to type int here.
        new_size = int(new_size)

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("disk_resize() in check mode: resize Disk ID {} "
                                  "to {} GB was requested.").format(disk_facts['id'], new_size)
            return

        if not new_size:
            self.result['failed'] = False
            self.result['warning'] = "disk_resize(): zero size requested for Disk ID {} - ignoring.".format(
                disk_facts['id'])
            return

        if new_size < disk_facts['sizeMax']:
            self.result['failed'] = True
            self.result['msg'] = ("disk_resize(): downsizing Disk ID {} is not allowed - current "
                                  "size {}, requeste size {}.").format(disk_facts['id'],
                                                                       disk_facts['sizeMax'], new_size)
            return

        if new_size == disk_facts['sizeMax']:
            self.result['failed'] = False
            self.result['warning'] = ("disk_resize(): nothing to do for Disk ID {} - new size is the "
                                      "same as current.").format(disk_facts['id'])
            return

        api_params = dict(diskId=disk_facts['id'], size=new_size)
        # NOTE: we are using API "resize2", as in this module we are managing 
        # disks attached to compute(s) (DSF ver.2 only)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/resize2", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        disk_facts['sizeMax'] = new_size

        return

    def disk_limitIO(self, limits, diskId):
        """Limits already created Disk identified by its ID. 
        @param (dict) limits: Dictionary with limits.
        @param (int) diskId: ID of the Disk to limit.
        @returns: nothing on success. On error this method will abort module execution.
        """        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_limitIO")
        api_params = dict(diskId=diskId,
                          total_bytes_sec=limits['total_bytes_sec'],
                          read_bytes_sec=limits['read_bytes_sec'],
                          write_bytes_sec=limits['write_bytes_sec'],
                          total_iops_sec=limits['total_iops_sec'],
                          read_iops_sec=limits['read_iops_sec'],
                          write_iops_sec=limits['write_iops_sec'],
                          total_bytes_sec_max=limits['total_bytes_sec_max'],
                          read_bytes_sec_max=limits['read_bytes_sec_max'],
                          write_bytes_sec_max=limits['write_bytes_sec_max'],
                          total_iops_sec_max=limits['total_iops_sec_max'],
                          read_iops_sec_max=limits['read_iops_sec_max'],
                          write_iops_sec_max=limits['write_iops_sec_max'],
                          size_iops_sec=limits['size_iops_sec'])
        self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/limitIO", api_params)
        self.result['msg'] = "Specified Disk ID {} limited successfully.".format(self.validated_disk_id)
        return
    
    def disk_rename(self, diskId, name):
        """Renames disk to the specified new name.

        @param disk_id: ID of the Disk to rename.
        @param name: New name.

        @returns: nothing on success. On error this method will abort module execution.
        """
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_rename")
        api_params = dict(diskId=diskId,
                          name=name)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/rename", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def disk_restore(self, disk_id):
        """Restores previously deleted Disk identified by its ID. For restore to succeed 
        the Disk must be in 'DELETED' state.

        @param disk_id: ID of the Disk to restore.

        @returns: nothing on success. On error this method will abort module execution.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "disk_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "disk_restore() in check mode: restore Disk ID {} was requested.".format(disk_id)
            return

        api_params = dict(diskId=disk_id,
                          reason="Restored on user {} request by DECORT Ansible module.".format(self.decort_username), )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/disks/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    ##############################
    #
    # Port Forward rules management
    #
    ##############################

    def _pfw_get(self, comp_id, vins_id):
        """Convenience method to get current PFW rules for the specified compute ID.
        """
        api_params = dict(vinsId=vins_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/natRuleList", api_params)
        all_rules = json.loads(api_resp.content.decode('utf8'))

        if comp_id == 0:
            # no filtering by compute ID, return rules as is
            return all_rules

        filtered_rules = []
        for runner in all_rules:
            if runner['vmId'] == comp_id:
                filtered_rules.append(runner)

        return filtered_rules

    def pfw_configure(self, comp_facts, vins_facts, new_rules=None):
        """Manage port forwarding rules for Compute in a smart way. The method will try to match existing
        rules against the new rules set and calculate the delta settings to apply to the corresponding 
        virtual network function.

        @param (dict) comp_facts: dictionary with Compute facts as returned by .../compute/get. It describes
        the Compute instance for which PFW rules will be managed.
        @param (dict) vins_facts: dictionary with ViNS facts as returned by .../vins/get. It described ViNS
        to which PFW rules set will be applied.
        @param (list of dicts) new_rules: new PFW rules set. If None is passed, remove all existing
        PFW rules for the Compute.

        @returns: list of dictionaries with PFW rules as returned by .../vins/natRuleList on success, 
        None on error. 
        """

        # At the entry to this method we assume that initial validations are already passed, namely:
        # 1) Compute instance exists
        # 2) ViNS exists and has GW VNS in valid state
        # 3) Compute is connected to this ViNS

        #
        #
        # Strategy for port forwards management:
        # 1) obtain current port forwarding rules for the target VM
        # 2) create a delta list of port forwards (rules to add and rules to remove)
        #   - full match between existing & requested = ignore, no update of pfw_delta
        #   - existing rule not present in requested list => copy to pfw_delta and mark as 'delete'
        #   - requested rule not present in the existing list => copy to pfw_delta and mark as 'create'
        # 3) provision delta list (first delete rules marked for deletion, next add rules mark for creation)
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "pfw_configure")

        ret_rules = []

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("pfw_configure() in check mode: port forwards configuration requested "
                                  "for Compute ID {} / ViNS ID {}").format(comp_facts['id'], vins_facts['id'])
            ret_rules = self._pfw_get(comp_facts['id'], vins_facts['id'])
            return ret_rules

        iface_ipaddr = ""  # keep IP address associated with Compute's connection to this ViNS - need this for natRuleDel API
        for iface in comp_facts['interfaces']:
            if iface['connType'] == 'VXLAN' and iface['connId'] == vins_facts['vxlanId']:
                iface_ipaddr = iface['ipAddress']
                break
        else:
            self.result['failed'] = True
            self.result['msg'] = "Compute ID {} is not connected to ViNS ID {}.".format(comp_facts['id'],
                                                                                         vins_facts['id'])
            return ret_rules

        existing_rules = []
        for runner in vins_facts['vnfs']['NAT']['config']['rules']:
            if runner['vmId'] == comp_facts['id']:
                existing_rules.append(runner)

        if not len(existing_rules) and not len(new_rules):
            self.result['failed'] = False
            self.result['warning'] = ("pfw_configure(): both existing and new port forwarding rule lists "
                                      "for Compute ID {} are empty - nothing to do.").format(comp_facts['id'])
            return ret_rules

        if new_rules == None or len(new_rules) == 0:
            # delete all existing rules for this Compute
            api_params = dict(vinsId=vins_facts['id'],
                              ruleId=-1)
            self.decort_api_call(requests.post, "/restmachine/cloudapi/vins/natRuleDel", api_params)
            self.result['changed'] = True
            return ret_rules

        # 
        # delta_list will be a list of dictionaries that describe _changes_ to the port forwarding rules
        # of the Compute in hands.
        # The dictionary has the following keys - values:
        #   (int) publicPortStart - external port range start
        #   (int) publicPortEnd - external port range end
        #   (int) localPort - internal port number
        #   (string) protocol - protocol, either 'tcp' or 'udp'
        #   (string) action - string, either 'del' or 'add'
        #   (int) id - the ID of existing PFW rule that should be deleted (applicable only for action='del')
        # 
        delta_list = []
        # select from new_rules the rules to add - those not found in existing rules
        for rule in new_rules:
            rule['action'] = 'add'
            rule_port_end = rule.get('public_port_end', rule['public_port_start'])
            if rule_port_end > rule['public_port_start']:
                # This is a ranged rule, i.e. when range of public ports maps to an equally
                # sized range of local ports.
                # For such case we have to make sure that the local port equals public
                # port (this check & adjustment will be made by vnf_nat.add method anyway, but
                # if we adjust here, we can avoid unnecessary rule del / add iteration in the
                # module run, thus saving execution time)
                rule['local_port'] = rule['public_port_start']
            for runner in existing_rules:
                if (runner['publicPortStart'] == rule['public_port_start'] and
                        runner['publicPortEnd'] == rule_port_end and
                        runner['localPort'] == rule['local_port'] and
                        runner['protocol'] == rule['proto']):
                    rule['action'] = 'keep'
                    break
            if rule['action'] == 'add':
                delta_rule = dict(publicPortStart=rule['public_port_start'],
                                  publicPortEnd=rule_port_end,
                                  localPort=rule['local_port'],
                                  protocol=rule['proto'],
                                  action='add',
                                  id='-1')
                delta_list.append(delta_rule)

        # select from existing_rules the rules to delete - those not found in new_rules
        for rule in existing_rules:
            rule['action'] = 'del'
            for runner in new_rules:
                runner_port_end = runner.get('public_port_end', runner['public_port_start'])
                if (rule['publicPortStart'] == runner['public_port_start'] and
                        rule['publicPortEnd'] == runner_port_end and
                        rule['localPort'] == runner['local_port'] and
                        rule['protocol'] == runner['proto']):
                    rule['action'] = 'keep'
                    break
            if rule['action'] == 'del':
                delta_list.append(rule)

        if not len(delta_list):
            # strange, but still nothing to do?
            self.result['failed'] = False
            self.result['warning'] = ("pfw_configure() no difference between current and new PFW rules "
                                      "found. No change applied to Compute ID {}.").format(comp_facts['id'])
            ret_rules = self._pfw_get(comp_facts['id'], vins_facts['id'])
            return ret_rules

        # now delta_list contains a list of enriched rule dictionaries with extra key 'action', which
        # tells what kind of action is expected on this rule - 'add' or 'del'
        # We first iterate to delete, then iterate again to add rules

        # Sort pfw_delta_list so that the items with action="del" come first, and those with
        # action='add' come last.
        # Iterate over pfw_delta_list and first delete port forwarding rules marked for deletion,
        # next create the rules marked for creation.
        api_base = "/restmachine/cloudapi/vins/"
        for delta_rule in sorted(delta_list, key=lambda i: i['action'], reverse=True):
            if delta_rule['action'] == 'del':
                api_params = dict(vinsId=vins_facts['id'],
                                  ruleId=delta_rule['id'])
                self.decort_api_call(requests.post, api_base + 'natRuleDel', api_params)
                # On success the above call will return here. On error it will abort execution by calling fail_json.
                self.result['changed'] = True
            elif delta_rule['action'] == 'add':
                api_params = dict(vinsId=vins_facts['id'],
                                  intIp=iface_ipaddr,
                                  intPort=delta_rule['localPort'],
                                  extPortStart=delta_rule['publicPortStart'],
                                  extPortEnd=delta_rule['publicPortEnd'],
                                  proto=delta_rule['protocol'])
                self.decort_api_call(requests.post, api_base + 'natRuleAdd', api_params)
                # On success the above call will return here. On error it will abort execution by calling fail_json.
                self.result['changed'] = True

        self.result['failed'] = False

        ret_rules = self._pfw_get(comp_facts['id'], vins_facts['id'])
        return ret_rules

    def _k8s_get_by_id(self, k8s_id):
        """Helper function that locates k8s by ID and returns k8s facts.

        @param (int) k8s_id: ID of the k8s to find and return facts for.

        @return: k8s ID and a dictionary of k8s facts as provided by k8s/get API call. Note that if it fails
        to find the k8s with the specified ID, it may return 0 for ID and empty dictionary for the facts. So
        it is suggested to check the return values accordingly.
        """
        ret_k8s_id = 0
        ret_k8s_dict = dict()

        if not k8s_id:
            self.result['failed'] = True
            self.result['msg'] = "k8s_get_by_id(): zero k8s ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(k8sId=k8s_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/get", api_params)
        if api_resp.status_code == 200:
            ret_k8s_id = k8s_id
            ret_k8s_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("k8s_get_by_id(): failed to get k8s by ID {}. HTTP code {}, "
                                      "response {}.").format(k8s_id, api_resp.status_code, api_resp.reason)

        return ret_k8s_id, ret_k8s_dict

    ##############################
    #
    # K8s management
    #
    ##############################
    def k8s_find(self, k8s_id, k8s_name="",rg_id=0,check_state=True):
        """Returns non zero k8s ID and a dictionary with k8s details on success, 0 and empty dictionary otherwise.
        This method does not fail the run if k8s cannot be located by its name (arg_k8s_name), because this could be
        an indicator of the requested k8s never existed before.
        However, it does fail the run if k8s cannot be located by arg_k8s_id (if non zero specified) or if API errors
        occur.
        @param (int) arg_k8s_id: integer ID of the k8s to be found. If non-zero k8s ID is passed, account ID and k8s name
        are ignored. However, k8s must be present in this case, as knowing its ID implies it already exists, otherwise
        method will fail.
        @param (string) arg_k8s_name: string that defines the name of k8s to be found. This parameter is case sensitive.
        @param (bool) arg_check_state: tells the method to report k8s in valid states only.

        @return: ID of the k8s, if found. Zero otherwise.
        @return: dictionary with k8s facts if k8s is present. Empty dictionary otherwise. None on error.
        """

        # Resource group can be in one of the following states:
        # MODELED, CREATED, DISABLING, DISABLED, ENABLING, DELETING, DELETED, DESTROYED, DESTROYED
        #
        # Transient state (ending with ING) are invalid from k8s manipulation viewpoint
        #

        K8S_INVALID_STATES = ["MODELED","DESTROYED","DESTROYING"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_find")

        ret_k8s_id = 0
        api_params = dict(includedeleted=True)
        ret_k8s_dict = None

        if k8s_id:
            ret_k8s_id, ret_k8s_dict = self._k8s_get_by_id(k8s_id)
            if not ret_k8s_id:
                self.result['failed'] = True
                self.result['msg'] = "k8s_find(): cannot find k8s cluster by ID {}.".format(k8s_id)
                self.amodule.fail_json(**self.result)
        else:
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/list", api_params)
            if api_resp.status_code == 200:
                k8s_list = json.loads(api_resp.content.decode('utf8'))
        for k8s_item in k8s_list:
            if k8s_item['name'] == k8s_name and k8s_item['rgId'] == rg_id:
                if not check_state or k8s_item['status'] not in K8S_INVALID_STATES:
                    ret_k8s_id = k8s_item['id']
                    _, ret_k8s_dict = self._k8s_get_by_id(ret_k8s_id)


        return ret_k8s_id, ret_k8s_dict

    def k8s_state(self, arg_k8s_dict, arg_desired_state, arg_started=False):
        """Enable or disable k8s cluster.

        @param arg_k8s_dict: dictionary with the target k8s facts as returned by k8s_find(...) method or
        .../k8s/get API call.
        @param arg_desired_state: the desired state for this k8s cluster. Valid states are 'enabled' and 'disabled'.
        @param arg_started: the desired tech state for this k8s cluster. Valid states are 'True' and 'False'.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_state")

        NOP_STATES_FOR_K8S_CHANGE = ["MODELED", "DISABLING",
                                     "ENABLING", "DELETING",
                                     "DELETED", "DESTROYING",
                                     "DESTROYED", "CREATING",
                                     "RESTORING"]
        VALID_TARGET_STATES = ["ENABLED", "DISABLED"]
   
        if arg_k8s_dict['status'] in NOP_STATES_FOR_K8S_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("k8s_state(): no state change possible for k8s ID {} "
                                  "in its current state '{}'.").format(arg_k8s_dict['id'], arg_k8s_dict['status'])
            return
        if arg_k8s_dict['status'] not in VALID_TARGET_STATES:
            self.result['failed'] = False
            self.result['warning'] = ("k8s_state(): unrecognized desired state '{}' requested "
                                      "for k8s ID {}. No k8s state change will be done.").format(arg_desired_state,
                                                                                                 arg_k8s_dict['id'])
            return

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("k8s_state() in check mode: setting state of k8s ID {}, name '{}' to "
                                  "'{}' was requested.").format(arg_k8s_dict['id'], arg_k8s_dict['name'],
                                                                arg_desired_state)
            return
        if arg_desired_state == 'present':
            arg_desired_state = 'enabled'
        k8s_state_api = ""  # This string will also be used as a flag to indicate that API call is necessary
        api_params = dict(k8sId=arg_k8s_dict['id'])
        expected_state = ""
        tech_state = ""
        if arg_k8s_dict['status'] in ["CREATED", "ENABLED"] and arg_desired_state == 'disabled':
            k8s_state_api = "/restmachine/cloudapi/k8s/disable"
            expected_state = "DISABLED"
        elif arg_k8s_dict['status'] in ["CREATED", "DISABLED"] and arg_desired_state == 'enabled':
            k8s_state_api = "/restmachine/cloudapi/k8s/enable"
            expected_state = "ENABLED"
        elif arg_k8s_dict['status'] == "ENABLED" and arg_desired_state == 'enabled' and arg_started is True and arg_k8s_dict['techStatus'] == "STOPPED":
            k8s_state_api = "/restmachine/cloudapi/k8s/start"
            tech_state = "STARTED"
        elif arg_k8s_dict['status'] == "ENABLED" and arg_desired_state == 'enabled' and arg_started is False and arg_k8s_dict['techStatus'] == "STARTED":
            k8s_state_api = "/restmachine/cloudapi/k8s/stop"
            tech_state = "STOPPED"
        if k8s_state_api != "":
            self.decort_api_call(requests.post, k8s_state_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            arg_k8s_dict['status'] = expected_state
            arg_k8s_dict['started'] = tech_state
        else:
            self.result['failed'] = False
            self.result['msg'] = ("k8s_state(): no state change required for k8s ID {} from current "
                                  "state '{}' to desired state '{}'.").format(arg_k8s_dict['id'],
                                                                              arg_k8s_dict['status'],
                                                                              arg_desired_state)
        
        return

    def k8s_delete(self, k8s_id, permanently=False):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "k8s_delete() in check mode: delete K8s cluster ID {} was requested.".format(k8s_id)
            return

        api_params = dict(k8sId=k8s_id,
                          permanently=permanently,
                          )
        self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['msg'] = "k8s_delete() K8s cluster ID {} was deleted.".format(k8s_id)
        self.result['changed'] = True
        return

    def k8s_restore(self, k8s_id ):
        """Restores a deleted k8s cluster identified by ID.

        @param k8s_id: ID of the k8s cluster to restore.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "k8s_restore() in check mode: restore k8s ID {} was requested.".format(k8s_id)
            return

        api_params = dict(k8sId=k8s_id)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return
    
    def k8s_enable(self,k8s_id):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_enable")
        api_params = dict(k8sId=k8s_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/enable", api_params)
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def k8s_provision(self, k8s_name,
                      k8ci_id,rg_id, master_count,
                      master_cpu, master_ram,
                      master_disk, default_worker, extnet_id,
                      with_lb, annotation, ):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("k8s_provision() in check mode. Provision k8s '{}' in RG ID {} "
                                  "was requested.").format(k8s_name, rg_id)
            return 0
        def_wg_name = default_worker['name']
        def_wg_count = default_worker['num']
        def_wg_cpu = default_worker['cpu']
        def_wg_ram = default_worker['ram']
        def_wg_disk = default_worker['disk']
        def_wg_lab = default_worker['labels'] if "labels" in default_worker else None
        def_wg_taints = default_worker['taints'] if "taints" in default_worker else None
        def_wg_ann = default_worker['annotations'] if "annotations" in default_worker else None

        api_url = "/restmachine/cloudapi/k8s/create"
        api_params = dict(name=k8s_name,
                          rgId=rg_id,
                          k8ciId=k8ci_id,
                          workerGroupName=def_wg_name,
                          masterNum=master_count,
                          masterCpu=master_cpu,
                          masterRam=master_ram,
                          masterDisk=master_disk,
                          workerNum=def_wg_count,
                          workerCpu=def_wg_cpu,
                          workerRam=def_wg_ram,
                          workerDisk=def_wg_disk,
                          labels=def_wg_lab,
                          taints=def_wg_taints,
                          annotations=def_wg_ann,
                          extnetId=extnet_id,
                          withLB=with_lb,
                          desc=annotation,
                          )
        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        k8s_id = ""
        if api_resp.status_code == 200:
            for i in range(300):
                api_get_url = "/restmachine/cloudapi/tasks/get"
                api_get_params = dict(
                    auditId=api_resp.content.decode('utf8').replace('"', '')
                )
                api_get_resp = self.decort_api_call(requests.post, api_get_url, api_get_params)
                ret_info = json.loads(api_get_resp.content.decode('utf8'))
                if api_get_resp.status_code == 200:
                    if ret_info['status'] in ["PROCESSING", "SCHEDULED"]:
                        self.result['msg'] = ("k8s_provision(): Can't create cluster")
                        self.result['failed'] = False
                        time.sleep(30)
                    elif ret_info['status'] == "ERROR":
                        self.result['msg'] = ("k8s_provision(): Can't create cluster")
                        self.result['failed'] = True
                        return
                    elif ret_info['status'] == "OK":
                        k8s_id = ret_info['result']
                        self.result['changed'] = True
                        return k8s_id
                    else:
                        k8s_id = ret_info['status']
                else:
                    self.result['msg'] = ("k8s_provision(): Can't create cluster")
                    self.result['failed'] = True
            # Timeout
            self.result['msg'] = ("k8s_provision(): Can't create cluster")
            self.result['failed'] = True
        else:
            self.result['msg'] = ("k8s_provision(): Can't create cluster")
            self.result['failed'] = True
        return

    def k8s_workers_modify(self,arg_k8swg,arg_modwg):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_workers_modify")
        
        
        if self.k8s_info['techStatus'] != "STARTED":
            self.result['changed'] = False
            self.result['msg'] = ("k8s_workers_modify(): Can't modify with TechStatus other then STARTED")
            return
        
        wg_del_list = []
        wg_add_list = []
        wg_modadd_list = []
        wg_moddel_list = []
        wg_outer = [rec['name'] for rec in arg_modwg]
        wg_inner = [rec['name'] for rec in arg_k8swg['k8sGroups']['workers']]

        for rec in arg_k8swg['k8sGroups']['workers']:
            if rec['name'] not in wg_outer:
                wg_del_list.append(rec['id'])
        for rec in arg_modwg:
            if rec['name'] not in wg_inner:
                wg_add_list.append(rec)
        
        for rec_inn in arg_k8swg['k8sGroups']['workers']:
            for rec_out in arg_modwg:
                if rec_inn['name'] == rec_out['name']:
                    if rec_inn['num'] != rec_out['num'] and rec_out['num'] != 0:
                        count = rec_inn['num']-rec_out['num']
                        cmp_list = []
                        if count > 0:
                            for cmp in rec_inn['detailedInfo'][-count:]:
                                cmp_list.append(cmp['id'])
                            wg_moddel_list.append({rec_inn['id']:cmp_list})
                        if count < 0:
                            wg_modadd_list.append({rec_inn['id']:abs(count)})

        if wg_del_list:
            for wgid in wg_del_list: 
                api_params = dict(k8sId=self.k8s_id,workersGroupId=wgid)
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/workersGroupDelete", api_params)
                self.result['changed'] = True    
        if wg_add_list:
            for wg in wg_add_list:
                api_params = dict(k8sId=self.k8s_id,
                                  name=wg['name'],
                                  workerNum=wg['num'],
                                  workerCpu=wg['cpu'],
                                  workerRam=wg['ram'],
                                  workerDisk=wg['disk'],
                                  labels=wg['labels'] if "labels" in wg else None,
                                  taints=wg['taints'] if "taints" in wg else None,
                                  annotations=wg['annotations'] if "annotations" in wg else None,
                                )
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/workersGroupAdd", api_params)
                self.result['changed'] = True
        if wg_modadd_list:
            for wg in wg_modadd_list:
                for key in wg:
                    api_params = dict(k8sId=self.k8s_id,workersGroupId=key,num=wg[key])
                    api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/workerAdd", api_params)
                    self.result['changed'] = True
        if wg_moddel_list:
            for wg in wg_moddel_list:
                for key in wg:
                    for cmpid in wg[key]:
                        api_params = dict(k8sId=self.k8s_id,workersGroupId=key,workerId=cmpid)
                        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/deleteWorkerFromGroup", api_params)
                        self.result['changed'] = True
        self.result['failed'] = False
        return
    
    def k8s_k8ci_find(self,arg_k8ci_id):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_k8ci_find")
        
        api_params = dict(includeDisabled=False)

        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8ci/list", api_params)
        k8ci_id_present = False
        if api_resp.status_code == 200:
            ret_k8ci_list = json.loads(api_resp.content.decode('utf8'))
            for k8ci_item in ret_k8ci_list:
                if k8ci_item['id'] == arg_k8ci_id:
                    k8ci_id_present = True
                    break
                
            else:
                self.result['failed'] = True
                self.result['msg'] = ("Cannot find k8ci id: {}.").format(arg_k8ci_id)
                self.amodule.fail_json(**self.result)  
        else:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to get k8ci list HTTP code {}.").format(api_resp.status_code)
            self.amodule.fail_json(**self.result)
        return arg_k8ci_id
    
    def k8s_getConfig(self):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "k8s_getConfig")
        
        api_params = dict(k8sId=self.k8s_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/k8s/getConfig", api_params)
        ret_conf = api_resp.content.decode('utf8')
        return ret_conf

    ##############################
    #
    # Bservice management
    #
    ##############################
    def bservice_get_by_id(self,bs_id):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "bservice_get_by_id")

        ret_bs_id = 0
        ret_bs_dict = dict()

        if not bs_id:
            self.result['failed'] = True
            self.result['msg'] = "bservice_get_by_id(): zero B-Service ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(serviceId=bs_id, )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/bservice/get", api_params)
        if api_resp.status_code == 200:
            ret_bs_id = bs_id
            ret_bs_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("bservice_get_by_id(): failed to get B-service by ID {}. HTTP code {}, "
                                      "response {}.").format(bs_id, api_resp.status_code, api_resp.reason)

        return ret_bs_id, ret_bs_dict
    def _bservice_rg_list(self,acc_id,rg_id):
        ret_bs_dict=dict()
        api_params = dict(accountId=acc_id,rgId=rg_id )
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/bservice/list", api_params)
        if api_resp.status_code == 200:
            ret_bs_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("bservice_rg_list(): failed to get B-service list. HTTP code {}, "
                                      "response {}.").format(api_resp.status_code, api_resp.reason)
        return ret_bs_dict
    
    def bservice_find(self,account_id,rg_id,bservice_name="",bservice_id = 0,check_state=True):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "bservice_find")

        if bservice_id == 0:
            bs_rg_list = self._bservice_rg_list(account_id,rg_id)
            for srv in bs_rg_list:
                if bservice_name == srv['name']:
                    bservice_id = int(srv['id'])

        if  bservice_id > 0:
            ret_bs_id,ret_bs_dict = self.bservice_get_by_id(bservice_id)
            return ret_bs_id,ret_bs_dict
        else:
            return bservice_id,None
    
    def bservice_provision(self,bs_name,rgid,sshuser=None,sshkey=None):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "bservice_provision")

        api_url = "/restmachine/cloudapi/bservice/create"
        api_params = dict(
            name = bs_name,
            rgId = rgid,
            sshUser = sshuser,
            sshKey = sshkey,
        )   
        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        self.result['failed'] = False
        self.result['changed'] = True
        ret_bservice_id = int(api_resp.content.decode('utf8'))
        return ret_bservice_id
    
    def bservice_state(self,bs_dict,desired_state,started=True):
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "bservice_state")
        
        if desired_state == "present":
            desired_state = "enabled"
        
        NOP_STATES_FOR_BS_CHANGE = ["MODELED", "DISABLING", "ENABLING", "DELETING", "DELETED", "DESTROYING",
                                      "DESTROYED","RESTORYNG","RECONFIGURING"]
        VALID_TARGET_STATES = ["enabled", "disabled"]

        if bs_dict['status'] in NOP_STATES_FOR_BS_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("bservice_state(): no state change possible for ViNS ID {} "
                                  "in its current state '{}'.").format(bs_dict['id'], bs_dict['status'])
            return

        if desired_state not in VALID_TARGET_STATES:
            self.result['failed'] = False
            self.result['warning'] = ("bservice_state(): unrecognized desired state '{}' requested "
                                      "for B-service ID {}. No B-service state change will be done.").format(desired_state,
                                                                                                   bs_dict['id'])
            return

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("bservice_state() in check mode: setting state of B-service ID {}, name '{}' to "
                                  "'{}' was requested.").format(bs_dict['id'], bs_dict['name'],
                                                                desired_state)
            return

        bsstate_api = ""  # this string will also be used as a flag to indicate that API call is necessary
        api_params = dict(serviceId=bs_dict['id'])
        expected_state = ""

        if bs_dict['status'] in ["CREATED", "ENABLED"] and desired_state == 'disabled':
            bsstate_api = "/restmachine/cloudapi/bservice/disable"
            expected_state = "DISABLED"
        elif bs_dict['status'] in ["CREATED", "DISABLED"] and desired_state == 'enabled':
            bsstate_api = "/restmachine/cloudapi/bservice/enable"
            expected_state = "ENABLED"

        if bsstate_api != "":
            self.decort_api_call(requests.post, bsstate_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            bs_dict['status'] = expected_state
        else:
            self.result['failed'] = False
            self.result['msg'] = ("bservice_state(): no state change required for B-service ID {} from current "
                                  "state '{}' to desired state '{}'.").format(bs_dict['id'],
                                                                              bs_dict['status'],
                                                                              desired_state)
        
        start_api = ""

        if bs_dict['status'] in ["ENABLED","enabled"]: 
            if started == True and bs_dict['techStatus'] == "STOPPED":
                start_api = "/restmachine/cloudapi/bservice/start"
                t_state_expected = "STARTED"
            if started == False and bs_dict['techStatus'] == "STARTED":
                start_api = "/restmachine/cloudapi/bservice/stop"
                t_state_expected = "STOPPED"
        
        if start_api != "":
            self.decort_api_call(requests.post, start_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            bs_dict['techStatus'] = t_state_expected
        else:
            self.result['failed'] = False
            self.result['msg'] = ("bservice_state(): no start/stop action required for B-service ID {} from current "
                                  "techStatus '{}' to desired started = '{}'.").format(bs_dict['id'],
                                                                              bs_dict['techStatus'],
                                                                              started)
        return

    def bservice_delete(self,bs_id,permanently=True):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "bservice_delete")
        
        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "bservice_delete() in check mode: delete B-Service ID {} was requested.".format(bs_id)
            return

        api_params = dict(serviceId=bs_id,permanently=permanently)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/bservice/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['msg'] = "bservice_delete() B-Service ID {} was deleted.".format(bs_id)
        self.result['changed'] = True

        return

#
# GROUP MANAGE
#
    def _group_get_by_id(self,bs_id,g_id):
        
        api_params = dict(serviceId=bs_id,compgroupId=g_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/bservice/groupGet", api_params)
        if api_resp.status_code == 200:
            ret_gr_id = g_id
            ret_gr_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("group_get_by_id(): failed to get Group by ID {}. HTTP code {}, "
                                      "response {}.").format(g_id, api_resp.status_code, api_resp.reason)
        return ret_gr_id,ret_gr_dict
    
    def group_find(self,bs_id,bs_info,group_id=0,group_name=""):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_find")
        
        if group_id == 0:
            try:
                i = bs_info['groupsName'].index(group_name)
            except:
                return 0,None
            group_id = int(bs_info['groups'][i])
        return self._group_get_by_id(bs_id,group_id)
    
    def group_state(self,bs_id,gr_id,desired_state):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_state")

        group_api=""
        if desired_state == 'stopped':
            group_api = "/restmachine/cloudapi/bservice/groupStop"
            state_expected = "STOPPED"
        else:
            group_api = "/restmachine/cloudapi/bservice/groupStart"
            state_expected = "STARTED"
        api_params = dict(
            serviceId=bs_id,
            compgroupId=gr_id
        )
        if group_api != "":
            self.decort_api_call(requests.post, group_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
        else:
            self.result['failed'] = False
            self.result['msg'] = ("group_state(): no start/stop action required for B-service ID {} "
                                  "to desired state '{}'.").format(bs_id,desired_state)
        return
    def group_resize_count(self,bs_id,gr_dict,desired_count):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_resize_count")

        count = len(gr_dict['computes'])
        if desired_count != count:
            api_params=dict(
                serviceId=bs_id,
                compgroupId=gr_dict['id'],
                count=desired_count,
                mode="ABSOLUTE"
            )
            api_url = "/restmachine/cloudapi/bservice/groupResize"
            self.decort_api_call(requests.post, api_url, api_params)
            self.result['failed'] = False
            self.result['changed'] = True
            self.need_update_group_info = True
        else:
            self.result['failed'] = False
            self.result['msg'] = ("group_resize_count(): no need resize  Group ID {}.").format(gr_dict['id'])
        return                  
    def group_update_hw(self,bs_id,gr_dict,arg_cpu,arg_disk,arg_name,arg_role,arg_ram):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_update_hw")

        api_params=dict(
            serviceId=bs_id,
            compgroupId=gr_dict['id'],
            force=True,
        )

        if gr_dict['cpu'] != arg_cpu:
            api_params.update({'cpu': arg_cpu})
        if gr_dict['ram'] != arg_ram:
            api_params.update({'ram': arg_ram})
        if gr_dict['role'] != arg_role:
            api_params.update({'role': arg_role})
        if gr_dict['disk'] != arg_disk:
            api_params.update({'disk': arg_disk})
        if gr_dict['name'] != arg_name:
            api_params.update({'name': arg_name})

        api_url = "/restmachine/cloudapi/bservice/groupUpdate"
        if len(api_params) > 3:
            # 
            self.decort_api_call(requests.post, api_url, api_params)
            self.result['failed'] = False
            self.result['changed'] = True
            self.need_update_group_info = True
        else:
            self.result['failed'] = False
            self.result['msg'] = ("group_update_hw(): no need update Group ID {}.").format(gr_dict['id'])
        return
    
    def group_update_net(self,bs_id,gr_dict,arg_net):

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_update_net")

        list_vins= list()
        list_extnet= list()
        for net in arg_net:
            if net['type'] == 'VINS':
                list_vins.append(net['id'])
            else:
                list_extnet.append(net['id'])

        if gr_dict['vinses'] != list_vins:
            api_url = "/restmachine/cloudapi/bservice/groupUpdateVins"
            api_params = dict(
                serviceId=bs_id,
                compgroupId=gr_dict['id'],
                vinses=list_vins
            )
            self.decort_api_call(requests.post, api_url, api_params)
            self.result['failed'] = False
            self.result['changed'] = True
        
        #extnet connection need stoped status of group
        #rly need connect group to extnet ?
        return
    def group_provision(
        self,bs_id,arg_name,arg_count=1,arg_cpu=1,arg_ram=1024,
        arg_boot_disk=10,arg_image_id=0,arg_driver="KVM_X86",arg_role="",
        arg_network=None,arg_timeout=0
        ):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_provision")
        
        list_vins= list()
        for net in arg_network:
            if net['type'] == 'VINS':
                list_vins.append(net['id'])
        api_url = "/restmachine/cloudapi/bservice/groupAdd"
        api_params = dict(
            serviceId = bs_id,
            name = arg_name,
            count = arg_count,
            cpu = arg_cpu,
            ram = arg_ram,
            disk = arg_boot_disk,
            imageId = arg_image_id,
            driver = arg_driver,
            role = arg_role,
            vinses = list_vins,
            timeoutStart = arg_timeout
        )
        self.decort_api_call(requests.post, api_url, api_params)
        self.result['failed'] = False
        self.result['changed'] = True
        return
    
    def group_delete(self,bs_id,gr_id):
        
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "group_delete")
        
        api_url = "/restmachine/cloudapi/bservice/groupRemove"
        api_params=dict(
            serviceId = bs_id,
            compgroupId = gr_id
        )
        self.decort_api_call(requests.post, api_url, api_params)
        self.result['failed'] = False
        self.result['msg'] = "group_delete() Group ID {} was deleted.".format(gr_id)
        self.result['changed'] = True
        return      
####################
### LB MANAGMENT ###
####################
    def _lb_get_by_id(self,lb_id):
        """Helper function that locates LB by ID and returns LB facts. This function
        expects that the ViNS exists (albeit in DELETED or DESTROYED state) and will return
        0 LB ID if not found.

        @param (int) vins_id: ID of the LB to find and return facts for.

        @return: LB ID and a dictionary of LB facts as provided by LB/get API call. 
        """
        ret_lb_id = 0
        ret_lb_dict = dict()

        if not lb_id:
            self.result['failed'] = True
            self.result['msg'] = "lb_get_by_id(): zero LB ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(lbId=lb_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/get", api_params)
        if api_resp.status_code == 200:
            ret_lb_id = lb_id
            ret_lb_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("lb_get_by_id(): failed to get LB by ID {}. HTTP code {}, "
                                      "response {}.").format(lb_id, api_resp.status_code, api_resp.reason)

        return ret_lb_id, ret_lb_dict
    def _rg_listlb(self,rg_id):
        """List all LB in the resource group
            @param (int) rg_id: id onr resource group
        """
        if not rg_id:
            self.result['failed'] = True
            self.result['msg'] = "_rg_listlb(): zero RG ID specified."
            self.amodule.fail_json(**self.result)

        api_params = dict(rgId=rg_id)
        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/rg/listLb", api_params)
        if api_resp.status_code == 200:
            ret_rg_vins_list = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("rg_listlb(): failed to get RG by ID {}. HTTP code {}, "
                                      "response {}.").format(rg_id, api_resp.status_code, api_resp.reason)
            return []

        return ret_rg_vins_list
    def lb_find(self,lb_id=0,lb_name="",rg_id=0):
        """Find specified LB. 

        @returns: LB ID and dictionary with LB facts. 
        """
        LB_INVALID_STATES = ["ENABLING", "DISABLING", "DELETING", "DELETED", "DESTROYING", "DESTROYED"]

        ret_lb_id = 0
        ret_lb_facts = None

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_find")

        if lb_id > 0:
            ret_lb_id, ret_lb_facts = self._lb_get_by_id(lb_id)
            if not ret_lb_id:
                self.result['failed'] = True
                self.result['msg'] = "lb_find(): cannot find LB by ID {}.".format(lb_id)
                self.amodule.fail_json(**self.result)
            if not self.amodule.check_mode or ret_lb_facts['status'] not in LB_INVALID_STATES:
                return ret_lb_id, ret_lb_facts
            else:
                return 0, None
        elif lb_name != "":
            if rg_id > 0:
                list_lb = self._rg_listlb(rg_id)
                for lb in list_lb:
                    if lb['name'] == lb_name:
                        ret_lb_id, ret_lb_facts = self._lb_get_by_id(lb['id'])
                        if not self.amodule.check_mode or ret_lb_facts['status'] not in LB_INVALID_STATES:
                            return ret_lb_id, ret_lb_facts
                        else:
                            return 0, None
            else:
                self.result['failed'] = True
                self.result['msg'] = ("vins_lb(): cannot find LB by name '{}' "
                                      "when no account ID or RG ID is specified.").format(lb_name)
                self.amodule.fail_json(**self.result)
        else: 
            self.result['failed'] = True
            self.result['msg'] = "vins_find(): cannot find LB by zero ID and empty name."
            self.amodule.fail_json(**self.result)

        return 0, None
    def lb_provision(self,lb_name,rg_id,vins_id,ext_net_id,annotation,start=True):
        """Provision LB according to the specified arguments.
        If critical error occurs the embedded call to API function will abort further execution of 
        the script and relay error to Ansible.
        Note, that when creating ViNS at account level, default location under DECORT controller 
        will be selected automatically.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("vins_lb() in check mode: provision LB name '{}' was "
                                  "requested in RG with id: {}.").format(lb_name,rg_id)
            return 0

        if lb_name == "":
            self.result['failed'] = True
            self.result['msg'] = "lb_provision(): LB name cannot be empty."
            self.amodule.fail_json(**self.result)

        api_url = "/restmachine/cloudapi/lb/create"
        api_params = dict(
                name=lb_name,
                rgId=rg_id,
                extnetId=ext_net_id,
                vinsId=vins_id,
                start=start,
                decs=annotation
        )
        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        ret_lb_id = int(api_resp.content.decode('utf8'))
        return ret_lb_id
    def lb_delete(self,lb_id,permanently=False):
        """Deletes specified LB.

        @param (int) lb_id: integer value that identifies the ViNS to be deleted.
        @param (bool) permanently: a bool that tells if deletion should be permanent. If False, the LB will be
        marked as DELETED and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes this LB can be restored by calling the corresponding 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "lb_delete() in check mode: delete ViNS ID {} was requested.".format(lb_id)
            return

        api_params = dict(lbId=lb_id,
                          permanently=permanently)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return
    def lb_state(self, lb_dict, desired_state):
        """Change state for LB.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_state")

        NOP_STATES_FOR_LB_CHANGE = ["MODELED", "DISABLING", "ENABLING", "DELETING", "DELETED", "DESTROYING",
                                      "DESTROYED"]
        VALID_TARGET_STATES = ["enabled", "disabled","restart"]
        VALID_TARGET_TSTATES = ["STARTED","STOPPED"]
        
        if lb_dict['status'] in NOP_STATES_FOR_LB_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("lb_state(): no state change possible for LB ID {} "
                                  "in its current state '{}'.").format(lb_dict['id'], lb_dict['status'])
            return

        if desired_state not in VALID_TARGET_STATES:
            self.result['failed'] = False
            self.result['warning'] = ("lb_state(): unrecognized desired state '{}' requested "
                                      "for LB ID {}. No LB state change will be done.").format(desired_state,
                                                                                                   lb_dict['id'])
            return

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = ("lb_state() in check mode: setting state of LB ID {}, name '{}' to "
                                  "'{}' was requested.").format(lb_dict['id'], lb_dict['name'],
                                                                desired_state)
            return

        state_api = ""
        api_params = dict(lbId=lb_dict['id'])
        expected_state = ""
        if lb_dict['status'] in ["CREATED", "ENABLED"]:
            if desired_state == 'disabled':
                state_api = "/restmachine/cloudapi/lb/disable"
                expected_state = "DISABLED"
            if lb_dict['techStatus'] == "STARTED":
                if desired_state == 'stopped':
                    state_api = "/restmachine/cloudapi/lb/stop"
                if desired_state == 'restart':
                    state_api = "/restmachine/cloudapi/lb/restart"
            elif lb_dict['techStatus'] == "STOPPED":
                if desired_state == 'started':
                    state_api = "/restmachine/cloudapi/lb/start"
        elif lb_dict['status'] == "DISABLED" and desired_state == 'enabled':
            state_api = "/restmachine/cloudapi/lb/enable"
            expected_state = "ENABLED"

        if state_api != "":
            self.decort_api_call(requests.post, state_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
            lb_dict['status'] = expected_state
        else:
            self.result['failed'] = False
            self.result['msg'] = ("lb_state(): no state change required for LB ID {} from current "
                                  "state '{}' to desired state '{}'.").format(lb_dict['id'],
                                                                              lb_dict['status'],
                                                                              desired_state)
        return
    def lb_restore(self, lb_id):
        """Restores previously deleted LB identified by its ID.

        @param lb_id: ID of the LB to restore.

        @returns: nothing on success. On error this method will abort module execution.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['msg'] = "lb_restore() in check mode: restore LB ID {} was requested.".format(lb_id)
            return

        api_params = dict(lbId=lb_id)
        self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return
    
    def lb_update_backends(self,lb_backends,mod_backends,mod_servers):
        """
        backends
        """
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_update_backends")

        if mod_backends:
            backs_out = [rec['name'] for rec in mod_backends]
        else:
            backs_out=""
        backs_in = [rec['name'] for rec in lb_backends] 
        del_backs = set(backs_in).difference(backs_out) 
        add_becks = set(backs_out).difference(backs_in)
        upd_becks = set(backs_in).intersection(backs_out)
        
        for item in del_backs:
            #need delete frontend
            api_params = dict(lbId=self.lb_id,backendName = item)
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendDelete", api_params)
            self.result['changed'] = True
        for item in add_becks:
            backend, = list(filter(lambda i: i['name'] == item,mod_backends))
            api_params = dict(
                            lbId=self.lb_id,
                            backendName = backend['name'],
                            algorithm = backend['algorithm'] if "algorithm" in backend else None,
                            **backend['default_settings'] if "default_settings" in backend else {},
                            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendCreate", api_params)
            self.result['changed'] = True
        for item in upd_becks.union(add_becks):
            
            backend, = list(filter(lambda i: i['name'] == item,lb_backends))
            mod_backend, = list(filter(lambda i: i['name'] == item,mod_backends))
            servers_in = [rec['name'] for rec in backend['servers']]
            servers_out = []
            #oO rework
            if mod_servers:
                for serv in mod_servers:
                    for bend in serv['backends']:
                        if bend['name'] == item:
                            servers_out.append(serv['name'])

            del_srv = set(servers_in).difference(servers_out)
            add_srv = set(servers_out).difference(servers_in)
            upd_srv = set(servers_in).intersection(servers_out)

            del backend['serverDefaultSettings']['guid']
            
            if "default_settings" not in mod_backend:
                mod_backend["default_settings"] = self.default_settings

            if "algorithm" not in mod_backend:
                mod_backend["algorithm"] = self.default_alg

            if backend['serverDefaultSettings'] != mod_backend["default_settings"] or\
                mod_backend["algorithm"] != backend['algorithm']:
                    api_params = dict(
                            lbId=self.lb_id,
                            backendName = item,
                            algorithm = mod_backend['algorithm'],
                            **mod_backend['default_settings'] if "default_settings" in mod_backend else {},
                            )
                    api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendUpdate", api_params)
                    self.result['changed'] = True
            
            for srv in del_srv:
                api_params = dict(lbId=self.lb_id,backendName = item,serverName=srv)
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerDelete", api_params)
                self.result['changed'] = True
            for srv in add_srv:
                server, = list(filter(lambda i: i['name'] == srv,mod_servers))
                back, = list(filter(lambda i: i['name'] == item,server['backends']))
                api_params = dict(
                            lbId=self.lb_id,
                            backendName = item,
                            serverName = server['name'],
                            address = server['address'],
                            port = back['port'],
                            check = server['check'] if "check" in server else None,
                            **server['server_settings'] if "server_settings" in server else {},
                            )
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerAdd", api_params)
                self.result['changed'] = True
            for srv in upd_srv:
                mod_server, = list(filter(lambda i: i['name'] == srv,mod_servers))
                mod_server_back, = list(filter(lambda i: i['name'] == item,mod_server['backends']))
                server, = list(filter(lambda i: i['name'] == srv, backend['servers']))
                
                del server['serverSettings']['guid']

                if "server_settings" not in mod_server_back:
                    mod_server_back['server_settings'] = self.default_settings    
                if "check" not in mod_server:
                    mod_server['check'] = self.default_server_check
                
                if (mod_server['address'] != server['address'] or\
                    server['check']!=mod_server["check"]) or\
                    mod_server_back['server_settings'] != server['serverSettings']:
                        api_params = dict(
                            lbId=self.lb_id,
                            backendName = item,
                            serverName = mod_server['name'],
                            address = mod_server['address'],
                            port = mod_server_back['port'],
                            check = mod_server_back['check'] if "check" in mod_server_back else None,
                            **mod_server_back['server_settings'] if "server_settings" in mod_server_back else {},
                            )
                        api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerUpdate", api_params)
                        self.result['changed'] = True
                
        return
    def lb_update_frontends(self,lb_frontends,mod_frontends):
        """
        frontends
        """
        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "lb_update_frontends")
        if mod_frontends:
            front_out = [rec['name'] for rec in mod_frontends]
        else:
            front_out=""
        front_in = [rec['name'] for rec in lb_frontends]

        del_front = set(front_in).difference(front_out)
        add_front = set(front_out).difference(front_in)
        upd_front = set(front_in).intersection(front_out)

        for front in del_front:
            delete_front, = list(filter(lambda i: i['name'] == front,lb_frontends))
            api_params = dict(
                            lbId=self.lb_id,
                            frontendName=delete_front['name'],
                            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendDelete", api_params)
            self.result['changed'] = True
        for front in add_front:
            create_front, = list(filter(lambda i: i['name'] == front,mod_frontends))
            api_params = dict(
                            lbId=self.lb_id,
                            frontendName=create_front['name'],
                            backendName=create_front['backend'],
                            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendCreate", api_params)
            self.result['changed'] = True
            if "bindings" in create_front:
                for bind in create_front['bindings']:
                    self._lb_bind_frontend(
                                            create_front['name'],
                                            bind['name'],
                                            bind['address'] if "address" in bind else None,
                                            bind['port'] if "port" in bind else None
                                            )
        for front in upd_front:
            update_front, = list(filter(lambda i: i['name'] == front,mod_frontends))
            lb_front, = list(filter(lambda i: i['name'] == front,lb_frontends))
            mod_bind = [rec['name'] for rec in update_front['bindings']]
            lb_bind = [rec['name'] for rec in lb_front['bindings']]

            del_bind_list = set(lb_bind).difference(mod_bind)
            add_bind_list = set(mod_bind).difference(lb_bind)
            upd_bind_list = set(lb_bind).intersection(mod_bind)

            for bind_name in del_bind_list:
                del_bind, = list(filter(lambda i: i['name'] == bind_name,lb_front['bindings']))
                api_params = dict(
                            lbId=self.lb_id,
                            frontendName=update_front['name'],
                            bindingName=del_bind['name'],
                            )
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendBindDelete", api_params)
                self.result['changed'] = True
            for bind_name in add_bind_list:
                add_bind, = list(filter(lambda i: i['name'] == bind_name,update_front['bindings']))
                self._lb_bind_frontend(
                    update_front['name'],
                    add_bind['name'],
                    add_bind['address'] if "address" in add_bind else None,
                    add_bind['port'] if "port" in add_bind else None
                    )
            for bind_name in upd_bind_list:
                lb_act_bind, = list(filter(lambda i: i['name'] == bind_name,lb_front['bindings']))
                mod_act_bind, = list(filter(lambda i: i['name'] == bind_name,update_front['bindings']))
                del lb_act_bind['guid']
                if lb_act_bind != mod_act_bind:
                    self._lb_bind_frontend(
                        update_front['name'],
                        mod_act_bind['name'],
                        mod_act_bind['address'] if "address" in mod_act_bind else None,
                        mod_act_bind['port'] if "port" in mod_act_bind else None,
                        update=True
                    )    
        return
    
    def _lb_bind_frontend(self,front_name,bind_name,bind_addr=None,bind_port=None,update=False):
        api_params = dict(
                            lbId=self.lb_id,
                            frontendName=front_name,
                            bindingName=bind_name,
                            bindingAddress=bind_addr,
                            bindingPort=bind_port,
                        )
        if update == True:
            api_url = "/restmachine/cloudapi/lb/frontendBindingUpdate"
        else:
            api_url = "/restmachine/cloudapi/lb/frontendBind"
        api_resp = self.decort_api_call(requests.post, api_url, api_params)
        self.result['changed'] = True
    
    def lb_update(self,lb_backends=[],lb_frontends=[],mod_backends=[],mod_servers=[],mod_frontends=[]):
        #lists from module and cloud
        mod_backs_list = [back['name'] for back in mod_backends]
        lb_backs_list = [back['name'] for back in lb_backends]
        #ADD\DEL\UPDATE LISTS OF BACKENDS
        del_list_backs = set(lb_backs_list).difference(mod_backs_list)
        add_back_list = set(mod_backs_list).difference(lb_backs_list)
        upd_back_list = set(lb_backs_list).intersection(mod_backs_list)
        
        #FE

        mod_front_list = [front['name'] for front in mod_frontends]
        lb_front_list = [front['name'] for front in lb_frontends]
        
        if del_list_backs:
            
            self._lb_delete_backends(
                del_list_backs,
                lb_frontends
            )

        if add_back_list:
            self._lb_create_backends(
                add_back_list,
                mod_backends,
                mod_servers   
            )

        if upd_back_list:
            self._lb_update_backends(
                upd_back_list,
                lb_backends,
                mod_backends,
                mod_servers    
            )
        
        del_list_fronts = set(lb_front_list).difference(mod_front_list)
        add_list_fronts = set(mod_front_list).difference(lb_front_list)
        upd_front_list = set(lb_front_list).intersection(mod_front_list)

        if del_list_fronts:
            self._lb_delete_fronts(del_list_fronts)
        
        if add_list_fronts:
            self._lb_add_fronts(add_list_fronts,mod_frontends)
        if upd_front_list:
            self._lb_update_fronts(upd_front_list,lb_frontends,mod_frontends)
        
        return
    
    def _lb_delete_backends(self,back_list,lb_fronts):

        #delete frontends with that backend
        for back in back_list:
            fronts = list(filter(lambda i: i['backend'] == back,lb_fronts))
            if fronts:
                self._lb_delete_fronts(fronts)
            api_params = dict(
                lbId=self.lb_id,
                backendName = back
            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendDelete", api_params)
            self.result['changed'] = True
        return
    def _lb_delete_fronts(self,d_fronts):
        for front in d_fronts:
            api_params = dict(
                lbId=self.lb_id,
                frontendName=front['name'] if "name" in front else front,
            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendDelete", api_params)
            #del from cloud dict
            if type(front)==dict:
                del self.lb_facts['frontends'][front['name']]
            self.result['changed'] = True
        
        return
    def _lb_add_fronts(self,front_list,mod_fronts):
        for front in front_list:
            add_front, = list(filter(lambda i: i['name'] == front,mod_fronts))
            api_params = dict(
                lbId=self.lb_id,
                frontendName=add_front['name'],
                backendName=add_front['backend'],
                )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendCreate", api_params)
            for bind in add_front['bindings']:
                self._lb_bind_frontend(
                    add_front['name'],
                    bind['name'],
                    bind['address']if "address" in bind else None,
                    bind['port'] if "port" in bind else None,
                )
            return
    def _lb_create_backends(self,back_list,mod_backs,mod_serv):
        '''
        Create backends and add servers to them
        '''
        for back in back_list:
            backend, = list(filter(lambda i: i['name'] == back,mod_backs))
            api_params = dict(
                            lbId=self.lb_id,
                            backendName = back,
                            algorithm = backend['algorithm'] if "algorithm" in backend else None,
                            **backend['default_settings'] if "default_settings" in backend else {},
                            )
            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendCreate", api_params)

            for server in mod_serv:
                try:
                    srv_back, = list(filter(lambda i: i['name'] == back,server['backends']))
                except:
                    continue
                api_params = dict(
                                lbId=self.lb_id,
                                backendName = back,
                                serverName = server['name'],
                                address = server['address'],
                                port = srv_back['port'],
                                check = srv_back['check'] if "check" in srv_back else None,
                                **srv_back['server_settings'] if "server_settings" in srv_back else {},
                                )
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerAdd", api_params)
            
            self.result['changed'] = True

        return
    
    def _lb_update_backends(self,back_list,lb_backs,mod_backs,mod_serv):
        
        lb_backs = list(filter(lambda i: i['name'] in back_list,lb_backs))
        #mod_back =  list(filter(lambda i: i['name'] in back_list,mod_backs))

        for back in lb_backs:
            
            del back['serverDefaultSettings']['guid']
            mod_back, = list(filter(lambda i: i['name']==back['name'],mod_backs))
            #mod_servers = list(filter(lambda i: i['name']==back['name'],mod_serv))
            #raise Exception(mod_servers)
            if "default_settings" not in mod_back:
                mod_back["default_settings"] = self.default_settings
            else:
                for param,value in self.default_settings.items():
                    if param not in mod_back["default_settings"]:
                        mod_back["default_settings"].update(param,value)


            if "algorithm" not in mod_back:
                mod_back["algorithm"] = self.default_alg
            
            if back['serverDefaultSettings'] != mod_back["default_settings"] or\
                mod_back["algorithm"] != back['algorithm']:
                    api_params = dict(
                            lbId=self.lb_id,
                            backendName = back['name'],
                            algorithm = mod_back['algorithm'],
                            **mod_back['default_settings'],
                            )
                    api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendUpdate", api_params)
                    self.result['changed'] = True
            
            lb_servers_list = [srv['name'] for srv in back['servers']]
            for server in mod_serv:
                try:
                    mod_back, = list(filter(lambda i: i['name'] == back['name'],server['backends']))
                except:
                    continue
                if  server['name'] not in lb_servers_list:
                    api_params = dict(
                                lbId=self.lb_id,
                                backendName = mod_back['name'],
                                serverName = server['name'],
                                address = server['address'],
                                port = mod_back['port'],
                                check = server['check'] if "check" in server else None,
                                **server['server_settings'] if "server_settings" in server else {},
                                )
                    api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerAdd", api_params)
                    self.result['changed'] = True        
                else:
                    lb_server, = list(filter(lambda i: i['name'] == server['name'],back['servers']))
                    del lb_server['serverSettings']['guid']

                    if "server_settings" not in mod_back:
                        mod_back['server_settings'] = self.default_settings 
                    else:
                        for param,value in self.default_settings.items():
                            if param not in mod_back["server_settings"]:
                                mod_back["server_settings"].update(param,value)
                    
                    if "check" not in mod_back:
                        mod_back['check'] = self.default_server_check

                    if (server['address'] != lb_server['address'] or\
                        lb_server['check']!=mod_back['check']) or\
                        mod_back['server_settings'] != lb_server['serverSettings']:
                            api_params = dict(
                                lbId=self.lb_id,
                                backendName = mod_back['name'],
                                serverName = server['name'],
                                address = server['address'],
                                port = mod_back['port'],
                                check = mod_back['check'],
                                **mod_back['server_settings'],
                                )
                            api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerUpdate", api_params)
                            self.result['changed'] = True
                    lb_servers_list.remove(server['name'])
            for server in lb_servers_list:
                api_params = dict(lbId=self.lb_id,backendName = back['name'],serverName=server)
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/backendServerDelete", api_params)
                self.result['changed'] = True    
        return
    def _lb_update_fronts(self,upd_front_list,lb_frontends,mod_frontends):
        
        for front in upd_front_list:
            mod_front, = list(filter(lambda i: i['name'] == front,mod_frontends))
            lb_front, = list(filter(lambda i: i['name'] == front,lb_frontends))
            lb_binds_list = [bind['name'] for bind in lb_front['bindings']]
            for bind in mod_front['bindings']:
                if bind['name'] not in lb_binds_list:
                    pass
                    self._lb_bind_frontend(
                        front,
                        bind['name'],
                        bind['address']if "address" in bind else None,
                        bind['port'] if "port" in bind else None,
                )
                else:
                    lb_bind, = list(filter(lambda i: i['name'] == bind['name'],lb_front['bindings']))
                    del lb_bind['guid']

                    if dict(sorted(bind.items())) != dict(sorted(lb_bind.items())):
                        self._lb_bind_frontend(
                            front,
                            bind['name'],
                            bind['address']if "address" in bind else None,
                            bind['port'] if "port" in bind else None,
                            update=True,
                        )
                    lb_binds_list.remove(bind['name'])
            
            for lb_bind in lb_binds_list:
                api_params = dict(
                    lbId=self.lb_id,
                    frontendName=front,
                    bindingName=lb_bind,
                )
                api_resp = self.decort_api_call(requests.post, "/restmachine/cloudapi/lb/frontendBindDelete", api_params)
                self.result['changed'] = True    

        return
