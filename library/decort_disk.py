#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2020 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: decort_disk
short_description: Manage Disks (virtualized storage resources) in DECORT cloud
description: >
     This module can be used to create new disk in DECORT cloud platform, obtain or 
     modify its characteristics, and delete it.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT module
     - requests module
     - decort_utils utility library (module)
     - DECORT cloud platform version 3.4.1 or higher
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECORT cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECORT cloud controller on which this JWT will be used.'
options:
    account_id:
        description:
        - ID of the account, which owns this disk. This is the alternative to I(account_name) option.
        - If both I(account_id) and I(account_name) specified, then I(account_name) is ignored.
        default: 0
        required: no
    account_name:
        description:
        - 'Name of the account, which will own this disk.'
        - 'This parameter is ignored if I(account_id) is specified.'
        default: empty string
        required: no
    annotation:
        description:
        - Optional text description of this disk.
        default: empty string
        required: no
    app_id:
        description:
        - 'Application ID for authenticating to the DECORT controller when I(authenticator=oauth2).'
        - 'Required if I(authenticator=oauth2).'
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_ID
           environment variable.'
        required: no
    app_secret:
        description:
        - 'Application API secret used for authenticating to the DECORT controller when I(authenticator=oauth2).'
        - This parameter is required when I(authenticator=oauth2) and ignored in other modes.
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_SECRET
           environment variable.'
        required: no
    authenticator:
        description:
        - Authentication mechanism to be used when accessing DECORT controller and authorizing API call.
        default: jwt
        choices: [ jwt, oauth2, legacy ]
        required: yes
    controller_url:
        description:
        - URL of the DECORT controller that will be contacted to manage the RG according to the specification.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    id:
        description:
        - `ID of the disk to manage. If I(id) is specified it is assumed, that this disk already
          exists. In other words, you cannot create new disk by specifying its ID, use I(name)
          when creating new disk.`
        - `If non-zero I(id) is specified, then I(name), I(account_id) and I(account_name) 
          are ignored.`
        default: 0
        required: no
    name:
        description:
        - `Name of the disk to manage. To manage disk by name you also need to specify either
          I(account_id) or I(account_name).`
        - If non-zero I(id) is specified, I(name) is ignored.
        - `Note that the platform does not enforce uniqueness of disk names, so if more than one
          disk with this name exists under the specified account, module will return the first
          occurence.`
        default: empty string
        required: no
    force_detach:
        description:
        - `By default it is not allowed to delete or destroy disk that is currently attached to a compute
          instance (e.g. virtual machine or bare metal server). Set this argument to true to change this
          behavior.`
        - This argument is meaningful for I(state=absent) operations only and ignored otherwise.
        default: false
        required: no
    jwt:
        description:
        - 'JWT (access token) for authenticating to the DECORT controller when I(authenticator=jwt).'
        - 'This parameter is required if I(authenticator=jwt) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_JWT environment variable.
        required: no
    oauth2_url:
        description:
        - 'URL of the oauth2 authentication provider to use when I(authenticator=oauth2).'
        - 'This parameter is required when when I(authenticator=oauth2).'
        - 'If not specified in the playbook, the value will be taken from DECORT_OAUTH2_URL environment variable.'
    password:
        description:
        - 'Password for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required if I(authenticator=legacy) and ignored in other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_PASSWORD environment variable.
        required: no
    place_with:
        description:
        - `This argument can be used to simplify data disks creation along with a new compute, by placing
          disks in the same storage, where corresponding OS image is deployed.`
        - `Specify ID of an OS image, and the newly created disk will be provisioned from the same
          storage, where this OS image is located. You may optionally specify I(pool) to control
          actual disk placement within that storage, or leave I(pool=default) to let platform manage
          it automatically.`
        - This parameter is used when creating new disks and ignored for all other operations.
        - This is an alternative to specifying I(sep_id).
        default: 0
        required: no
    pool:
        description:
        - Name of the pool where to place new disk. Once disk is created, its pool cannot be changed.
        - This parameter is used when creating new disk and igonred for all other operations.
        default: default
        required: no
    sep_id:
        description:
        - `ID of the Storage Endpoint Provider (SEP) where to place new disk. Once disk is created, 
          its SEP cannot be changed.`
        - `You may think of SEP as an identifier of a storage system connected to DECORT platform. There
          may be several different storage systems and, consequently, several SEPs available to choose from.`
        - This parameter is used when creating new disk and igonred for all other operations.
        - See also I(place_with) for an alternative way to specify disk placement.
        default: 0
        required: no
    size:
        description:
        - Size of the disk in GB. This parameter is mandatory when creating new disk.
        - `If specified for an existing disk, and it is greater than current disk size, platform will try to resize
          the disk on the fly. Downsizing disk is not allowed.`
        required: no
    state:
        description:
        - Specify the desired state of the disk at the exit of the module.
        - 'If desired I(state=present):'
        - ' - Disk does not exist or is in [DESTROYED, PURGED] states, create new disk according to the specifications.'
        - ' - Disk is in DELETED state, restore it and change size if necessary.'
        - ' - Disk is in one of [CREATED, ASSIGNED] states, do nothing.'
        - ' - Disk in any other state, abort with an error.'
        - 'If desired I(state=absent):'
        - ' - Disk is in one of [CREATED, ASSIGNED, DELETED] states, destroy it.'
        - ' - Disk not found or in [DESTROYED, PURGED] states, do nothing.' 
        - ' - Disk in any other state, abort with an error.'
        default: present
        choices: [ absent, present ]
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_USER environment variable.
        required: no
    verify_ssl:
        description:
        - 'Controls SSL verification mode when making API calls to DECORT controller. Set it to False if you
         want to disable SSL certificate verification. Intended use case is when you run module in a trusted
         environment that uses self-signed certificates. Note that disabling SSL verification in any other
         scenario can lead to security issues, so please know what you are doing.'
        default: True
        required: no
    workflow_callback:
        description:
        - 'Callback URL that represents an application, which invokes this module (e.g. up-level orchestrator or
          end-user portal) and may except out-of-band updates on progress / exit status of the module run.'
        - API call at this URL will be used to relay such information to the application.
        - 'API call payload will include module-specific details about this module run and I(workflow_context).'
        required: no
    workflow_context:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        - 'This context data is expected to uniquely identify the task carried out by this module invocation so
           that up-level orchestrator could match returned information to the its internal entities.'
        required: no
'''

EXAMPLES = '''
- name: create new Disk named "MyDataDisk01" of size 50 GB, on SEP ID 1, in default pool, under the account "MyAccount".
    decort_vins:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://cloud.digitalenergy.online"
      name: "MyDataDisk01"
      sep_id: 1
      pool: "default"
      size: 50
      account_name: "MyAccount"
      state: present
    delegate_to: localhost
    register: my_disk
'''

RETURN = '''
facts:
    description: facts about the disk
    returned: always
    type: dict
    sample:
      facts:
        id: 50
        name: data01
        size: 10
        sep_id: 1
        pool: datastore
        state: ASSIGNED
        account_id: 7
        attached_to: 18
        gid: 1001
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *


def decort_disk_package_facts(disk_facts, check_mode=False):
    """Package a dictionary of disk facts according to the decort_disk module specification. 
    This dictionary will be returned to the upstream Ansible engine at the completion of 
    the module run.

    @param (dict) disk_facts: dictionary with Disk facts as returned by API call to .../disks/get
    @param (bool) check_mode: boolean that tells if this Ansible module is run in check mode
    """

    ret_dict = dict(id=0,
                    name="none",
                    state="CHECK_MODE",
                    size=0,
                    account_id=0,
                    sep_id=0,
                    pool="none",
                    attached_to=0,
                    gid=0
                    )

    if check_mode:
        # in check mode return immediately with the default values
        return ret_dict

    if disk_facts is None:
        # if void facts provided - change state value to ABSENT and return
        ret_dict['state'] = "ABSENT"
        return ret_dict

    ret_dict['id'] = disk_facts['id']
    ret_dict['name'] = disk_facts['name']
    ret_dict['size'] = disk_facts['sizeMax']
    ret_dict['state'] = disk_facts['status']
    ret_dict['account_id'] = disk_facts['accountId']
    ret_dict['sep_id'] = disk_facts['sepid']
    ret_dict['pool'] = disk_facts['pool']
    ret_dict['attached_to'] = disk_facts['vmid']
    ret_dict['gid'] = disk_facts['gid']

    return ret_dict

def decort_disk_parameters():
    """Build and return a dictionary of parameters expected by decort_disk module in a form accepted
    by AnsibleModule utility class."""

    return dict(
        account_id=dict(type='int', required=False, default=0),
        account_name=dict(type='str', required=False, default=''),
        annotation=dict(type='str', required=False, default='Disk by decort_disk'),
        app_id=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_APP_ID'])),
        app_secret=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECORT_APP_SECRET']),
                        no_log=True),
        authenticator=dict(type='str',
                           required=True,
                           choices=['legacy', 'oauth2', 'jwt']),
        controller_url=dict(type='str', required=True),
        id=dict(type='int', required=False, default=0),
        name=dict(type='str', required=False),
        force_detach=dict(type='bool', required=False, default=False),
        jwt=dict(type='str',
                 required=False,
                 fallback=(env_fallback, ['DECORT_JWT']),
                 no_log=True),
        oauth2_url=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECORT_OAUTH2_URL'])),
        password=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_PASSWORD']),
                      no_log=True),
        place_with=dict(type='int', required=False, default=0),
        pool=dict(type='str', required=False, default='default'),
        sep_id=dict(type='int', required=False, default=0),
        size=dict(type='int', required=False),
        state=dict(type='str',
                   default='present',
                   choices=['absent', 'present']),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

def main():
    module_parameters = decort_disk_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,
                            mutually_exclusive=[
                                ['oauth2', 'password'],
                                ['password', 'jwt'],
                                ['jwt', 'oauth2'],
                            ],
                            required_together=[
                                ['app_id', 'app_secret'],
                                ['user', 'password'],
                            ],
                            )

    decon = DecortController(amodule)

    disk_id = 0
    disk_facts = None # will hold Disk facts
    validated_acc_id = 0
    acc_facts = None # will hold Account facts

    if amodule.params['id']:
        # expect existing Disk with the specified ID
        # This call to disk_find will abort the module if no Disk with such ID is present
        disk_id, disk_facts = decon.disk_find(amodule.params['id'])
        if not disk_id:
            decon.result['failed'] = True
            decon.result['msg'] = "Specified Disk ID {} not found.".format(amodule.params['id'])
            amodule.fail_json(**decon.result)
        validated_acc_id =disk_facts['accountId']
    elif amodule.params['account_id'] > 0 or amodule.params['account_name'] != "":
        # Make sure disk name is specified, if not - fail the module
        if amodule.params['name'] == "":
            decon.result['failed'] = True
            decon.result['msg'] = ("Cannot manage disk if both ID is 0 and disk name is empty.")
            amodule.fail_json(**decon.result)
        # Specified account must be present and accessible by the user, otherwise abort the module 
        validated_acc_id, acc_facts = decon.account_find(amodule.params['account_name'], amodule.params['account_id'])
        if not validated_acc_id:
            decon.result['failed'] = True
            decon.result['msg'] = ("Current user does not have access to the requested account "
                                    "or non-existent account specified.")
            amodule.fail_json(**decon.result)
        # This call to disk_find may return disk_id=0 if no Disk with this name found in 
        disk_id, disk_facts = decon.disk_find(disk_id=0, disk_name=amodule.params['name'],
                                                account_id=validated_acc_id,
                                                check_state=False)
    else: 
        # this is "invalid arguments combination" sink
        # if we end up here, it means that module was invoked with disk_id=0 and undefined account
        decon.result['failed'] = True
        if amodule.params['account_id'] == 0 and amodule.params['account_name'] == "":
            decon.result['msg'] = "Cannot find Disk by name when account name is empty and account ID is 0."
        if amodule.params['name'] == "":
            decon.result['msg'] = "Cannot find Disk by empty name."
        amodule.fail_json(**decon.result)

    #
    # Initial validation of module arguments is complete
    #
    # At this point non-zero disk_id means that we will be managing pre-existing Disk
    # Otherwise we are about to create a new disk
    #
    # Valid Disk model statii are as follows:
    # 
    # "CREATED", "ASSIGNED", DELETED", "DESTROYED", "PURGED"
    # 

    disk_should_exist = False
    target_sep_id = 0
    target_pool = "default"
    
    if disk_id:
        disk_should_exist = True
        if disk_facts['status'] in ["MODELED", "CREATING" ]:
            # error: nothing can be done to existing Disk in the listed statii regardless of
            # the requested state
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing Disk ID {} because of its current "
                                   "status '{}'").format(disk_id, disk_facts['status'])
        elif disk_facts['status'] in ["CREATED", "ASSIGNED"]:
            if amodule.params['state'] == 'absent':
                decon.disk_delete(disk_id, True, amodule.params['force_detach']) # delete permanently
                disk_facts['status'] = 'DESTROYED'
                disk_should_exist = False
            elif amodule.params['state'] == 'present':
                # resize Disk as necessary & if possible
                if decon.check_amodule_argument('size', False):
                    decon.disk_resize(disk_facts, amodule.params['size'])
        elif disk_facts['status'] == "DELETED":
            if amodule.params['state'] == 'present':
                # restore
                decon.disk_restore(disk_id)
                _, disk_facts = decon.disk_find(disk_id)
                decon.disk_resize(disk_facts, amodule.params['size'])
                disk_should_exist = True
            elif amodule.params['state'] == 'absent':
                # destroy permanently
                decon.disk_delete(disk_id, permanently=True)
                disk_facts['status'] = 'DESTROYED'
                disk_should_exist = False
        elif disk_facts['status'] in ["DESTROYED", "PURGED"]:
            if amodule.params['state'] == 'present':
                # Need to re-provision this Disk.
                # Some attributes may change, some must stay the same:
                # - disk name  - stays, take from disk_facts
                # - account ID - stays, take from validated account ID
                # - size       - may change, take from module arguments
                # - SEP ID     - may change, build based on module arguments
                # - pool       - may change, take from module arguments
                # - annotation - may change, take from module arguments
                #
                # First validate required parameters:
                decon.check_amodule_argument('size') # this will fail the module if size is not specified
                target_sep_id = 0
                if decon.check_amodule_argument('sep_id', False) and amodule.params['sep_id'] > 0:
                    # non-zero sep_id is explicitly passed in module arguments
                    target_sep_id = amodule.params['sep_id']
                elif decon.check_amodule_argument('place_with', False) and amodule.params['place_with'] > 0:
                    # request to place this disk on the same SEP as the specified OS image
                    # validate specified OS image and assign SEP ID accordingly
                    image_id, image_facts = decon.image_find(amodule.params['place_with'], "", 0)
                    target_sep_id = image_facts['sepid']
                else:
                    # no new SEP ID is explicitly specified, and no place_with option - use sep_id from the disk_facts
                    target_sep_id = disk_facts['sepid']
                disk_id = decon.disk_provision(disk_name=disk_facts['name'], # as this disk was found, its name is in the facts
                                               size=amodule.params['size'],
                                               account_id=validated_acc_id, 
                                               sep_id=target_sep_id,
                                               pool=amodule.params['pool'],
                                               desc=amodule.params['annotation'],
                                               location="")
                disk_should_exist = True
            elif amodule.params['state'] == 'absent':
                # nop
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for Disk ID {} because of its "
                                       "current status '{}'").format(disk_id,
                                                                     disk_facts['status'])
                disk_should_exist = False
    else:
        # disk_id =0 -> pre-existing Disk was not found.
        disk_should_exist = False  # we will change it back to True if Disk is created successfully
        # If requested state is 'absent' - nothing to do
        if amodule.params['state'] == 'absent':
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do as target state 'absent' was requested for "
                                   "non-existent Disk name '{}'").format(amodule.params['name'])
        elif amodule.params['state'] == 'present':
            decon.check_amodule_argument('name') # if disk name not specified, fail the module 
            decon.check_amodule_argument('size') # if disk size not specified, fail the module

            # as we already have account ID, we can create Disk and get disk id on success
            if decon.check_amodule_argument('sep_id', False) and amodule.params['sep_id'] > 0:
                # non-zero sep_id is explicitly passed in module arguments
                target_sep_id = amodule.params['sep_id']
            elif decon.check_amodule_argument('place_with', False) and amodule.params['place_with'] > 0:
                # request to place this disk on the same SEP as the specified OS image
                # validate specified OS image and assign SEP ID accordingly
                image_id, image_facts = decon.image_find(amodule.params['place_with'], "", 0)
                target_sep_id = image_facts['sepid']
            else:
                # no SEP ID is explicitly specified, and no place_with option - we do not know where
                # to place the new disk - fail the module
                decon.result['failed'] = True
                decon.result['msg'] = ("Cannot create new Disk name '{}': no SEP ID specified and "
                                       "no 'place_with' option used.").format(amodule.params['name'])
                amodule.fail_json(**decon.result)
            
            disk_id = decon.disk_provision(disk_name=amodule.params['name'],
                                            size=amodule.params['size'],
                                            account_id=validated_acc_id, 
                                            sep_id=target_sep_id,
                                            pool=amodule.params['pool'],
                                            desc=amodule.params['annotation'],
                                            location="")
            disk_should_exist = True            
        elif amodule.params['state'] == 'disabled':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "Disk name '{}'").format(amodule.params['state'],
                                                            amodule.params['name'])
    
    #
    # conditional switch end - complete module run
    #
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        # prepare Disk facts to be returned as part of decon.result and then call exit_json(...)
        if disk_should_exist:
            if decon.result['changed']:
                # If we arrive here, there is a good chance that the Disk is present - get fresh Disk
                # facts by Disk ID.
                # Otherwise, Disk facts from previous call (when the Disk was still in existence) will
                # be returned.
                _, disk_facts = decon.disk_find(disk_id)
        decon.result['facts'] = decort_disk_package_facts(disk_facts, amodule.check_mode)
        amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
