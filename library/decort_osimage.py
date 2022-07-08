#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
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
module: decort_osimage
short_description: Locate OS image in DCORT cloud by its name and return image ID
description: >
     This module can be used to obtain image ID of an OS image in DECORT cloud to use with subsequent calls to
     decort_vm module for batch VM provisioning. It will speed up VM creation and save a bunch of extra calls to
     DECORT cloud controller on each VM creation act.

version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT Python module
     - requests Python module
     - netaddr Python module
     - decort_utils utility library (module)
     - DECORT cloud platform version 3.6.1 or higher.
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECORT cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECORT cloud controller on which this JWT will be used.'
options:
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
        - URL of the DECORT controller that will be contacted to obtain OS image details.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    image_name:
        description:
        - Name of the OS image to use. Module will return the ID of this image.
        - 'The specified image name will be looked up in the target DECORT controller and error will be generated if
          no matching image is found.'
        required: yes
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
        - If not specified in the playbook, the value will be taken from DECORT_OAUTH2_URL environment variable.
    password:
        description:
        - 'Password for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required if I(authenticator=legacy) and ignored in other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_PASSWORD environment variable.
        required: no
    pool:
        description:
        - 'Name of the storage pool, where the image should be found.'
        - 'Omit this option if no matching by pool name is required. The first matching image will be returned."
        required: no
    sep_id:
        description:
        - 'ID of the SEP (Storage End-point Provider), where the image should be found.'
        - 'Omit this option if no matching by SEP ID is required. The first matching image will be returned."
        required: no
    account_name:
        description:
        - 'Name of the account for which the specified OS image will be looked up.'
        - 'This parameter is required for listing OS images.'
        required: yes
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



    account_name:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    virt_id:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    virt_name:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    state:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    drivers:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    architecture:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    imagetype:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    boottype:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    url:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    sepId:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    poolName:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    hotresize:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    image_username:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    image_password:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    usernameDL:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    passwordDL:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no
    permanently:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        required: no








'''

EXAMPLES = '''
  - name: create_osimage 
    decort_osimage:
      authenticator: oauth2
      verify_ssl: False
      controller_url: "https://ds1.digitalenergy.online"
      state: present
      image_name: "alpine_linux3.14.0"
      account_Id: 12345
      url: "https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-virt-3.14.0-x86_64.iso"
      boottype: "uefi"
      imagetype: "linux"
      hotresize: False
      image_username: "test"
      image_password: "p@ssw0rd"
      usernameDL: "testDL"
      passwordDL: "p@ssw0rdDL"
      architecture: "X86_64"
      drivers: "KVM_X86"
    delegate_to: localhost
    register: osimage

  - name: get_osimage 
    decort_osimage:
      authenticator: oauth2
      controller_url: "https://ds1.digitalenergy.online"
      image_name: "alpine_linux_3.14.0"
      account_Id: 12345
    delegate_to: localhost
    register: osimage

  - name: create_virtual_osimage 
    decort_osimage:
      authenticator: oauth2
      controller_url: "https://ds1.digitalenergy.online"
      image_name: "alpine_linux_3.14.0"
      virt_name: "alpine_last"
    delegate_to: localhost
    register: osimage

  - name: rename_osimage 
    decort_osimage:
      authenticator: oauth2
      controller_url: "https://ds1.digitalenergy.online"
      image_name: "alpine_linux_3.14.0v2.0"
      image_id: 54321
    delegate_to: localhost
    register: osimage



'''

RETURN = '''
facts:
    description: facts about the specified OS image
    returned: always
    type: dict
    sample:
      facts:
        id: 100
        linkto: 80
        name: "Ubuntu 16.04 v1.0"
        size: 3
        sep_id: 1
        pool: "vmstore"
        type: Linux
        arch: x86_64
        state: CREATED
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *

class decort_osimage(DecortController):
    def __init__(self,amodule):
        super(decort_osimage, self).__init__(amodule)

        self.validated_image_id = 0
        self.validated_virt_image_id = 0
        self.validated_image_name = amodule.params['image_name']
        self.validated_virt_image_name = None
        self.validated_virt_image_id = amodule.params['virt_id']
        if amodule.params['account_name']:
            self.validated_account_id, _ = self.account_find(amodule.params['account_name'])
        else:
            self.validated_account_id = amodule.params['account_Id']
        
        if self.validated_account_id == 0:
            # we failed either to find or access the specified account - fail the module
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = ("Cannot find account '{}'").format(amodule.params['account_name'])
            amodule.fail_json(**self.result)


        if amodule.params['image_id'] != 0 and amodule.params['image_name']:
            self.validated_image_id = amodule.params['image_id']
            if amodule.params['image_name']:
                decort_osimage.decort_image_rename(self,amodule)
                self.result['msg'] = ("Image renamed successfully")



    def decort_image_find(self, amodule):
        # function that finds the OS image
        image_id, image_facts = self.image_find(image_id=amodule.params['image_id'], image_name=self.validated_image_name,
                                                account_id=self.validated_account_id, rg_id=0,
                                                sepid=amodule.params['sep_id'],
                                                pool=amodule.params['pool'])
        return image_id, image_facts

    def decort_virt_image_find(self, amodule):
        # function that finds a virtual image
        image_id, image_facts = self.virt_image_find(image_id=amodule.params['virt_id'],
                                                    account_id=self.validated_account_id, rg_id=0,
                                                    sepid=amodule.params['sep_id'],
                                                    virt_name=amodule.params['virt_name'],
                                                    pool=amodule.params['pool'])
        return image_id, image_facts



    def decort_image_create(self,amodule):
        # function that creates OS image
        image_facts = self.image_create(img_name=self.validated_image_name, 
                        url=amodule.params['url'], 
                        gid=amodule.params['gid'], 
                        boottype=amodule.params['boottype'],
                        imagetype=amodule.params['imagetype'],
                        hotresize=amodule.params['hotresize'],
                        username=amodule.params['image_username'],
                        password=amodule.params['image_password'],
                        account_Id=amodule.params['account_Id'],
                        usernameDL=amodule.params['usernameDL'],
                        passwordDL=amodule.params['passwordDL'],
                        sepId=amodule.params['sepId'],
                        poolName=amodule.params['poolName'],
                        architecture=amodule.params['architecture'],
                        drivers=amodule.params['drivers'])
        self.result['changed'] = True
        return image_facts

    def decort_virt_image_link(self,amodule):
        # function that links an OS image to a virtual one
        self.virt_image_link(imageId=self.validated_virt_image_id, targetId=self.validated_image_id)
        image_id, image_facts = decort_osimage.decort_virt_image_find(self, amodule)
        self.result['facts'] = decort_osimage.decort_osimage_package_facts(image_facts, amodule.check_mode)
        self.result['msg'] = ("Image '{}' linked to virtual image '{}'").format(self.validated_image_id,
                                                                                decort_osimage.decort_osimage_package_facts(image_facts)['id'],)
        return image_id, image_facts
    
    def decort_image_delete(self,amodule):
        # function that removes an image
        self.image_delete(imageId=amodule.image_id_delete, permanently=amodule.params['permanently'])
        self.result['changed'] = True
        self.result['msg'] = ("Image '{}' deleted").format(amodule.image_id_delete)

    def decort_virt_image_create(self,amodule):
        # function that creates a virtual image
        image_facts = self.virt_image_create(name=amodule.params['virt_name'], targetId=self.validated_image_id)
        image_id, image_facts = decort_osimage.decort_virt_image_find(self, amodule)
        self.result['facts'] = decort_osimage.decort_osimage_package_facts(image_facts, amodule.check_mode)
        return image_id, image_facts
    
    def decort_image_rename(self,amodule):
        # image renaming function
        image_facts = self.image_rename(imageId=self.validated_image_id, name=amodule.params['image_name'])
        self.result['msg'] = ("Image renamed successfully")
        image_id, image_facts = decort_osimage.decort_image_find(self, amodule)
        return image_id, image_facts


    def decort_osimage_package_facts(arg_osimage_facts, arg_check_mode=False):
        """Package a dictionary of OS image according to the decort_osimage module specification. This
        dictionary will be returned to the upstream Ansible engine at the completion of the module run.

        @param arg_osimage_facts: dictionary with OS image facts as returned by API call to .../images/list
        @param arg_check_mode: boolean that tells if this Ansible module is run in check mode.

        @return: dictionary with OS image specs populated from arg_osimage_facts.
        """

        ret_dict = dict(id=0,
                        name="none",
                        size=0,
                        type="none",
                        state="CHECK_MODE",                        )

        if arg_check_mode:
            # in check mode return immediately with the default values
            return ret_dict

        if arg_osimage_facts is None:
            # if void facts provided - change state value to ABSENT and return
            ret_dict['state'] = "ABSENT"
            return ret_dict
    
        ret_dict['id'] = arg_osimage_facts['id']
        ret_dict['name'] = arg_osimage_facts['name']
        ret_dict['size'] = arg_osimage_facts['size']
        ret_dict['type'] = arg_osimage_facts['type']
        # ret_dict['arch'] = arg_osimage_facts['architecture']
        ret_dict['sep_id'] = arg_osimage_facts['sepId']
        ret_dict['pool'] = arg_osimage_facts['pool']
        ret_dict['state'] = arg_osimage_facts['status']
        ret_dict['linkto'] = arg_osimage_facts['linkTo']
        return ret_dict


    def decort_osimage_parameters():
        """Build and return a dictionary of parameters expected by decort_osimage module in a form accepted
        by AnsibleModule utility class."""

        return dict(
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
            pool=dict(type='str', required=False, default=""),
            sep_id=dict(type='int', required=False, default=0),
            account_name=dict(type='str', required=False),
            account_Id=dict(type='int', required=False),
            user=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_USER'])),
            verify_ssl=dict(type='bool', required=False, default=True),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),
            image_name=dict(type='str', required=False),
            image_id=dict(type='int', required=False,default=0),
            virt_id=dict(type='int', required=False, default=0),
            virt_name=dict(type='str', required=False),
            state=dict(type='str',
                   default='present',
                   choices=['absent', 'present']),
            drivers=dict(type='str', required=False, default="KVM_X86"),
            architecture=dict(type='str', required=False, default="X86_64"),
            imagetype=dict(type='str', required=False, default="linux"),
            boottype=dict(type='str', required=False, default="uefi"),
            url=dict(type='str', required=False),
            gid=dict(type='int', required=False, default=0),
            sepId=dict(type='int', required=False, default=0),
            poolName=dict(type='str', required=False),
            hotresize=dict(type='bool', required=False, default=False),
            image_username=dict(type='str', required=False),
            image_password=dict(type='str', required=False),
            usernameDL=dict(type='str', required=False),
            passwordDL=dict(type='str', required=False),
            permanently=dict(type='bool', required=False, default=False),
        )
        

def main():
    module_parameters = decort_osimage.decort_osimage_parameters()

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

    decon = decort_osimage(amodule)

    if amodule.params['image_name'] or amodule.params['image_id']:
        image_id, image_facts = decort_osimage.decort_image_find(decon, amodule)
        decon.validated_image_id = decort_osimage.decort_osimage_package_facts(image_facts)['id']
        if decort_osimage.decort_osimage_package_facts(image_facts)['id'] > 0:
            decon.result['facts'] = decort_osimage.decort_osimage_package_facts(image_facts, amodule.check_mode)

    if amodule.params['state'] == "present" and decon.validated_image_id == 0 and amodule.params['image_name'] and amodule.params['url']:
        decort_osimage.decort_image_create(decon,amodule)
        decon.result['changed'] = True
        image_id, image_facts = decort_osimage.decort_image_find(decon, amodule)
        decon.result['msg'] = ("OS image '{}' created").format(decort_osimage.decort_osimage_package_facts(image_facts)['id'])
        decon.result['facts'] = decort_osimage.decort_osimage_package_facts(image_facts, amodule.check_mode)
        decon.validated_image_id = decort_osimage.decort_osimage_package_facts(image_facts)['id']

    
    elif amodule.params['state'] == "absent" and amodule.params['image_name'] or amodule.params['image_id'] and decort_osimage.decort_osimage_package_facts(image_facts)['accountId'] == amodule.params['account_Id']:
        amodule.image_id_delete = decon.validated_image_id
        decort_osimage.decort_image_delete(decon,amodule)
    


    if amodule.params['virt_name'] or amodule.params['virt_id']:

        image_id, image_facts = decort_osimage.decort_virt_image_find(decon, amodule)
        if decort_osimage.decort_osimage_package_facts(image_facts)['id'] > 0:
            decon.result['facts'] = decort_osimage.decort_osimage_package_facts(image_facts, amodule.check_mode)
        decon.validated_virt_image_id = decort_osimage.decort_osimage_package_facts(image_facts)['id']
        decon.validated_virt_image_name = decort_osimage.decort_osimage_package_facts(image_facts)['name']


        if decort_osimage.decort_osimage_package_facts(image_facts)['id'] == 0 and amodule.params['state'] == "present" and decon.validated_image_id > 0:
            image_id, image_facts = decort_osimage.decort_virt_image_create(decon,amodule)
            decon.result['msg'] = ("Virtual image '{}' created").format(decort_osimage.decort_osimage_package_facts(image_facts)['id'])
            decon.result['changed'] = True
        elif decort_osimage.decort_osimage_package_facts(image_facts)['id'] == 0 and amodule.params['state'] == "present" and decon.validated_image_id == 0:
            decon.result['msg'] = ("Cannot find OS image")
            amodule.fail_json(**decon.result)


        if decon.validated_image_id:
            if decort_osimage.decort_osimage_package_facts(image_facts)['linkto'] != decon.validated_image_id:
                decort_osimage.decort_virt_image_link(decon,amodule)
                decon.result['changed'] = True
                amodule.exit_json(**decon.result)
        

        if decon.validated_virt_image_id > 0 and amodule.params['state'] == "absent":
            decon.result['msg'] = ("Osimage module cannot delete virtual images.")
            decon.result['failed'] = True
            amodule.exit_json(**decon.result)


    if decon.result['failed'] == True:
        # we failed to find the specified image - fail the module
        decon.result['changed'] = False
        amodule.fail_json(**decon.result)

    amodule.exit_json(**decon.result)

    
if __name__ == "__main__":
    main()
