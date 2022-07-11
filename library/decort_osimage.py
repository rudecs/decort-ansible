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
     Note that this module is effectively an information provisioner. It is not designed to and does not manage 
     nor change state of OS image (or any other) objects in DECORT cloud.
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
        - 'The specified image name will be looked up in the target DECORT controller and error will be generated
        - if no matching image is found.'
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
    vdc_id:
        description:
        - ID of the VDC to limit the search of the OS image to.
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
<<<<<<< HEAD
    account_name:
        description:
        - 'Account name. Used to get a unique integer account ID.'
        required: no
    virt_id:
        description:
        - 'A unique integer identifier for the virtual image.'
        - 'Can be used to obtain information about a virtual image, as well as to create a virtual image and 
        - bind another operating system image to it.'
        required: no
    virt_name:
        description:
        - 'Name of the virtual image. Used to get the `virt_id`, and later information about the virtual image, 
        - as well as to create a virtual image and bind another operating system image to it.'
        required: no
    state:
        description:
        - 'The state of the images. If set to present, operating system images will be created to which 
        - the account specified in `account_Id` or `account_name` is bound. If set to absent, they will be removed.
        required: no
    drivers:
        description:
        - 'A list of compute types (eg virtual servers) that are appropriate for the operating system image. 
        - Note: `KVM_X86`. Used when creating an operating system image.'
        required: no
    architecture:
        description:
        - 'Binary architecture of the image. Note. `X86_64` or `PPC64_LE`. Used when creating 
        -an operating system image.'
        required: no
    imagetype:
        description:
        - 'Image type. `linux`, `windows` or `other`. The default is `linux`. Used when creating
        - an operating system image.'
        required: no
    boottype:
        description:
        - 'Image upload type. `bios` or `uefi`. The default is `uefi`. Used when creating an operating 
        -system image.'
        required: no
    url:
        description:
        - 'Uniform resource locator (URL) pointing to the iso image of the operating system. Used when 
        -creating an operating system image.'
        required: no
    sepId:
        description:
        - 'The unique integer ID of the storage provider endpoint. Specified in pair with `poolName`. 
        - Used when creating an operating system image.'
        required: no
    poolName:
        description:
        - 'The pool in which the image will be created. Specified in pair with `sepId`. Used when creating
        - an operating system image.'
        required: no
    hotresize:
        description:
        - 'Whether the image supports "hot" resizing. The default is `false`. Used when creating an operating
        - system image.'
        required: no
    image_username:
        description:
        - 'An optional username for the image. Used when creating an operating system image.'
        required: no
    image_password:
        description:
        - 'An optional password for the image. Used when creating an operating system image. Used when creating
        - an operating system image.'
        required: no
    usernameDL:
        description:
        - 'The username for loading the binary media. Used in conjunction with `passwordDL`. Used when creating
        - an operating system image'
        required: no
    passwordDL:
        description:
        - 'The password for loading the binary media. Used in conjunction with `usernameDL`. Used when creating
        - an operating system image.'
        required: no
    permanently:
        description:
        - 'Whether to permanently delete the image. Used when deleting an image. The default is false.'
        required: no

=======
>>>>>>> parent of 28876ae (decort_osimage update)
'''

EXAMPLES = '''
- name: locate OS image specified by its name, store result in image_to_use variable.
    decort_osimage:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://ds1.digitalenergy.online"
      image_name: "Ubuntu 18.04 v1.2.5"
      account_name: "GreyseDevelopment"
    delegate_to: localhost
    register: image_to_use
'''

RETURN = '''
facts:
    description: facts about the specified OS image
    returned: always
    type: dict
    sample:
      facts:
        id: 100
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
                    state="CHECK_MODE",
                    )

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
        image_name=dict(type='str', required=True),
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
        account_name=dict(type='str', required=True),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        vdc_id=dict(type='int', required=False, default=0),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

# Workflow digest:
# 1) authenticate to DECORT controller & validate authentication by issuing API call - done when 
#    creating DecortController
# 2) obtain a list of OS images accessible to the specified account (and optionally - within 
#    the specified VDC)
# 3) match specified OS image by its name - if image is not found abort the module
# 5) report result to Ansible

def main():
    module_parameters = decort_osimage_parameters()

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

    # we need account ID to locate OS images - find the account by the specified name and get its ID
    validated_account_id, _ = decon.account_find(amodule.params['account_name'])
    if validated_account_id == 0:
        # we failed either to find or access the specified account - fail the module
        decon.result['failed'] = True
        decon.result['changed'] = False
        decon.result['msg'] = ("Cannot find account '{}'").format(amodule.params['account_name'])
        amodule.fail_json(**decon.result)

    image_id, image_facts = decon.image_find(image_id=0, image_name=amodule.params['image_name'], 
                                             account_id=validated_account_id, rg_id=0,
                                             sepid=amodule.params['sep_id'],
                                             pool=amodule.params['pool'])
    if decon.result['failed'] == True:
        # we failed to find the specified image - fail the module
        decon.result['changed'] = False
        amodule.fail_json(**decon.result)

    decon.result['facts'] = decort_osimage_package_facts(image_facts, amodule.check_mode)
    decon.result['changed'] = False # decort_osimage is a read-only module - make sure the 'changed' flag is set to False
    amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
