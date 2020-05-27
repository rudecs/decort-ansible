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
module: decort_kvmvm
short_description: Manage KVM virtual machine in DECORT cloud
description: >
     This module can be used to create a KVM based virtual machine in Digital Energy cloud platform from a 
     specified OS image, modify virtual machine's CPU and RAM allocation, change its power state, configure
     network port forwarding rules, restart guest OS and delete a virtual machine thus releasing
     corresponding cloud resources.
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
        - 'ID of the account in which this VM will be created (for new VMs) or is located (for already
          existing VMs). This is the alternative to I(account_name) option.'
        - If both I(account_id) and I(account_name) specified, then I(account_name) is ignored.
        - If any one of I(vm_id) or I(rg_id) specified, I(account_id) is ignored.
        required: no
    account_name:
        description:
        - 'Name of the account in which this VM will be created (for new VMs) or is located (for already
           existing VMs).'
        - This parameter is ignored if I(account_id) is specified.
        - If any one of I(vm_id) or I(rg_id) specified, I(account_name) is ignored.
        required: no
    annotation:
        description:
        - Optional text description of this VM.
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
    arch:
        description:
        - Architecture of the KVM VM. DECORT supports KVM hosts based on Intel x86 and IBM PowerPC hardware.
        - This parameter is used when new KVM VM is created and ignored for all other operations.
        - Module may fail if your DECORT installation does not have physical nodes of specified architecture.
        default: KVM_X86
        choices: [ KVM_X86, KVM_PPC ]
        required: yes
    authenticator:
        description:
        - Authentication mechanism to be used when accessing DECORT controller and authorizing API call.
        default: jwt
        choices: [ jwt, oauth2, legacy ]
        required: yes
    boot_disk:
        description:
        - 'Boot disk size in GB. If this parameter is not specified for a new VM, the size of the boot disk 
          will be set to the size of the OS image, which this VM is based on.'
        - Boot disk is always created in the same storage and pool, as the OS image, which this VM is based on.
        - Boot disk cannot be detached from VM.
        required: no
    controller_url:
        description:
        - URL of the DECORT controller that will be contacted to manage the VM according to the specification.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    cpu:
        description:
        - Number of virtual CPUs to allocate for the VM.
        - This parameter is required for creating new VM and optional for other operations.
        - 'If you set this parameter for an existing VM, then the module will check if VM resize is necessary and do
          it accordingly. Note that resize operation on a running VM may generate errors as not all OS images support
          hot resize feature.'
        required: no
    id:
        description:
        - ID of the KVM VM to manage.
        - 'Either I(id) or a combination of VM name I(name) and RG related parameters (either I(rg_id) or a pair of
           I(account_name) and I(rg_name) is required to manage an existing VM.'
        - 'This parameter is not required (and ignored) when creating new VM as VM ID is assigned by cloud platform
           automatically and cannot be changed afterwards. If existing VM is identified by I(id), then I(account_id),
           I(account_name), I(rg_name) or I(rg_id) parameters will be ignored.'
        required: no
    image_id:
        description:
        - ID of the OS image to use for VM provisioning.
        - 'This parameter is valid at VM creation time only and is ignored for operations on existing VMs.'
        - 'You need to know image ID, e.g. by extracting it with decort_osimage module and storing
           in a variable prior to calling decort_kvmvm.'
        - 'If both I(image_id) and I(image_name) are specified, I(image_name) will be ignored.'
        required: no
    image_name:
        description:
        - Name of the OS image to use for a new VM provisioning.
        - 'This parameter is valid at VM creation time only and is ignored for operations on existing VMs.'
        - 'The specified image name will be looked up in the target DECORT controller and error will be generated if
          no matching image is found.'
        - 'If both I(image_id) and I(image_name) are specified, I(image_name) will be ignored.'
        required: no
    jwt:
        description:
        - 'JWT (access token) for authenticating to the DECORT controller when I(authenticator=jwt).'
        - 'This parameter is required if I(authenticator=jwt) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_JWT environment variable.
        required: no
    name:
        description:
        - Name of the VM.
        - 'To manage VM by I(name) you also need to specify either I(rg_id) or a pair of I(rg_name) and I(account_name).'
        - 'If both I(name) and I(id) are specified, I(name) will be ignored and I(id) used to locate the VM.'
        required: no
    networks:
        description:
        - List of dictionaries that specifies network connections for this VM.
        - Structure of each element is as follows:
        - ' - (string) type - type of the network connection. Supported types are VINS and EXTNET.'
        - ' - (int)    id - ID of the target network segment. It is ViNS ID for I(net_type=VINS) and
              external network segment ID for I(net_type=EXTNET)'
        - ' - (string) ip_addr - optional IP address to request for this connection. If not specified, the 
              platform will assign valid IP address automatically.'
        - 'If you call decort_kvmvm module for an existing VM, the module will try to reconfigure existing network
          connections according to the new specification.'
        - If this parameter is not specified, the VM will have no connections to the network(s).
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
    ram:
        description:
        - Size of RAM in MB to allocate to the VM.
        - This parameter is required for creating new VM and optional for other operations.
        - 'If you set this parameter for an existing VM, then the module will check if VM resize is necessary and do
          it accordingly. Note that resize operation on a running VM may generate errors as not all OS images support
          hot resize feature.'
        required: no
    ssh_key:
        description:
        - 'SSH public key to be deployed on to the new VM for I(ssh_key_user). If I(ssh_key_user) is not specified,
          the key will not be deployed, and a warning is generated.'
        - This parameter is valid at VM creation time only and ignored for any operation on existing VMs.
        required: no
    ssh_key_user:
        description:
        - User for which I(ssh_key) should be deployed.
        - If I(ssh_key) is not specified, this parameter is ignored and a warning is generated.
        - This parameter is valid at VM creation time only and ignored for any operation on existing VMs.
        required: no
    state:
        description:
        - Specify the desired state of the virtual machine at the exit of the module.
        - 'Regardless of I(state), if VM exists and is in one of [MIGRATING, DESTROYING, ERROR] states, do nothing.'
        - 'If desired I(state=check):'
        - ' - Just check if VM exists in any state and return its current specifications.'
        - ' - If VM does not exist, fail the task.'
        - 'If desired I(state=present):'
        - ' - VM does not exist, create the VM according to the specifications and start it.'
        - ' - VM in one of [RUNNING, PAUSED, HALTED] states, attempt resize if necessary, change network if necessary.'
        - ' - VM in DELETED state, restore and start it.'
        - ' - VM in DESTROYED state, recreate the VM according to the specifications and start it.'
        - 'If desired I(state=poweredon):'
        - ' - VM does not exist, create it according to the specifications.'
        - ' - VM in RUNNING state, attempt resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, attempt resize if necessary, change network if necessary, next
              start the VM.'
        - ' - VM in DELETED state, restore it.'
        - ' - VM in DESTROYED state, create it according to the specifications.'
        - 'If desired I(state=absent):'
        - ' - VM in one of [RUNNING, PAUSED, HALTED] states, destroy it.'
        - ' - VM in one of [DELETED, DESTROYED] states, do nothing.'
        - 'If desired I(state=paused):'
        - ' - VM in RUNNING state, pause the VM, resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, resize if necessary, change network if necessary.'
        - ' - VM in one of [DELETED, DESTROYED] states, abort with an error.'
        - 'If desired I(state=poweredoff) or I(state=halted):'
        - ' - VM does not exist, create the VM according to the specifications and leave it in HALTED state.'
        - ' - VM in RUNNING state, stop the VM, resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, resize if necessary, change network if necessary.'
        - ' - VM in DELETED state, abort with an error.'
        - ' - VM in DESTROYED state, recreate the VM according to the specifications and leave it in HALTED state.'
        default: present
        choices: [ present, absent, poweredon, poweredoff, halted, paused, check ]
    tags:
        description:
        - String of custom tags to be assigned to the VM (This feature is not implemented yet!).
        - These tags are arbitrary text that can be used for grouping or indexing the VMs by other applications.
        required: no
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_USER environment variable.
        required: no
    rg_id:
        description:
        - ID of the Resource Group where a new VM will be deployed or an existing VM can be found.
        - 'This parameter may be required when managing VM by its I(name). If you specify I(rg_id), then
          I(account_name), I(account_id) and I(rg_name) will be ignored.'
        required: no
    rg_name:
        description:
        - Name of the RG where the VM will be deployed (for new VMs) or can be found (for existing VMs).
        - This parameter is required when managing VM by its I(name).
        - If both I(rg_id) and I(rg_name) are specified, I(rg_name) will be ignored.
        - If I(rg_name) is specified, then either I(account_name) or I(account_id) must also be set.
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
- name: create a VM named "SimpleVM" in the DECORT cloud along with VDC named "ANewVDC" if it does not exist yet.
    decort_kvmvm:
      annotation: "VM managed by decort_kvmvm module"
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: SimpleVM
      cpu: 2
      ram: 4096
      boot_disk:
        size: 10
        model: ovs
        pool: boot
      image_name: "Ubuntu 16.04 v1.1"
      data_disks:
        - size: 50
          model: ovs
          pool: data
      port_forwards:
        - ext_port: 21022
          int_port: 22
          proto: tcp
        - ext_port: 80
          int_port: 80
          proto: tcp
      state: present
      tags: "PROJECT:Ansible STATUS:Test"
      account_name: "Development"
      rg_name: "ANewVDC"
    delegate_to: localhost
    register: simple_vm
- name: resize the above VM to CPU 4 and remove port forward rule for port number 80.
    decort_kvmvm:
      authenticator: jwt
      jwt: "{{ MY_JWT }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: SimpleVM
      cpu: 4
      ram: 4096
      port_forwards:
        - ext_port: 21022
          int_port: 22
          proto: tcp
      state: present
      account_name: "Development"
      rg_name: "ANewVDC"
    delegate_to: localhost
    register: simple_vm
- name: stop existing VM identified by the VM ID and down size it to CPU:RAM 1:2048 along the way.
    decort_kvmvm:
      authenticator: jwt
      jwt: "{{ MY_JWT }}"
      controller_url: "https://ds1.digitalenergy.online"
      id: "{{ TARGET_VM_ID }}"
      cpu: 1
      ram: 2048
      state: poweredoff
    delegate_to: localhost
    register: simple_vm
- name: check if VM exists and read in its specs.
    decort_kvmvm:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: "{{ TARGET_VM_NAME }}"
      rg_name: "{{ TARGET_VDC_NAME }}"
      account_name: "{{ TRAGET_TENANT }}"
      state: check
    delegate_to: localhost
    register: existing_vm
'''

RETURN = '''
facts:
    description: facts about the virtual machine that may be useful in the playbook
    returned: always
    type: dict
    sample:
      facts:
        id: 9454
        name: TestVM
        state: RUNNING
        username: testuser
        password: Yab!tWbyPF
        int_ip: 192.168.103.253
        rg_name: SandboxVDC
        rg_id: 2883
        vdc_ext_ip: 185.193.143.151
        ext_ip: 185.193.143.106
        ext_netmask: 24
        ext_gateway: 185.193.143.1
        ext_mac: 52:54:00:00:1a:24
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decort_utils import *

class decort_kvmvm(DecortController):
    def __init__(self, arg_amodule):
        # call superclass constructor first
        super(decort_kvmvm, self).__init__(arg_amodule)

        self.comp_should_exist = False
        self.comp_id = 0
        self.comp_info = None
        self.acc_id = 0
        self.rg_id = 0

        validated_acc_id =0
        validated_rg_id = 0
        validated_rg_facts = None

        # Analyze Compute name & ID, RG name & ID and build arguments to compute_find accordingly.
        if arg_amodule.params['name'] == "" and arg_amodule.params['id'] == 0:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = "Cannot manage Compute when its ID is 0 and name is empty."
            self.fail_json(**self.result)
            # fail the module - exit

        if not arg_amodule.params['id']: # manage Compute by name -> need RG identity
            if not arg_amodule.params['rg_id']: # RG ID is not set -> locate RG by name -> need account ID
                validated_acc_id, _ = self.account_find(arg_amodule.params['account_name'],
                                                        arg_amodule.params['account_id'])
                if not validated_acc_id:
                    self.result['failed'] = True
                    self.result['changed'] = False
                    self.result['msg'] = ("Current user does not have access to the account ID {} / "
                                          "name '{}' or non-existent account specified.").format(arg_amodule.params['account_id'],
                                                                                                 arg_amodule.params['account_name'])
                    self.fail_json(**self.result)
                    # fail the module -> exit
            # now validate RG
            validated_rg_id, validated_rg_facts = self.rg_find(validated_acc_id,
                                                               arg_amodule.params['rg_id'],
                                                               arg_amodule.params['rg_name'])
            if not validated_rg_id:
                self.result['failed'] = True
                self.result['changed'] = False
                self.result['msg'] = "Cannot find RG ID {} / name '{}'.".format(arg_amodule.params['rg_id'],
                                                                                arg_amodule.params['rg_name'])
                self.fail_json(**self.result)
                # fail the module - exit

            self.rg_id = validated_rg_id
            arg_amodule.params['rg_id'] = validated_rg_id
            arg_amodule.params['rg_name'] = validated_rg_facts['name']
            self.acc_id = validated_rg_facts['accountId']

        # at this point we are ready to locate Compute, and if anything fails now, then it must be
        # because this Compute does not exist or something goes wrong in the upstream API
        # We call compute_find with check_state=False as we also consider the case when a Compute
        # specified by account / RG / compute name never existed and will be created for the first time.
        self.comp_id, self.comp_info, self.rg_id = self.compute_find(comp_id=arg_amodule.params['id'],
                                                                     comp_name=arg_amodule.params['name'],
                                                                     rg_id=validated_rg_id,
                                                                     check_state=False)

        if self.comp_id:
            if self.comp_info['status'] != 'DESTROYED' and self.comp_info['arch'] not in ["KVM_X86", "KVM_PPC"]:
                # If we found a Compute in a non-DESTROYED state and it is not of type KVM_*, abort the module
                self.result['failed'] = True
                self.result['msg'] = ("Compute ID {} architecture '{}' is not supported by "
                                      "decort_kvmvm module.").format(self.comp_id, 
                                                                     self.amodule.params['arch'])
                self.amodule.fail_json(**self.result)
                # fail the module - exit
            self.comp_should_exist = True
            self.acc_id = self.comp_info['accountId']

        return

    def nop(self):
        """No operation (NOP) handler for Compute management by decort_kvmvm module.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual Compute state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.comp_id:
            self.result['msg'] = ("No state change required for Compute ID {} because of its "
                                   "current status '{}'.").format(self.comp_id, self.comp_info['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent Compute instance.").format(self.amodule.params['state'])
        return

    def error(self):
        """Error handler for Compute instance management by decort_kvmvm module.
        This function is intended to be called when an invalid state change is requested.
        Invalid means that the current is invalid for any operations on the Compute or the 
        transition from current to desired state is not technically possible.
        """
        self.result['failed'] = True
        self.result['changed'] = False
        if self.comp_id:
            self.result['msg'] = ("Invalid target state '{}' requested for Compute ID {} in the "
                                   "current status '{}'.").format(self.comp_id,
                                                                  self.amodule.params['state'],
                                                                  self.comp_info['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent Compute name '{}' "
                                   "in RG ID {} / name '{}'").format(self.amodule.params['state'],
                                                                    self.amodule.params['name'],
                                                                    self.amodule.params['rg_id'],
                                                                    self.amodule.params['rg_name'])
        return

    def create(self):
        """New Compute instance creation handler for decort_kvmvm module.
        This function checks for the presence of required parameters and deploys a new KVM VM
        Compute instance with the specified characteristics into the target Resource Group.
        The target RG must exist.
        """
        # the following parameters must be present: cpu, ram, image_id or image_name
        # each of the following calls will abort if argument is missing
        self.check_amodule_argument('cpu')
        self.check_amodule_argument('ram')

        if self.amodule.params['arch'] not in ["KVM_X86", "KVM_PPC"]:
            self.result['failed'] = True
            self.result['msg'] = ("Unsupported architecture '{}' is specified for "
                                  "KVM VM create.").format(self.amodule.params['arch'])
            self.amodule.fail_json(**self.result)
            # fail the module - exit

        validated_bdisk_size = 0

        image_facts = None
        # either image_name or image_id must be present
        if self.check_amodule_argument('image_id', abort=False) and self.amodule.params['image_id'] > 0 :
            # find image by image ID and account ID
            # image_find(self, image_id, image_name, account_id, rg_id=0, sepid=0, pool=""):
            _, image_facts = self.image_find(image_id=self.amodule.params['image_id'],
                                             image_name="",
                                             account_id=self.acc_id)
        elif self.check_amodule_argument('image_name', abort=False) and self.amodule.params['image_name'] != "":
            # find image by image name and account ID
            _, image_facts = self.image_find(image_id=0,
                                             image_name=self.amodule.params['image_name'],
                                             account_id=self.acc_id)
        else:
            # neither image_name nor image_id are set - abort the script
            self.result['failed'] = True
            self.result['msg'] = "Missing both 'image_name' and 'image_id'. You need to specify one to create a Compute."
            self.amodule.fail_json(**self.result)
            # fail the module - exit

        if ((not self.check_amodule_argument('boot_disk', False)) or 
            self.amodule.params['boot_disk'] <= image_facts['size']):
            # adjust disk size to the minimum allowed by OS image, which will be used to spin off this Compute
            validated_bdisk_size = image_facts['size']
        else:
            validated_bdisk_size =self.amodule.params['boot_disk']

        start_compute = True
        if self.amodule.params['state'] in ('halted', 'poweredoff'):
            start_compute = False
        
        if self.amodule.params['ssh_key'] and self.amodule.params['ssh_key_user']:
            cloud_init_params = {'users': [
                {"name": self.amodule.params['ssh_key_user'],
                    "ssh-authorized-keys": [self.amodule.params['ssh_key']],
                    "shell": '/bin/bash'}
                ]}
        else:
            cloud_init_params = None

        # if we get through here, all parameters required to create new Compute instance should be at hand

        self.comp_id = self.compute_provision(rg_id=self.rg_id, 
                                    comp_name=self.amodule.params['name'], arch=self.amodule.params['arch'],
                                    cpu=self.amodule.params['cpu'], ram=self.amodule.params['ram'],
                                    boot_disk=validated_bdisk_size,
                                    image_id=image_facts['id'],
                                    annotation=self.amodule.params['annotation'],
                                    userdata=cloud_init_params,
                                    start_on_create=start_compute)
        self.comp_should_exist = True

        # 
        # Compute was created
        #
        # Setup network connections
        self.compute_networks(self.comp_info, self.amodule.params['networks']) 
        # Next manage data disks
        self.compute_data_disks(self.comp_info, self.amodule.params['data_disks'])
        # read in Compute facts after all initial setup is complete
        _, self.comp_info, _ = self.compute_find(comp_id=self.comp_id)

        return

    def destroy(self):
        """Compute destroy handler for VM management by decort_kvmvm module.
        Note that this handler deletes the VM permanently together with all assigned disk resources.
        """
        self.compute_delete(comp_id=self.comp_id, permanently=True)
        self.comp_info['status'] = 'DESTROYED'
        self.comp_should_exist = False
        return

    def restore(self):
        """Compute restore handler for Compute instance management by decort_kvmvm module.
        Note that restoring Compute is only possible if it is in DELETED state. If called on a 
        Compute instance in any other state, the method will throw an error and abort the execution
        of the module.
        """
        self.compute_restore(comp_id=self.comp_id)
        # TODO - do we need updated comp_info to manage port forwards and size after VM is restored?
        _, self.comp_info, _ = self.compute_find(comp_id=self.comp_id)
        self.modify()
        self.comp_should_exist = True
        return

    def modify(self, arg_wait_cycles=0):
        """Compute modify handler for KVM VM management by decort_kvmvm module.
        This method is a convenience wrapper that calls individual Compute modification functions from
        DECORT utility library (module).
        """
        self.compute_networks(self.comp_info, self.amodule.params['networks'])
        self.compute_bootdisk_size(self.comp_info, self.amodule.params['boot_disk'])
        self.compute_data_disks(self.comp_info, self.amodule.params['data_disks'])
        self.compute_resize(self.comp_info,
                            self.amodule.params['cpu'], self.amodule.params['ram'],
                            wait_for_state_change=arg_wait_cycles)
        return

    def package_facts(self, check_mode=False):
        """Package a dictionary of KVM VM facts according to the decort_kvmvm module specification. 
        This dictionary will be returned to the upstream Ansible engine at the completion of decort_kvmvm 
        module run.

        @param check_mode: boolean that tells if this Ansible module is run in check mode

        @return: dictionary of KVM VM facts, containing suffucient information to manage the KVM VM in
        subsequent Ansible tasks.
        """

        ret_dict = dict(id=0,
                    name="",
                    arch="",
                    cpu="",
                    ram="",
                    disk_size=0,
                    data_disks=[],  # IDs of attached data disks; this list can be emty
                    state="CHECK_MODE",
                    account_id=0,
                    rg_id=0,
                    username="",
                    password="",
                    public_ips=[],  # direct IPs; this list can be empty
                    private_ips=[], # IPs on ViNSes; usually, at least one IP is listed
                    nat_ip="",      # IP of the external ViNS interface; can be empty.
                    )

        if check_mode or self.comp_info is None:
            # if in check mode (or void facts provided) return immediately with the default values
            return ret_dict

        # if not self.comp_should_exist:
        #    ret_dict['state'] = "ABSENT"
        #    return ret_dict

        ret_dict['id'] = self.comp_info['id']
        ret_dict['name'] = self.comp_info['name']
        ret_dict['arch'] = self.comp_info['arch']
        ret_dict['state'] = self.comp_info['status']
        ret_dict['account_id'] = self.comp_info['accountId']
        ret_dict['rg_id'] = self.comp_info['rgId']
        # if the VM is an imported VM, then the 'accounts' list may be empty,
        # so check for this case before trying to access login and passowrd values
        if len(self.comp_info['osUsers']):
            ret_dict['username'] = self.comp_info['osUsers'][0]['login']
            ret_dict['password'] = self.comp_info['osUsers'][0]['password']

        if self.comp_info['interfaces']:
            # We need a list of all ViNSes in the account, which owns this Compute
            # to find a ViNS, which may have active external connection. Then
            # we will save external IP address of that connection in ret_dict['nat_ip']

            for iface in self.comp_info['interfaces']:
                if iface['connType'] == "VXLAN": # This is ViNS connection
                    ret_dict['private_ips'].append(iface['ipAddress'])
                    # if iface['connId']
                    # Now we need to check if this ViNS has GW function and external connection.
                    # If it does - save public IP address of GW VNF in ret_dict['nat_ip']
                elif iface['connType'] == "VLAN": # This is direct external network connection
                    ret_dict['public_ips'].append(iface['ipAddress'])
            
        ret_dict['cpu'] = self.comp_info['cpus']
        ret_dict['ram'] = self.comp_info['ram']

        ret_dict['image_id'] = self.comp_info['imageId']

        for ddisk in self.comp_info['disks']:
            if ddisk['type'] == 'B':
                # if it is a boot disk - store its size
                ret_dict['disk_size'] = ddisk['maxSize']
            elif ddisk['type'] == 'D':
                # if it is a data disk - append its ID to the list of data disks IDs
                ret_dict['data_disks'].append(ddisk['id'])

        return ret_dict

    @staticmethod
    def build_parameters():
        """Build and return a dictionary of parameters expected by decort_kvmvm module in a form
        accepted by AnsibleModule utility class.
        This dictionary is then used y AnsibleModule class instance to parse and validate parameters
        passed to the module from the playbook.
        """

        return dict(
            account_id=dict(type='int', required=False, default=0),
            account_name=dict(type='str', required=False, default=''),
            annotation=dict(type='str',
                            default='',
                            required=False),
            app_id=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECORT_APP_ID'])),
            app_secret=dict(type='str',
                            required=False,
                            fallback=(env_fallback, ['DECORT_APP_SECRET']),
                            no_log=True),
            arch=dict(type='str', choices=['KVM_X86', 'KVM_PPC'], default='KVM_X86'),
            authenticator=dict(type='str',
                               required=True,
                               choices=['legacy', 'oauth2', 'jwt']),
            boot_disk=dict(type='int', required=False),
            controller_url=dict(type='str', required=True),
            # count=dict(type='int', required=False, default=1),
            cpu=dict(type='int', required=False),
            # datacenter=dict(type='str', required=False, default=''),
            data_disks=dict(type='list', default=[], required=False), # list of integer disk IDs
            id=dict(type='int', required=False, default=0),
            image_id=dict(type='int', required=False),
            image_name=dict(type='str', required=False),
            jwt=dict(type='str',
                     required=False,
                     fallback=(env_fallback, ['DECORT_JWT']),
                     no_log=True),
            name=dict(type='str'),
            networks=dict(type='list', default=[], required=False), # list of dictionaries
            oauth2_url=dict(type='str',
                            required=False,
                            fallback=(env_fallback, ['DECORT_OAUTH2_URL'])),
            password=dict(type='str',
                          required=False,
                          fallback=(env_fallback, ['DECORT_PASSWORD']),
                          no_log=True),
            ram=dict(type='int', required=False),
            rg_id=dict(type='int', default=0),
            rg_name=dict(type='str', default=""),
            ssh_key=dict(type='str', required=False),
            ssh_key_user=dict(type='str', required=False),
            state=dict(type='str',
                       default='present',
                       choices=['absent', 'paused', 'poweredoff', 'halted', 'poweredon', 'present', 'check']),
            tags=dict(type='str', required=False),
            user=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_USER'])),
            verify_ssl=dict(type='bool', required=False, default=True),
            # wait_for_ip_address=dict(type='bool', required=False, default=False),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),
        )

# Workflow digest:
# 1) authenticate to DECORT controller & validate authentication by issuing API call - done when creating DECSController
# 2) check if the VM with the specified id or rg_name:name exists
# 3) if VM does not exist, check if there is enough resources to deploy it in the target account / vdc
# 4) if VM exists: check desired state, desired configuration -> initiate action accordingly
# 5) VM does not exist: check desired state -> initiate action accordingly
#       - create VM: check if target VDC exists, create VDC as necessary, create VM
#       - delete VM: delete VM
#       - change power state: change as required
#       - change guest OS state: change as required
# 6) report result to Ansible

def main():
    module_parameters = decort_kvmvm.build_parameters()

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
                            required_one_of=[
                                ['id', 'name'],
                            ],
                            )

    # Initialize DECORT KVM VM instance object
    # This object does not necessarily represent an existing KVM VM
    subj = decort_kvmvm(amodule)

    # handle state=check before any other logic
    if amodule.params['state'] == 'check':
        subj.result['changed'] = False
        if subj.comp_id:
            # Compute is found - package facts and report success to Ansible
            subj.result['failed'] = False
            subj.comp_info = subj.compute_find(comp_id=subj.comp_id)
            _, rg_facts = subj.rg_find(rg_id=subj.rg_id)
            subj.result['facts'] = subj.package_facts(rg_facts, amodule.check_mode)
            amodule.exit_json(**subj.result)
            # we exit the module at this point
        else:
            subj.result['failed'] = True
            subj.result['msg'] = ("Cannot locate Compute name '{}'. Other arguments are: Compute ID {}, "
                                  "RG name '{}', RG ID {}, Account '{}'.").format(amodule.params['name'],
                                                                                amodule.params['id'],
                                                                                amodule.params['rg_name'],
                                                                                amodule.params['rg_id'],
                                                                                amodule.params['account_name'])
            amodule.fail_json(**subj.result)
            pass

    if subj.comp_id:
        if subj.comp_info['status'] in ("MIGRATING", "DESTROYING", "ERROR"):
            # nothing to do for an existing Compute in the listed states regardless of the requested state
            subj.nop()
        elif subj.comp_info['status'] == "RUNNING":
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present', 'poweredon'):
                # check port forwards / check size / nop
                subj.modify()
            elif amodule.params['state'] in ('paused', 'poweredoff', 'halted'):
                # pause or power off the vm, then check port forwards / check size
                subj.compute_powerstate(subj.comp_info, amodule.params['state'])
                subj.modify(arg_wait_cycles=7)
        elif subj.comp_info['status'] in ("PAUSED", "HALTED"):
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present', 'paused', 'poweredoff', 'halted'):
                subj.modify()
            elif amodule.params['state'] == 'poweredon':
                subj.modify()
                subj.compute_powerstate(subj.comp_info, amodule.params['state'])
        elif subj.comp_info['status'] == "DELETED":
            if amodule.params['state'] in ('present', 'poweredon'):
                # TODO - check if restore API returns VM ID (similarly to VM create API)
                subj.compute_restore(comp_id=subj.comp_id)
                # TODO - do we need updated comp_info to manage port forwards and size after VM is restored?
                _, subj.comp_info, _ = subj.compute_find(comp_id=subj.comp_id)
                subj.modify()
            elif amodule.params['state'] == 'absent':
                subj.nop()
                subj.comp_should_exist = False
            elif amodule.params['state'] in ('paused', 'poweredoff', 'halted'):
                subj.error()
        elif subj.comp_info['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'poweredon', 'poweredoff', 'halted'):
                subj.create()
                # TODO: Network setup?
                # TODO: Data disks setup?
            elif amodule.params['state'] == 'absent':
                subj.nop()
                subj.comp_should_exist = False
            elif amodule.params['state'] == 'paused':
                subj.error()
    else:
        # Preexisting Compute of specified identity was not found.
        # If requested state is 'absent' - nothing to do
        if amodule.params['state'] == 'absent':
            subj.nop()
        elif amodule.params['state'] in ('present', 'poweredon', 'poweredoff', 'halted'):
            subj.create()
            # TODO: Network setup?
            # TODO: Data disks setup?
        elif amodule.params['state'] == 'paused':
            subj.error()

    if subj.result['failed']:
        amodule.fail_json(**subj.result)
    else:
        # prepare Compute facts to be returned as part of decon.result and then call exit_json(...)
        rg_facts = None
        if subj.comp_should_exist:
            if subj.result['changed']:
                # There were changes to the Compute - refresh Compute facts.
                _, subj.comp_info, _ = subj.compute_find(comp_id=subj.comp_id)
            #
            # TODO: check if we really need to get RG facts here in view of DNF implementation
            # we need to extract RG facts regardless of 'changed' flag, as it is our source of information on
            # the VDC external IP address
            _, rg_facts = subj.rg_find(arg_rg_id=subj.rg_id)
        subj.result['facts'] = subj.package_facts(rg_facts, amodule.check_mode)
        amodule.exit_json(**subj.result)


if __name__ == "__main__":
    main()
