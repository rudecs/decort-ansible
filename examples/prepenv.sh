#!/bin/bash

# 1. As this file will contain sensitive data (application ID & Secret pair) put this file 
#    in a directory, where only you will have access to it, e.g. your ~/.ssh directory.
# 2. Make sure this file is not readable by anybody else (chmod 400).
# 3. Paste your Application ID (obtained from DECORT SSO application) to DECORT_APP_ID.
# 4. Paste your Application Secret (obtained from DECORT SSO application) to DECORT_APP_SECRET.
# 5. Paste DECORT SSO application URL to DECORT_OAUTH2_URL.
#
# Source this file into shell to prepare environment for running DECORT Ansible module, e.g.
# . ~/.ssh/prepenv.sh
#
# More informaiton on DECORT Ansible module can be found at:
#   https://github.com/rudecs/decort-ansible/wiki
#

export DECORT_APP_ID="put your application ID here"
export DECORT_APP_SECRET="put your application secret here"
export DECORT_OAUTH2_URL="put DECORT SSO URL here" # "https://sso.digitalenergy.online"

export ANSIBLE_HOST_KEY_CHEKCING=False
