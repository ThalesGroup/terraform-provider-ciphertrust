#!/bin/bash

# These values are required to create Google Cloud EKM resources.
# Replace dummy values with your values and execute this script.

KEY_URI_HOSTNAME=key-uri-hostname
POLICY_CLIENT=policy-client
JUSTIFICATION_REASON=justification-reason
ATTESTATION_ZONE=attestation-zone
ATTESTATION_PROJECT_ID=attestation-project-id
ATTESTATION_INSTANCE_NAME=attestation-instance-name

files=$(find . -name gcp_ekm_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|attestation-instance-name|"$ATTESTATION_INSTANCE_NAME"|g" ${arr[$a]}
	sed -i "s|attestation-project-id|"$ATTESTATION_PROJECT_ID"|g" ${arr[$a]}
	sed -i "s|attestation-zone|"$ATTESTATION_ZONE"|g" ${arr[$a]}
	sed -i "s|justification-reason|"$JUSTIFICATION_REASON"|g" ${arr[$a]}
	sed -i "s|policy-client|"$POLICY_CLIENT"|g" ${arr[$a]}
	sed -i "s|key-uri-hostname|"$KEY_URI_HOSTNAME"|g" ${arr[$a]}
done
