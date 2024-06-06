#!/bin/bash

# These values are required to create OCI resources.
# Replace dummy values with your values and execute this script.

OCI_KEY_FILE_PATH=oci-key-file
OCI_PUBKEY_FINGERPRINT=oci-pubkey-fingerprint
OCI_REGION=oci-region
TENANCY_OCID=tenancy-ocid
TENANCY_NAME=tenancy-name
USER_OCID=user-ocid
OPENID_CONFIG_URL=openid-config-url
OCI_COMPARTMENT_NAME=oci-compartment-name
OCI_CLIENT_APPLICATION_ID=oci-client-application-id
## Path to file containing key policy
OCI_KEY_POLICY_FILE=oci-key-policy-file
## Path to file containing vault policy
OCI_VAULT_POLICY_FILE=oci-vault-policy-file

files=$(find . -name oci_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|oci-key-file|"$OCI_KEY_FILE_PATH"|g" ${arr[$a]}
	sed -i "s|oci-pubkey-fingerprint|"$OCI_PUBKEY_FINGERPRINT"|g" ${arr[$a]}
	sed -i "s|oci-region|"$OCI_REGION"|g" ${arr[$a]}
	sed -i "s|tenancy-ocid|"$TENANCY_OCID"|g" ${arr[$a]}
	sed -i "s|tenancy-name|"$TENANCY_NAME"|g" ${arr[$a]}
	sed -i "s|user-ocid|"$USER_OCID"|g" ${arr[$a]}
	sed -i "s|openid-config-url|"$OPENID_CONFIG_URL"|g" ${arr[$a]}
	sed -i "s|oci-compartment-name|"$OCI_COMPARTMENT_NAME"|g" ${arr[$a]}
	sed -i "s|oci-client-application-id|"$OCI_CLIENT_APPLICATION_ID"|g" ${arr[$a]}
	sed -i "s|oci-key-policy-file|"$OCI_KEY_POLICY_FILE"|g" ${arr[$a]}
	sed -i "s|oci-vault-policy-file|"$OCI_VAULT_POLICY_FILE"|g" ${arr[$a]}
done
