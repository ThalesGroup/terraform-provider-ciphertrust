#!/bin/bash

# These values are required for all scripts that require a HSM Luna.
# Replace dummy values with your values and execute this script.

# IPv4 address of the HSM Luna
HSM_HOSTNAME=hsm-hostname
# Path to the HSM Luna certificate
HSM_SERVER_CERT_PATH=hsm-server-cert-path
# HSM Luna partition
HSM_PARTITION_LABEL=hsm-partition-label
# HSM Luna partition serial number
HSM_PARTITION_SN=hsm-partition-sn
# HSM Luna partition password
HSM_PARTITION_PASSWORD=hsm-partition-password

files=$(find . -name hsm_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|hsm-server-cert-path|"$HSM_SERVER_CERT_PATH"|g" ${arr[$a]}
	sed -i "s|hsm-hostname|"$HSM_HOSTNAME"|g" ${arr[$a]}
	sed -i "s|hsm-partition-password|"$HSM_PARTITION_PASSWORD"|g" ${arr[$a]}
	sed -i "s|hsm-partition-label|"$HSM_PARTITION_LABEL"|g" ${arr[$a]}
	sed -i "s|hsm-partition-sn|"$HSM_PARTITION_SN"|g" ${arr[$a]}
done
