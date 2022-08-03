#!/bin/bash

# These values are required for all scripts that require a DSM
# Replace dummy values with your values and execute this script.

# IPv4 address of the DSM
DSM_IP=dsm-ip
# Path the DSM certificate
DSM_SERVER_CERT_PATH=dsm-server-cert-path
# DSM Domain ID
DSM_DOMAIN=dsm-domain
# DSM Username
DSM_USERNAME=dsm-username
# DSM Password
DSM_PASSWORD=dsm-password

files=$(find . -name dsm_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|dsm-ip|"$DSM_IP"|g" ${arr[$a]}
	sed -i "s|dsm-server-cert-path|"$DSM_SERVER_CERT_PATH"|g" ${arr[$a]}
	sed -i "s|dsm-domain|"$DSM_DOMAIN"|g" ${arr[$a]}
	sed -i "s|dsm-password|"$DSM_PASSWORD"|g" ${arr[$a]}
	sed -i "s|dsm-username|"$DSM_USERNAME"|g" ${arr[$a]}
done
