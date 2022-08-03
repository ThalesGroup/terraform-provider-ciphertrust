#!/bin/bash

# Most of these values are required to create Azure resources. Premium vault and pfx are not.
# Replace dummy values with your values and execute this script.

# Name of a non-premium Azure vault
AZURE_VAULT_NAME=azure-vault-name
# Name of a premium Azure vault
AZURE_PREMIUM_VAULT_NAME=azure-premium-vault-name
# Path to a PFX file to upload to Azure
AZURE_PFX_FILE_PATH="azure-pfx-file-path"
# PFX file password upload to Azure
AZURE_PFX_FILE_PASSWORD=azure-pfx-file-password

files=$(find . -name azure_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|azure-vault-name|"$AZURE_VAULT_NAME"|g" ${arr[$a]}
	sed -i "s|azure-premium-vault-name|"$AZURE_PREMIUM_VAULT_NAME"|g" ${arr[$a]}
	sed -i "s|azure-pfx-file-path|"$AZURE_PFX_FILE_PATH"|g" ${arr[$a]}
	sed -i "s|azure-pfx-file-password|"$AZURE_PFX_FILE_PASSWORD"|g" ${arr[$a]}
done
