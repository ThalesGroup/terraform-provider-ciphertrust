#!/bin/bash

# These values are required to create Google Cloud resources.
# Replace dummy values with your values and execute this script.

# Project name
GCP_PROJECT=gcp-project
# Qualified path to your keyring eg: projects/project-name/locations/global/keyRings/keyring-name
GCP_KEYRING=gcp-keyring
# Path to a service account key file
GCP_KEYFILE_PATH=/gcp-key-file.json

files=$(find . -name gcp_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|gcp-project|"$GCP_PROJECT"|g" ${arr[$a]}
	sed -i "s|gcp-keyring|"$GCP_KEYRING"|g" ${arr[$a]}
	sed -i "s|gcp-key-file-path|"$GCP_KEYFILE_PATH"|g" ${arr[$a]}
done
