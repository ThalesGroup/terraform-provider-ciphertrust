#!/bin/bash

# These values are required for to create Google Workspace CSE resources.
# Replace dummy values with your values and execute this script.

GCP_CSE_ISSUER=gcp-cse-issuer
GCP_CSE_JWKS_URL=gcp-cse-jwks-url
GCP_CSE_OPEN_ID_CONFIGURATION_URL=gcp-cse-open-id_configuration_url
GCP_CSE_AUTHENTICATION_AUDIENCE=gcp-cse-authentication-audience
GCP_CSE_ENDPOINT_URL_HOSTNAME=gcp-cse-endpoint-url-hostname

files=$(find . -name gcp_cse_vars.tf)
declare -a arr=($files)
for a in ${!arr[@]}; do
	echo Updating ${arr[$a]}
	sed -i "s|gcp-cse-issuer|"$GCP_CSE_ISSUER"|g" ${arr[$a]}
	sed -i "s|gcp-cse-jwks-url|"$GCP_CSE_JWKS_URL"|g" ${arr[$a]}
	sed -i "s|gcp-cse-open-id_configuration_url|"$GCP_CSE_OPEN_ID_CONFIGURATION_URL"|g" ${arr[$a]}
	sed -i "s|gcp-cse-authentication-audience|"$GCP_CSE_AUTHENTICATION_AUDIENCE"|g" ${arr[$a]}
	sed -i "s|gcp-cse-endpoint-url-hostname|"$GCP_CSE_ENDPOINT_URL_HOSTNAME"|g" ${arr[$a]}
done
