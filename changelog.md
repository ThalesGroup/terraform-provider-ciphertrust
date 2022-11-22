# 0.9.0-beta8

## New Resources
    ciphertrust_gcp_acl
        Set access permissions for users and groups to Google Cloud keyrings.

## New Data Sources
	ciphertrust_gcp_keyring
		Reads the keyring.
		
## Changed Resources
	ciphertrust_gcp_key resource
		Removed gcp_cloud_resource_name.
		Renamed key_ring_id to keyring_id.
	ciphertrust_cm_key
		Added read only variable owner_id.
	ciphertrust_groups
		Added ability to add users to system groups.
	ciphertrust_gcp_keyring
		Renamed key_ring_id to keyring_id.

## Changed Data Sources
	ciphertrust_gcp_key resource
		Renamed key_ring_id to keyring_id.   
		Removed gcp_cloud_resource_name.

# 0.9.0-beta7

## Fixes:
    ciphertrust_cm_key 
        Added read-only linked_keys attribute.
        Linked keys are deleted when the resource is destroyed.     

# 0.9.0-beta6

## New Resources
    ciphertrust_proxy
    ciphertrust_interface

## Resources Updates
    ciphertrust_aws_key and ciphertrust_aws_policy_template
        key_admins_roles - Key policy administrator roles. New in Ciphertrust Manager v2.10.
        key_users_roles - Key policy user roles. New in Ciphertrust Manager v2.10.

    ciphertrust_azure_key
        exportable - Set to true to create an exportable key in Azure. Only valid for keys uploaded from hsm-luna. New in Ciphertrust Manager v2.10.

## Breaking Changes
    Previously when creating a ciphertrust_gwcse_endpoint resource, cse_identity_id was a string. It's now a list of strings.

# 0.9.0-beta5

## Breaking Changes
    Previously all 'meta' parameters were a string. Now they are a list of key:value pairs.

## New Resources
    ciphertrust_domain
    ciphertrust_user
    ciphertrust_ntp
    ciphertrust_groups
    ciphertrust_ekm_endpoint
    ciphertrust_gwcse_identity
    ciphertrust_gwcse_endpoint
    ciphertrust_google_project
    ciphertrust_license
    ciphertrust_syslog
    ciphertrust_log_forwarder
    ciphertrust_property

## Changed Resources
    ciphertrust_azure_vault
        managed_hsm - Set true to add a managed-hsm vault
    ciphertrust_cluster
    	Trial license activated during cluster creation
    ciphertrust_azure_key
        exportable - Create an exportable key in Azure. Only valid for keys uploaded from hsm-luna.
