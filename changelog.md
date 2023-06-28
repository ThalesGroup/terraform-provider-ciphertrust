# 0.9.0-beta10

## New Resources
    ciphertrust_aws_custom_keystore
        Used to create custom key store of type EXTERNAL_KEY_STORE, AWS_CLOUDHSM. 
        Supported from Ciphertrust Manager v2.12 onwards.
        It supports following:
            Allow creation of custom key store of type EXTERNAL_KEY_STORE in unlinked as well as linked mode
            For custom key store of type EXTERNAL_KEY_STORE following operations are supported:
                Keystore of EXTERNAL_KEY_STORE can be backed by Luna as key source or Ciphertrust Manager as key source 
                Allow connect, disconnect, block, unblock of custom key store
                Allow updation of attributes (as applicable for linked and unlinked key store)
            For custom key store of type AWS_CLOUDHSM following operations are supported:
                Allow connect, disconnect of custom key store
                Allow updation of attributes (as applicable for linked and unlinked key store)

    ciphertrust_aws_xks_key:
        Creates an AWS HYOK (XKS) key. Supported from Ciphertrust Manager v2.12 onwards.
        AWS HYOK key source tier and External Key Store key source tier need to match. 
        Following key sources are supported for AWS HYOK (XKS) key:
            Luna as key source
            Ciphertrust Manager as key source
        It supports following:
            Allow creation of AWS HYOK (XKS) key in unlinked as well as linked mode
            Allow block, unblock of AWS HYOK (XKS) key
            Allow updation of attributes (as applicable for linked and unlinked key)
    
    ciphertrust_virtual_key:
        Used to create an AWS HYOK (XKS) key with luna as key source in custom key store of type EXTERNAL_KEY_STORE. 
        Supported from Ciphertrust Manager v2.12 onwards.

    ciphertrust_aws_cloudhsm_key
        Used to create AWS key in custom key store of type AWS_CLOUDHSM. 
        Supported from Ciphertrust Manager v2.12 onwards.
        It supports following:
            Allow creation of CloudHSM key in AWS_CLOUDHSM key store.

    ciphertrust_cte_client
        Used to create a CTE Client on CM. A client is a computer system where the data needs to be protected.

    ciphertrust_cte_guardpoint
        Used to create a CTE GuardPoint on a CTE Client. A GuardPoint specifies the list of folders that contains paths to be protected. 
        Access to files and encryption of files under the GuardPoint is controlled by security policies.

    ciphertrust_cte_policies
        Used to create CTE policies on CM which can be used to add a guardpoint on CTE client. 
        A policy is a collection of rules that govern data access and encryption on CTE client.

## New Data Sources
    ciphertrust_aws_custom_keystore
        Reads a aws custom keystore resource
    ciphertrust_aws_xks_key
        Reads a aws xks (HYOK) key resource
    ciphertrust_virtual_key
        Reads a virtual key resource
    ciphertrust_aws_cloudhsm_key
        Reads a aws CloudHSM key resource

# 0.9.0-beta9

## New Resources
    ciphertrust_password_policy
        Updates CipherTrust Manager's global password policy
    ciphertrust_policies:
        Creates custom policies that:
            Allow a non-admin users add an AWS KMS
            Allow a non-admin users add an Azure vault
            Allow a non-admin users add a Google Cloud keyring
            Prevent users from exporting CipherTrust keys 
     ciphertrust_policy_attachments
        Used to attach ciphertrust_policies to principles, eg groups.

## New Data Sources
    ciphertrust-gcp-connection
        Reads a gcp connection resource

## Breaking changes
    ciphertrust_gcp_key
        enable_versions - has changed from a list of version id strings to a list of version numbers
        disable_versions - has changed from a list of version id strings to a list of version numbers

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
