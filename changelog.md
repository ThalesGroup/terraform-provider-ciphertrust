# 0.10.8-beta
## Updated Resources
    ciphertrust_cm_key
        name - 'ForceNew' has been applied to this attribute. 
               If the key name is changed the current key will be destroyed and a new key created.
               Note: The key must already be deletable for a name change to be successful. Either 'undeletable' must already be false, or if 'undeletable' is true, 'remove_from_state_on_destroy' must already be true.

# 0.10.7-beta

## Updated Provider Block

    cloud_key_manager {
        azure {
            purge_keys_on_delete:           Purge or only soft-delete keys on destroy. 
                                            Defaults to purge.
            recover_soft_deleted_keys:      Recover soft-deleted keys if an attempt is made to create a key of the same name. 
                                            Defaults to false.
            retain_key_backups_after_purge: Retain or remove Azure key backups from Ciphertrust allowing for a new key of the same 
                                            name to be created or allowing for the opportunity to restore keys from backups. 
                                            Defaults to retain key backups.
        }
    }

## Updated Resources
    ciphertrust_azure_key
        restore_key_id - "CipherTrust key ID of a key to restore to the specified vault. 
                         Keys can be restored in the AVAILABLE, SOFT-DELETED or DELETED states. 
                         Restoring keys in the AVAILABLE or SOFT_DELETED state is only valid for CipherTrust Manager versions >= 2.17 and they must be restored to a different vault." 
        name - 'ForceNew' has been applied to this attribute. If the key name is changed the current key will be destroyed and a new key created.   

## New Data Sources
    Added the ciphertrust_cm_key data source.

# 0.10.6-beta

## New Resources

    ciphertrust_ldap_connection
        Resource for creating a ldap connection on Ciphertrust Manager.

    ciphertrust_oidc_connection
        Resource for creating a oidc connection on Ciphertrust Manager.

    ciphertrust_smb_connection
        Resource for creating a smb connection on Ciphertrust Manager.

    ciphertrust_cte_profile
        A profile contains the CipherTrust Manager logging criteria for CTE clients.

    ciphertrust_cte_clientgroup
        A client group is used to group one or more clients to simplify configuration and administration. 

    ciphertrust_cte_registration_token
        This resource is used to create a CTE Registration Token used to register a CTE client with Ciphertrust Manager.
    
    ciphertrust_cte_csigroup
        An CSI storage group communication service contains a group of Kubernetes CTE clients that can communicate with each other.

    ciphertrust_cte_ldtgroupcomms
        An LDT group communication service contains a group of LDT-enabled CTE clients that can communicate with each other.

    ciphertrust_cte_resourcegroup
        A resource is a combination of a directory, a file, and patterns or special variables. A resource set is a named collection of directories, files, or both, that a user or process will be permitted or denied access to.

    ciphertrust_cte_user_set
        A user set is a collection of users and user groups that you want to grant or deny access to GuardPoints. User sets are configured in policies. Policies can be applied to user sets, not to individual users.

    ciphertrust_cte_process_set
        A process set is a collection of processes (executables) that you want to grant or deny access to GuardPoints.

    ciphertrust_cte_sig_set
        A signature set is a collection of hashes of processes and executables that you want to grant or deny access to GuardPoints.

## Updated Resources
    ciphertrust_cm_key
        remove_from_state_on_destroy - This parameter allows a ciphertrust_cm_key resource to be destroyed even if 'undeleteable' is true. 
        If remove_from_state_on_destroy is false, 'undeleteable' will have to be updated to false before it can be destroyed.
        Default is false.
    
    ciphertrust_cte_policies
        Added support for force_restrict_update flag for policy modifications.

# 0.10.5-beta

## New Resources
    Resource to support creating Oracle External Vaults and Keys:
        ciphertrust_oci_tenancy
        ciphertrust_oci_connection
        ciphertrust_oci_issuer
        ciphertrust_oci_external_vault
        ciphertrust_oci_acl
        ciphertrust_oci_external_key
        ciphertrust_oci_external_key_version

## New Data Sources
    Corresponding data sources for the above Oracle resources:
        ciphertrust_oci_tenancy
        ciphertrust_oci_external_key_versions
        ciphertrust_oci_connection
        ciphertrust_oci_external_vault
        ciphertrust_oci_external_key
        ciphertrust_oci_regions
    Added the ciphertrust_aws_kms data source

## Fixes
    Removed the possibility of nil pointer derefernce when destroying Azure keys.

## Documentation
    Updates for the new resources and data sources.
    Updates to existing azure_key_resource.

# 0.10.4-beta

## Documentation
    Published updated documentation.

# 0.10.3-beta

## New Data Source
    Added the ciphertrust_scheduler data source.

## Fixes
    ciphertrust_cm_key key_size will accept 128, 192 and 256 for AES keys.

## Documentation
    Added documentation for CipherTrust Data Security Platform as a Service (CDSPaaS).

# 0.10.2-beta

    Changed provider parameter `domain`'s default value from `root` to the empty string.
        The login behavior is unchanged because the appliance's backend uses `root` when the domain is not specified.

    Introduced provider parameter `auth_domain`
        CipherTrust authentication domain of the user. This is the domain where the user was created.

# 0.10.1-beta

    Documentation update.

# 0.10.0-beta

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

## Fixes
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
