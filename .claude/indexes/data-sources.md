# Data source index

Every data source registered in [internal/provider/provider.go](../../internal/provider/provider.go) `DataSources()` (starts at line 756) → constructor file:line and Terraform type name. Update whenever you add or rename a data source.

## CipherTrust Manager core (cm/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_cm_users_list` | `cm.NewDataSourceUsers` | [cm/data_source_cm_users.go:24](../../internal/provider/cm/data_source_cm_users.go#L24) |
| `ciphertrust_cm_keys_list` | `cm.NewDataSourceKeys` | [cm/data_source_cm_keys.go:22](../../internal/provider/cm/data_source_cm_keys.go#L22) |
| `ciphertrust_cm_groups_list` | `cm.NewDataSourceGroups` | [cm/data_source_cm_groups.go:22](../../internal/provider/cm/data_source_cm_groups.go#L22) |
| `ciphertrust_cm_tokens_list` | `cm.NewDataSourceRegTokens` | [cm/data_source_cm_reg_tokens.go:23](../../internal/provider/cm/data_source_cm_reg_tokens.go#L23) |
| `ciphertrust_cm_local_ca_list` | `cm.NewDataSourceCertificateAuthorities` | [cm/data_source_cm_certificate_authorities.go:24](../../internal/provider/cm/data_source_cm_certificate_authorities.go#L24) |
| `ciphertrust_cm_prometheus_status` | `cm.NewDataSourcePrometheus` | [cm/data_source_cm_prometheus.go:23](../../internal/provider/cm/data_source_cm_prometheus.go#L23) |
| `ciphertrust_scheduler_list` | `cm.NewDataSourceScheduler` | [cm/data_source_scheduler.go:25](../../internal/provider/cm/data_source_scheduler.go#L25) |

(Note: there is also a `cm/data_source_trial_license.go` file but it's not currently registered in `provider.go`.)

## Connections (connections/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_aws_connection_list` | `connections.NewDataSourceAWSConnection` | [connections/data_source_aws_connection.go:24](../../internal/provider/connections/data_source_aws_connection.go#L24) |
| `ciphertrust_azure_connection_list` | `connections.NewDataSourceAzureConnection` | [connections/data_source_azure_connection.go:23](../../internal/provider/connections/data_source_azure_connection.go#L23) |
| `ciphertrust_gcp_connection_list` | `connections.NewDataSourceGCPConnection` | [connections/data_source_gcp_connection.go:23](../../internal/provider/connections/data_source_gcp_connection.go#L23) |
| `ciphertrust_oci_connection_list` | `connections.NewDataSourceOCIConnection` | [connections/data_source_oci_connection.go:31](../../internal/provider/connections/data_source_oci_connection.go#L31) |
| `ciphertrust_scp_connection_list` | `connections.NewDataSourceScpConnection` | [connections/data_source_scp_connection.go:23](../../internal/provider/connections/data_source_scp_connection.go#L23) |

## CCKM AWS (cckm/aws/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_aws_account_details` | `aws.NewDataSourceAWSAccountDetails` | [cckm/aws/data_source_aws_account_details.go:24](../../internal/provider/cckm/aws/data_source_aws_account_details.go#L24) |
| `ciphertrust_aws_keys_list` | `aws.NewDataSourceAWSKeys` | [cckm/aws/data_source_aws_keys_list.go:100](../../internal/provider/cckm/aws/data_source_aws_keys_list.go#L100) |
| `ciphertrust_aws_kms_list` | `aws.NewDataSourceAWSKms` | [cckm/aws/data_source_aws_kms_list.go:75](../../internal/provider/cckm/aws/data_source_aws_kms_list.go#L75) |
| `ciphertrust_aws_custom_keystore_list` | `aws.NewDataSourceAWSCustomKeyStore` | [cckm/aws/data_source_aws_custom_key_store_list.go:83](../../internal/provider/cckm/aws/data_source_aws_custom_key_store_list.go#L83) |
| `ciphertrust_aws_xks_keys_list` | `aws.NewDataSourceAWSXKSKeys` | [cckm/aws/data_source_aws_xks_keys_list.go:53](../../internal/provider/cckm/aws/data_source_aws_xks_keys_list.go#L53) |
| `ciphertrust_aws_cloudhsm_keys_list` | `aws.NewDataSourceAWSCloudHSMKeys` | [cckm/aws/data_source_aws_cloudhsm_keys_list.go:53](../../internal/provider/cckm/aws/data_source_aws_cloudhsm_keys_list.go#L53) |
| `ciphertrust_aws_key_rotation_list` | `aws.NewDataSourceAWSKeyRotationList` | [cckm/aws/data_source_aws_key_rotation_list.go:79](../../internal/provider/cckm/aws/data_source_aws_key_rotation_list.go#L79) |
| `ciphertrust_aws_iam_roles_list` | `aws.NewDataSourceAWSIAMRoles` | [cckm/aws/data_source_aws_iam_roles_list.go:26](../../internal/provider/cckm/aws/data_source_aws_iam_roles_list.go#L26) |
| `ciphertrust_aws_iam_users_list` | `aws.NewDataSourceAWSIAMUsers` | [cckm/aws/data_source_aws_iam_users_list.go:26](../../internal/provider/cckm/aws/data_source_aws_iam_users_list.go#L26) |

## CCKM OCI (cckm/oci/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_get_oci_regions` | `oci.NewDataSourceGetOCIRegions` | [cckm/oci/data_source_get_oci_regions.go:26](../../internal/provider/cckm/oci/data_source_get_oci_regions.go#L26) |
| `ciphertrust_get_oci_compartments` | `oci.NewDataSourceGetOCICompartments` | [cckm/oci/data_source_get_oci_compartments.go:26](../../internal/provider/cckm/oci/data_source_get_oci_compartments.go#L26) |
| `ciphertrust_get_oci_vaults` | `oci.NewDataSourceGetOCIVaults` | [cckm/oci/data_source_get_oci_vaults.go:26](../../internal/provider/cckm/oci/data_source_get_oci_vaults.go#L26) |
| `ciphertrust_get_oci_buckets` | `oci.NewDataSourceGetOCIBuckets` | [cckm/oci/data_source_get_oci_buckets.go:26](../../internal/provider/cckm/oci/data_source_get_oci_buckets.go#L26) |
| `ciphertrust_oci_compartments_list` | `oci.NewDataSourceOCICompartmentsList` | [cckm/oci/data_source_oci_compartments_list.go:71](../../internal/provider/cckm/oci/data_source_oci_compartments_list.go#L71) |
| `ciphertrust_oci_vault_list` | `oci.NewDataSourceOCIVault` | [cckm/oci/data_source_oci_vaults.go:87](../../internal/provider/cckm/oci/data_source_oci_vaults.go#L87) |
| `ciphertrust_oci_key_list` | `oci.NewDataSourceOCIKeys` | [cckm/oci/data_source_oci_keys.go:96](../../internal/provider/cckm/oci/data_source_oci_keys.go#L96) |
| `ciphertrust_oci_key_version_list` | `oci.NewDataSourceOCIVersions` | [cckm/oci/data_source_oci_key_versions.go:74](../../internal/provider/cckm/oci/data_source_oci_key_versions.go#L74) |

## CCKM Azure (cckm/azure/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_azure_subscription_details` | `azure.NewDataSourceAzureSubscriptionDetails` | [cckm/azure/data_source_azure_subscription_details.go:27](../../internal/provider/cckm/azure/data_source_azure_subscription_details.go#L27) |
| `ciphertrust_azure_subscription_list` | `azure.NewDataSourceAzureSubscriptionList` | [cckm/azure/data_source_azure_subscription_list.go:71](../../internal/provider/cckm/azure/data_source_azure_subscription_list.go#L71) |
| `ciphertrust_azure_vault_details` | `azure.NewDataSourceAzureVaultDetails` | [cckm/azure/data_source_azure_vault_details.go:28](../../internal/provider/cckm/azure/data_source_azure_vault_details.go#L28) |
| `ciphertrust_azure_vault_list` | `azure.NewDataSourceAzureVaultList` | [cckm/azure/data_source_azure_vault_list.go:81](../../internal/provider/cckm/azure/data_source_azure_vault_list.go#L81) |
| `ciphertrust_azure_key_list` | `azure.NewDataSourceAzureKeyList` | [cckm/azure/data_source_azure_key_list.go:66](../../internal/provider/cckm/azure/data_source_azure_key_list.go#L66) |
| `ciphertrust_azure_certificate_list` | `azure.NewDataSourceAzureCertificateList` | [cckm/azure/data_source_azure_certificate_list.go:64](../../internal/provider/cckm/azure/data_source_azure_certificate_list.go#L64) |
| `ciphertrust_azure_key_pit_backup_list` | `azure.NewDataSourceAzureKeyPitBackupList` | [cckm/azure/data_source_azure_key_pit_backup_list.go:54](../../internal/provider/cckm/azure/data_source_azure_key_pit_backup_list.go#L54) |

The key list schema lives in [cckm/azure/data_source_azure_key_list_schema.go](../../internal/provider/cckm/azure/data_source_azure_key_list_schema.go).

## CTE (cte/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_cte_clients_list` | `cte.NewDataSourceCTEClients` | [cte/data_source_cte_clients.go:23](../../internal/provider/cte/data_source_cte_clients.go#L23) |
| `ciphertrust_cte_client_group` | `cte.NewDataSourceCTEClientGroup` | [cte/data_source_cte_client_group.go:20](../../internal/provider/cte/data_source_cte_client_group.go#L20) |
| `ciphertrust_cte_client_group_clients_list` | `cte.NewDataSourceCTEClientGroupClients` | [cte/data_source_cte_client_group_clients_list.go:22](../../internal/provider/cte/data_source_cte_client_group_clients_list.go#L22) |
| `ciphertrust_cte_client_group_dp_set` | `cte.NewDataSourceCTEClientGroupDesignatedPrimarySet` | [cte/data_source_cte_client_group_designated_primary_set.go:21](../../internal/provider/cte/data_source_cte_client_group_designated_primary_set.go#L21) |
| `ciphertrust_cte_client_guardpoint` | `cte.NewDataSourceCTEClientGuardPoint` | [cte/data_source_cte_client_guardpoints.go:21](../../internal/provider/cte/data_source_cte_client_guardpoints.go#L21) |
| `ciphertrust_cte_clientgroup_guardpoint` | `cte.NewDataSourceCTEClientGroupGuardPoint` | [cte/data_source_cte_clientgroup_guardpoints.go:21](../../internal/provider/cte/data_source_cte_clientgroup_guardpoints.go#L21) |
| `ciphertrust_cte_csi_group` | `cte.NewDataSourceCTECSIGroup` | [cte/data_source_cte_csigroup.go:20](../../internal/provider/cte/data_source_cte_csigroup.go#L20) |
| `ciphertrust_ldt_comm_group_svc_list` | `cte.NewDataSourceLDTGroupCommSvc` | [cte/data_source_cte_ldtgroupcomms.go:20](../../internal/provider/cte/data_source_cte_ldtgroupcomms.go#L20) |
| `ciphertrust_cte_ldtcommgroup_clients_list` | `cte.NewDataSourceCTELDTGroupCommSvcClients` | [cte/data_source_cte_ldtgroupcomms_clients_list.go:22](../../internal/provider/cte/data_source_cte_ldtgroupcomms_clients_list.go#L22) |
| `ciphertrust_cte_policies_list` | `cte.NewDataSourceCTEPolicy` | [cte/data_source_cte_policies.go:20](../../internal/provider/cte/data_source_cte_policies.go#L20) |
| `ciphertrust_cte_policy_data_tx_rules` | `cte.NewDataSourceCTEPolicyDataTXRule` | [cte/data_source_cte_policy_datatxrules.go:21](../../internal/provider/cte/data_source_cte_policy_datatxrules.go#L21) |
| `ciphertrust_cte_policy_idt_key_rules` | `cte.NewDataSourceCTEPolicyIDTKeyRule` | [cte/data_source_cte_policy_idtkeyrules.go:21](../../internal/provider/cte/data_source_cte_policy_idtkeyrules.go#L21) |
| `ciphertrust_cte_policy_key_rules` | `cte.NewDataSourceCTEPolicyKeyRule` | [cte/data_source_cte_policy_keyrules.go:21](../../internal/provider/cte/data_source_cte_policy_keyrules.go#L21) |
| `ciphertrust_cte_policy_ldt_key_rules` | `cte.NewDataSourceCTEPolicyLDTKeyRule` | [cte/data_source_cte_policy_ldtkeyrules.go:21](../../internal/provider/cte/data_source_cte_policy_ldtkeyrules.go#L21) |
| `ciphertrust_cte_policy_security_rules` | `cte.NewDataSourceCTEPolicySecurityRule` | [cte/data_source_cte_policy_securityrules.go:21](../../internal/provider/cte/data_source_cte_policy_securityrules.go#L21) |
| `ciphertrust_cte_policy_signature_rules` | `cte.NewDataSourceCTEPolicySignatureRule` | [cte/data_source_cte_policy_signaturerules.go:21](../../internal/provider/cte/data_source_cte_policy_signaturerules.go#L21) |
| `ciphertrust_cte_process_sets` | `cte.NewDataSourceCTEProcessSets` | [cte/data_source_cte_process_sets.go:23](../../internal/provider/cte/data_source_cte_process_sets.go#L23) |
| `ciphertrust_cte_profiles` | `cte.NewDataSourceCTEProfiles` | [cte/data_source_cte_profiles.go:22](../../internal/provider/cte/data_source_cte_profiles.go#L22) |
| `ciphertrust_cte_resource_sets` | `cte.NewDataSourceCTEResourceSets` | [cte/data_source_cte_resource_sets.go:23](../../internal/provider/cte/data_source_cte_resource_sets.go#L23) |
| `ciphertrust_cte_signature_sets` | `cte.NewDataSourceCTESignatureSets` | [cte/data_source_cte_signature_sets.go:23](../../internal/provider/cte/data_source_cte_signature_sets.go#L23) |
| `ciphertrust_cte_usersets` | `cte.NewDataSourceCTEUserSets` | [cte/data_source_cte_user_sets.go:23](../../internal/provider/cte/data_source_cte_user_sets.go#L23) |
