# Resource index

Every resource registered in [internal/provider/provider.go](../../internal/provider/provider.go) → constructor file:line and Terraform type name. The TF type name shown is what users write in `.tf` (the literal value of `resp.TypeName` after `Metadata()` sets it).

> Update this file whenever you add or rename a resource constructor.

## CipherTrust Manager core (cm/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_user` | `cm.NewResourceCMUser` | [cm/resource_cm_user.go:24](../../internal/provider/cm/resource_cm_user.go#L24) |
| `ciphertrust_cm_key` | `cm.NewResourceCMKey` | [cm/resource_cm_key.go:30](../../internal/provider/cm/resource_cm_key.go#L30) |
| `ciphertrust_groups` | `cm.NewResourceCMGroup` | [cm/resource_cm_group.go:24](../../internal/provider/cm/resource_cm_group.go#L24) |
| `ciphertrust_cm_reg_token` | `cm.NewResourceCMRegToken` | [cm/resource_cm_reg_token.go:25](../../internal/provider/cm/resource_cm_reg_token.go#L25) |
| `ciphertrust_cm_ssh_key` | `cm.NewResourceCMSSHKey` | [cm/resource_cm_ssh_key.go:24](../../internal/provider/cm/resource_cm_ssh_key.go#L24) |
| `ciphertrust_cm_user_password_change` | `cm.NewResourceCMPwdChange` | [cm/resource_cm_user_pwd_change.go:21](../../internal/provider/cm/resource_cm_user_pwd_change.go#L21) |
| `ciphertrust_hsm_root_of_trust_setup` | `cm.NewResourceHSMRootOfTrustServer` | [cm/resource_hsm_rot.go:27](../../internal/provider/cm/resource_hsm_rot.go#L27) |
| `ciphertrust_cluster` | `cm.NewResourceCMCluster` | [cm/resource_cm_cluster.go:29](../../internal/provider/cm/resource_cm_cluster.go#L29) |
| `ciphertrust_cluster_node` | `cm.NewResourceCMClusterNode` | [cm/resource_cm_cluster_node.go:58](../../internal/provider/cm/resource_cm_cluster_node.go#L58) |
| `ciphertrust_interface` | `cm.NewResourceCMInterface` | [cm/resource_interface.go:28](../../internal/provider/cm/resource_interface.go#L28) |
| `ciphertrust_interface_certificate_renewal` | `cm.NewResourceInterfaceCertificateRenewal` | [cm/resource_interface_certificate_renewal.go:32](../../internal/provider/cm/resource_interface_certificate_renewal.go#L32) |
| `ciphertrust_license` | `cm.NewResourceCMLicense` | [cm/resource_license.go:27](../../internal/provider/cm/resource_license.go#L27) |
| `ciphertrust_ntp` | `cm.NewResourceCMNTP` | [cm/resource_ntp.go:27](../../internal/provider/cm/resource_ntp.go#L27) |
| `ciphertrust_trial_license` | `cm.NewResourceCMTrialLicense` | [cm/resource_trial_license.go:25](../../internal/provider/cm/resource_trial_license.go#L25) |
| `ciphertrust_cm_prometheus` | `cm.NewResourceCMPrometheus` | [cm/resource_cm_prometheus.go:22](../../internal/provider/cm/resource_cm_prometheus.go#L22) |
| `ciphertrust_scheduler` | `cm.NewResourceScheduler` | [cm/resource_scheduler.go:62](../../internal/provider/cm/resource_scheduler.go#L62) |
| `ciphertrust_domain` | `cm.NewResourceCMDomain` | [cm/resource_cm_domain.go:26](../../internal/provider/cm/resource_cm_domain.go#L26) |
| `ciphertrust_log_forwarder` | `cm.NewResourceCMLogForwarders` | [cm/resource_log_forwarder.go:27](../../internal/provider/cm/resource_log_forwarder.go#L27) |
| `ciphertrust_password_policy` | `cm.NewResourceCMPasswordPolicy` | [cm/resource_password_policy.go:25](../../internal/provider/cm/resource_password_policy.go#L25) |
| `ciphertrust_policies` | `cm.NewResourceCMPolicy` | [cm/resource_policy.go:26](../../internal/provider/cm/resource_policy.go#L26) |
| `ciphertrust_policy_attachments` | `cm.NewResourceCMPolicyAttachment` | [cm/resource_policy_attachments.go:25](../../internal/provider/cm/resource_policy_attachments.go#L25) |
| `ciphertrust_property` | `cm.NewResourceCMProperty` | [cm/resource_property.go:25](../../internal/provider/cm/resource_property.go#L25) |
| `ciphertrust_proxy` | `cm.NewResourceCMProxy` | [cm/resource_proxy.go:23](../../internal/provider/cm/resource_proxy.go#L23) |
| `ciphertrust_syslog` | `cm.NewResourceCMSyslog` | [cm/resource_syslog.go:27](../../internal/provider/cm/resource_syslog.go#L27) |

## Connections (connections/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_aws_connection` | `connections.NewResourceCCKMAWSConnection` | [connections/resource_aws_connection.go:27](../../internal/provider/connections/resource_aws_connection.go#L27) |
| `ciphertrust_azure_connection` | `connections.NewResourceAzureConnection` | [connections/resource_azure_connection.go:39](../../internal/provider/connections/resource_azure_connection.go#L39) |
| `ciphertrust_gcp_connection` | `connections.NewResourceGCPConnection` | [connections/resource_gcp_connection.go:28](../../internal/provider/connections/resource_gcp_connection.go#L28) |
| `ciphertrust_oci_connection` | `connections.NewResourceCCKMOCIConnection` | [connections/resource_oci_connection.go:33](../../internal/provider/connections/resource_oci_connection.go#L33) |
| `ciphertrust_scp_connection` | `connections.NewResourceCMScpConnection` | [connections/resource_scp_connection.go:71](../../internal/provider/connections/resource_scp_connection.go#L71) |

Shared schema lives in [connections/schema_connections.go](../../internal/provider/connections/schema_connections.go).

## CCKM AWS (cckm/aws/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_aws_kms` | `aws.NewResourceCCKMAWSKMS` | [cckm/aws/resource_aws_kms.go:37](../../internal/provider/cckm/aws/resource_aws_kms.go#L37) |
| `ciphertrust_aws_key` | `aws.NewResourceAWSKey` | [cckm/aws/resource_aws_key.go:51](../../internal/provider/cckm/aws/resource_aws_key.go#L51) |
| `ciphertrust_aws_byok_key` | `aws.NewResourceAWSByokKey` | [cckm/aws/resource_aws_byok_key.go:37](../../internal/provider/cckm/aws/resource_aws_byok_key.go#L37) |
| `ciphertrust_aws_key_rotation` | `aws.NewResourceAWSKeyRotation` | [cckm/aws/resource_aws_key_rotation.go:62](../../internal/provider/cckm/aws/resource_aws_key_rotation.go#L62) |
| `ciphertrust_aws_key_material` | `aws.NewResourceAWSKeyMaterial` | [cckm/aws/resource_aws_key_material.go:58](../../internal/provider/cckm/aws/resource_aws_key_material.go#L58) |
| `ciphertrust_aws_policy_template` | `aws.NewResourceAWSPolicyTemplate` | [cckm/aws/resource_aws_policy_template.go:35](../../internal/provider/cckm/aws/resource_aws_policy_template.go#L35) |
| `ciphertrust_aws_custom_keystore` | `aws.NewResourceAWSCustomKeyStore` | [cckm/aws/resource_aws_custom_key_store.go:60](../../internal/provider/cckm/aws/resource_aws_custom_key_store.go#L60) |
| `ciphertrust_aws_xks_key` | `aws.NewResourceAWSXKSKey` | [cckm/aws/resource_aws_xks_key.go:35](../../internal/provider/cckm/aws/resource_aws_xks_key.go#L35) |
| `ciphertrust_aws_cloudhsm_key` | `aws.NewResourceAWSCloudHSMKey` | [cckm/aws/resource_aws_cloudhsm_key.go:34](../../internal/provider/cckm/aws/resource_aws_cloudhsm_key.go#L34) |
| `ciphertrust_aws_acl` | `aws.NewResourceCCKMAWSAcl` | [cckm/aws/resource_aws_acls.go:36](../../internal/provider/cckm/aws/resource_aws_acls.go#L36) |

Shared schema lives in [cckm/aws/aws_schema.go](../../internal/provider/cckm/aws/aws_schema.go).

## CCKM OCI (cckm/oci/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_oci_vault` | `oci.NewResourceCCKMOCIVault` | [cckm/oci/resource_oci_vault.go:35](../../internal/provider/cckm/oci/resource_oci_vault.go#L35) |
| `ciphertrust_oci_key` | `oci.NewResourceCCKMOCIKey` | [cckm/oci/resource_oci_key.go:37](../../internal/provider/cckm/oci/resource_oci_key.go#L37) |
| `ciphertrust_oci_key_version` | `oci.NewResourceCCKMOCIVersion` | [cckm/oci/resource_oci_key_version.go:36](../../internal/provider/cckm/oci/resource_oci_key_version.go#L36) |
| `ciphertrust_oci_byok_key` | `oci.NewResourceCCKMOCIByokKey` | [cckm/oci/resource_oci_byok_key.go:54](../../internal/provider/cckm/oci/resource_oci_byok_key.go#L54) |
| `ciphertrust_oci_byok_key_version` | `oci.NewResourceCCKMOCIByokVersion` | [cckm/oci/resource_oci_byok_key_version.go:37](../../internal/provider/cckm/oci/resource_oci_byok_key_version.go#L37) |
| `ciphertrust_oci_acl` | `oci.NewResourceCCKMOCIAcl` | [cckm/oci/resource_oci_acls.go:36](../../internal/provider/cckm/oci/resource_oci_acls.go#L36) |

OCI-specific helpers: [oci/oci_key_common.go](../../internal/provider/cckm/oci/oci_key_common.go), [oci/oci_key_version_common.go](../../internal/provider/cckm/oci/oci_key_version_common.go), [oci/oci_retry.go](../../internal/provider/cckm/oci/oci_retry.go), [oci/oci_log.go](../../internal/provider/cckm/oci/oci_log.go), [oci/tags.go](../../internal/provider/cckm/oci/tags.go). Models: [oci/models/](../../internal/provider/cckm/oci/models/).

## CCKM Azure (cckm/azure/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_azure_vault` | `azure.NewResourceCCKMAzureVault` | [cckm/azure/resource_azure_vault.go:45](../../internal/provider/cckm/azure/resource_azure_vault.go#L45) |
| `ciphertrust_azure_key` | `azure.NewResourceCCKMAzureKey` | [cckm/azure/resource_azure_key.go:62](../../internal/provider/cckm/azure/resource_azure_key.go#L62) |
| `ciphertrust_azure_certificate` | `azure.NewResourceCCKMAzureCertificate` | [cckm/azure/resource_azure_certificate.go:45](../../internal/provider/cckm/azure/resource_azure_certificate.go#L45) |
| `ciphertrust_azure_key_pit_backup` | `azure.NewResourceAzureKeyPitBackup` | [cckm/azure/resource_azure_key_pit_backup.go:31](../../internal/provider/cckm/azure/resource_azure_key_pit_backup.go#L31) |
| `ciphertrust_azure_acl` | `azure.NewResourceCCKMAzureAcl` | [cckm/azure/resource_azure_acls.go:36](../../internal/provider/cckm/azure/resource_azure_acls.go#L36) |

Azure-specific helpers: certificate ([azure_certificate_schema.go](../../internal/provider/cckm/azure/azure_certificate_schema.go), [azure_certificate_modify_plan.go](../../internal/provider/cckm/azure/azure_certificate_modify_plan.go), [azure_certificate_payload.go](../../internal/provider/cckm/azure/azure_certificate_payload.go), [azure_certificate_state.go](../../internal/provider/cckm/azure/azure_certificate_state.go), [azure_certificate_files.go](../../internal/provider/cckm/azure/azure_certificate_files.go)); key ([azure_key_payload.go](../../internal/provider/cckm/azure/azure_key_payload.go), [azure_key_state.go](../../internal/provider/cckm/azure/azure_key_state.go), [azure_key_update.go](../../internal/provider/cckm/azure/azure_key_update.go), [azure_key_validate.go](../../internal/provider/cckm/azure/azure_key_validate.go), [azure_key_backup_scheduler.go](../../internal/provider/cckm/azure/azure_key_backup_scheduler.go), [azure_key_rotation_scheduler.go](../../internal/provider/cckm/azure/azure_key_rotation_scheduler.go)); shared ([azure_attr_helpers.go](../../internal/provider/cckm/azure/azure_attr_helpers.go), [azure_post.go](../../internal/provider/cckm/azure/azure_post.go), [azure_read.go](../../internal/provider/cckm/azure/azure_read.go)).

## CTE (cte/)

| TF type | Constructor | File |
|---|---|---|
| `ciphertrust_cte_client` | `cte.NewResourceCTEClient` | [cte/resource_cte_client.go:39](../../internal/provider/cte/resource_cte_client.go#L39) |
| `ciphertrust_cte_client_group` | `cte.NewResourceCTEClientGroup` | [cte/resource_cte_clientgroup.go:28](../../internal/provider/cte/resource_cte_clientgroup.go#L28) |
| `ciphertrust_cte_clientgroup_designatedprimaryset` | `cte.NewResourceCTEClientGroupDesignatedPrimarySet` | [cte/resource_cte_clientgroup_dps.go:28](../../internal/provider/cte/resource_cte_clientgroup_dps.go#L28) |
| `ciphertrust_cte_clientgroup_guardpoint` | `cte.NewResourceCTEClientGroupGP` | [cte/resource_cte_clientgroup_guardpoints.go:32](../../internal/provider/cte/resource_cte_clientgroup_guardpoints.go#L32) |
| `ciphertrust_cte_client_guardpoint` | `cte.NewResourceCTEClientGP` | [cte/resource_cte_client_guardpoints.go:33](../../internal/provider/cte/resource_cte_client_guardpoints.go#L33) |
| `ciphertrust_cte_csigroup` | `cte.NewResourceCTECSIGroup` | [cte/resource_cte_csigroup.go:29](../../internal/provider/cte/resource_cte_csigroup.go#L29) |
| `ciphertrust_cte_ldtgroupcomms` | `cte.NewResourceLDTGroupCommSvc` | [cte/resource_cte_ldtgroupcomms.go:28](../../internal/provider/cte/resource_cte_ldtgroupcomms.go#L28) |
| `ciphertrust_cte_policy` | `cte.NewResourceCTEPolicy` | [cte/resource_cte_policy.go:27](../../internal/provider/cte/resource_cte_policy.go#L27) |
| `ciphertrust_cte_policy_data_tx_rule` | `cte.NewResourceCTEPolicyDataTXRule` | [cte/resource_cte_policy_datatxrules.go:24](../../internal/provider/cte/resource_cte_policy_datatxrules.go#L24) |
| `ciphertrust_cte_policy_idt_key_rule` | `cte.NewResourceCTEPolicyIDTKeyRule` | [cte/resource_cte_policy_idtkeyrules.go:21](../../internal/provider/cte/resource_cte_policy_idtkeyrules.go#L21) |
| `ciphertrust_cte_policy_key_rule` | `cte.NewResourceCTEPolicyKeyRule` | [cte/resource_cte_policy_keyrules.go:24](../../internal/provider/cte/resource_cte_policy_keyrules.go#L24) |
| `ciphertrust_cte_policy_ldtkey_rule` | `cte.NewResourceCTEPolicyLDTKeyRule` | [cte/resource_cte_policy_ldtkeyrules.go:24](../../internal/provider/cte/resource_cte_policy_ldtkeyrules.go#L24) |
| `ciphertrust_cte_policy_security_rule` | `cte.NewResourceCTEPolicySecurityRule` | [cte/resource_cte_policy_securityrules.go:26](../../internal/provider/cte/resource_cte_policy_securityrules.go#L26) |
| `ciphertrust_cte_policy_signature_rule` | `cte.NewResourceCTEPolicySignatureRule` | [cte/resource_cte_policy_signaturerules.go:25](../../internal/provider/cte/resource_cte_policy_signaturerules.go#L25) |
| `ciphertrust_cte_process_set` | `cte.NewResourceCTEProcessSet` | [cte/resource_cte_process_set.go:28](../../internal/provider/cte/resource_cte_process_set.go#L28) |
| `ciphertrust_cte_profile` | `cte.NewResourceCTEProfile` | [cte/resource_cte_profile.go:27](../../internal/provider/cte/resource_cte_profile.go#L27) |
| `ciphertrust_cte_resource_set` | `cte.NewResourceCTEResourceSet` | [cte/resource_cte_resource_set.go:28](../../internal/provider/cte/resource_cte_resource_set.go#L28) |
| `ciphertrust_cte_signature_set` | `cte.NewResourceCTESignatureSet` | [cte/resource_cte_signature_set.go:28](../../internal/provider/cte/resource_cte_signature_set.go#L28) |
| `ciphertrust_cte_user_set` | `cte.NewResourceCTEUserSet` | [cte/resource_cte_user_set.go:28](../../internal/provider/cte/resource_cte_user_set.go#L28) |

Shared schema lives in [cte/schema_cte.go](../../internal/provider/cte/schema_cte.go). CTE models live in [models/tfsdk_models.go](../../internal/provider/models/tfsdk_models.go) and [models/json_models.go](../../internal/provider/models/json_models.go).

## How to find a resource quickly
- By TF type (`ciphertrust_aws_key`): grep `resp.TypeName = req.ProviderTypeName + "_aws_key"` in [internal/provider/](../../internal/provider/).
- By constructor name: tables above are sorted by subsystem.
- All constructors are registered in [internal/provider/provider.go](../../internal/provider/provider.go) `Resources()` (starts at line 819).
