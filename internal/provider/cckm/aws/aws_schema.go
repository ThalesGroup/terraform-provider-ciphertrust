package cckm

import (
	"context"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// nullOrStateForUnknownObject is a plan modifier for Computed-only SingleNestedAttribute
// fields whose Go TFSDK type is a pointer (e.g. *MultiRegionConfigTFSDK). The Terraform
// Plugin Framework marks Computed-only attributes as unknown in the plan. This modifier
// resolves the unknown:
//   - New resource (null prior state): leaves the planned value as unknown so that
//     Terraform accepts whatever value (null or non-null) the provider returns after apply.
//   - Existing resource (known prior state): copies the prior state value to avoid
//     spurious "will be recomputed" diffs on this read-only nested object.
type nullOrStateForUnknownObject struct{}

func (nullOrStateForUnknownObject) Description(_ context.Context) string {
	return "Use null for new resources; use prior state value for existing resources."
}

func (nullOrStateForUnknownObject) MarkdownDescription(_ context.Context) string {
	return "Use null for new resources; use prior state value for existing resources."
}

func (nullOrStateForUnknownObject) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if !req.PlanValue.IsUnknown() {
		return
	}
	// New resource: state is null. Leave plan as unknown so Terraform accepts
	// whatever value (null or non-null) the provider returns after apply.
	// Returning null here would cause an "inconsistent result after apply" error
	// when the provider sets a non-null value (e.g. multi_region_configuration
	// for a multi-region key).
	if req.StateValue.IsNull() {
		return
	}
	// Existing resource: copy prior state to avoid spurious recompute diffs.
	resp.PlanValue = req.StateValue
}

type AWSCustomKeyStoreParamTFSDK struct {
	CloudHSMClusterID              types.String `tfsdk:"cloud_hsm_cluster_id"`
	ConnectionState                types.String `tfsdk:"connection_state"`
	ConnectionErrorDetails         types.String `tfsdk:"connection_error_details"`
	CustomKeystoreID               types.String `tfsdk:"custom_key_store_id"`
	CustomKeystoreName             types.String `tfsdk:"custom_key_store_name"`
	CustomKeystoreType             types.String `tfsdk:"custom_key_store_type"`
	KeyStorePassword               types.String `tfsdk:"key_store_password"`
	NumberOfHSMsInCloudHSMCluster  types.Int64  `tfsdk:"number_of_hsms_in_cloudhsm_cluster"`
	TrustAnchorCertificate         types.String `tfsdk:"trust_anchor_certificate"`
	XKSProxyConnectivity           types.String `tfsdk:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            types.String `tfsdk:"xks_proxy_uri_endpoint"`
	XKSProxyURIPath                types.String `tfsdk:"xks_proxy_uri_path"`
	XKSProxyVPCEndpointServiceName types.String `tfsdk:"xks_proxy_vpc_endpoint_service_name"`
	AWSAccountID                   types.String `tfsdk:"aws_account_id"`
	Arn                            types.String `tfsdk:"arn"`
}

type LocalHostedParamsTFSDK struct {
	Blocked               types.Bool   `tfsdk:"blocked"`
	HealthCheckCiphertext types.String `tfsdk:"health_check_ciphertext"`
	HealthCheckKeyID      types.String `tfsdk:"health_check_key_id"`
	HealthCheckURIPath    types.String `tfsdk:"health_check_uri_path"`
	LinkedState           types.Bool   `tfsdk:"linked_state"`
	MaxCredentials        types.Int32  `tfsdk:"max_credentials"`
	PartitionID           types.String `tfsdk:"partition_id"`
	PartitionLabel        types.String `tfsdk:"partition_label"`
	SourceContainerID     types.String `tfsdk:"source_container_id"`
	SourceContainerType   types.String `tfsdk:"source_container_type"`
	SourceKeyTier         types.String `tfsdk:"source_key_tier"`
}

type AWSCustomKeyStoreCommonTFSDK struct {
	ID                        types.String   `tfsdk:"id"`
	AccessKeyID               types.String   `tfsdk:"access_key_id"`
	SecretAccessKey           types.String   `tfsdk:"secret_access_key"`
	CloudName                 types.String   `tfsdk:"cloud_name"`
	CredentialVersion         types.Int64    `tfsdk:"credential_version"`
	CredentialCount           types.Int64    `tfsdk:"credential_count"`
	OldestCredentialsID       types.String   `tfsdk:"oldest_credentials_id"`
	KMSName                   types.String   `tfsdk:"kms_name"`
	KMSID                     types.String   `tfsdk:"kms_id"`
	Type                      types.String   `tfsdk:"type"`
	VersionCount              types.Int64    `tfsdk:"version_count"`
	CreatedAt                 types.String   `tfsdk:"created_at"`
	UpdatedAt                 types.String   `tfsdk:"updated_at"`
	Name                      types.String   `tfsdk:"name"`
	Region                    types.String   `tfsdk:"region"`
	EnableSuccessAuditEvent   types.Bool     `tfsdk:"enable_success_audit_event"`
	LinkedState               types.Bool     `tfsdk:"linked_state"`
	ConnectDisconnectKeystore types.String   `tfsdk:"connect_disconnect_keystore"`
	AWSParams                 types.Object   `tfsdk:"aws_param"`
	LocalHostedParams         types.Object   `tfsdk:"local_hosted_params"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
	Labels                    types.Map      `tfsdk:"labels"`
}

type AWSCustomKeyStoreTFSDK struct {
	AWSCustomKeyStoreCommonTFSDK
	EnableCredentialRotation *AWSEnableXksCredentialRotationJobTFSDK `tfsdk:"enable_credential_rotation"`
}

// CustomKeyStoreAwsParamTFSDK holds the aws_param fields for a custom key store list datasource item.
type CustomKeyStoreAwsParamTFSDK struct {
	CustomKeyStoreName             types.String `tfsdk:"custom_key_store_name"`
	CloudHSMClusterID              types.String `tfsdk:"cloud_hsm_cluster_id"`
	TrustAnchorCertificate         types.String `tfsdk:"trust_anchor_certificate"`
	NumberOfHSMsInCloudHSMCluster  types.Int64  `tfsdk:"number_of_hsms_in_cloudhsm_cluster"`
	XKSProxyURIEndpoint            types.String `tfsdk:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName types.String `tfsdk:"xks_proxy_vpc_endpoint_service_name"`
	XKSProxyURIPath                types.String `tfsdk:"xks_proxy_uri_path"`
	CustomKeyStoreType             types.String `tfsdk:"custom_key_store_type"`
	CustomKeyStoreID               types.String `tfsdk:"custom_key_store_id"`
	XKSProxyConnectivity           types.String `tfsdk:"xks_proxy_connectivity"`
	ConnectionState                types.String `tfsdk:"connection_state"`
	ConnectionErrorDetails         types.String `tfsdk:"connection_error_details"`
	AWSAccountID                   types.String `tfsdk:"aws_account_id"`
	Arn                            types.String `tfsdk:"arn"`
}

// CustomKeyStoreLocalHostedParamsTFSDK holds the local_hosted_params fields for a custom key store list datasource item.
type CustomKeyStoreLocalHostedParamsTFSDK struct {
	Blocked               types.Bool   `tfsdk:"blocked"`
	SourceContainerID     types.String `tfsdk:"source_container_id"`
	SourceContainerType   types.String `tfsdk:"source_container_type"`
	LinkedState           types.Bool   `tfsdk:"linked_state"`
	PartitionLabel        types.String `tfsdk:"partition_label"`
	PartitionID           types.String `tfsdk:"partition_id"`
	HealthCheckKeyID      types.String `tfsdk:"health_check_key_id"`
	HealthCheckCiphertext types.String `tfsdk:"health_check_ciphertext"`
	MaxCredentials        types.Int64  `tfsdk:"max_credentials"`
	SourceKeyTier         types.String `tfsdk:"source_key_tier"`
	HealthCheckURIPath    types.String `tfsdk:"health_check_uri_path"`
}

// CustomKeyStoreListItemTFSDK represents a single custom key store entry returned by the list API.
type CustomKeyStoreListItemTFSDK struct {
	ID                      types.String                          `tfsdk:"id"`
	CreatedAt               types.String                          `tfsdk:"created_at"`
	UpdatedAt               types.String                          `tfsdk:"updated_at"`
	Name                    types.String                          `tfsdk:"name"`
	Kms                     types.String                          `tfsdk:"kms"`
	Region                  types.String                          `tfsdk:"region"`
	Type                    types.String                          `tfsdk:"type"`
	CredentialVersion       types.Int64                           `tfsdk:"credential_version"`
	KmsID                   types.String                          `tfsdk:"kms_id"`
	CloudName               types.String                          `tfsdk:"cloud_name"`
	VersionCount            types.Int64                           `tfsdk:"version_count"`
	Gone                    types.Bool                            `tfsdk:"gone"`
	EnableSuccessAuditEvent types.Bool                            `tfsdk:"enable_success_audit_event"`
	AwsParam                *CustomKeyStoreAwsParamTFSDK          `tfsdk:"aws_param"`
	LocalHostedParams       *CustomKeyStoreLocalHostedParamsTFSDK `tfsdk:"local_hosted_params"`
}

// AWSCustomKeyStoreListDataSourceModel is the top-level model for the aws_custom_keystore_list datasource.
type AWSCustomKeyStoreListDataSourceModel struct {
	Filters         types.Map                     `tfsdk:"filters"`
	Matched         types.Int64                   `tfsdk:"matched"`
	CustomKeyStores []CustomKeyStoreListItemTFSDK `tfsdk:"custom_key_stores"`
}

type AWSKeyEnableRotationTFSDK struct {
	JobConfigID                           types.String `tfsdk:"job_config_id"`
	AutoRotateDisableEncrypt              types.Bool   `tfsdk:"disable_encrypt"`
	AutoRotateKeySource                   types.String `tfsdk:"key_source"`
	AutoRotateDisableEncryptOnAllAccounts types.Bool   `tfsdk:"disable_encrypt_on_all_accounts"`
}

type AWSKeyImportMaterialTFSDK struct {
	ImportType             types.String `tfsdk:"import_type"`
	KeyMaterialDescription types.String `tfsdk:"key_material_description"`
	KeyMaterialID          types.String `tfsdk:"key_material_id"`
	SourceKeyID            types.String `tfsdk:"source_key_identifier"`
	SourceKeyTier          types.String `tfsdk:"source_key_tier"`
	KeyExpiration          types.Bool   `tfsdk:"key_expiration"`
	ValidTo                types.String `tfsdk:"valid_to"`
}

type AWSKeyPolicyCommonTFSDK struct {
	ExternalAccounts types.Set    `tfsdk:"external_accounts"`
	KeyAdmins        types.Set    `tfsdk:"key_admins"`
	KeyAdminsRoles   types.Set    `tfsdk:"key_admins_roles"`
	KeyUsers         types.Set    `tfsdk:"key_users"`
	KeyUsersRoles    types.Set    `tfsdk:"key_users_roles"`
	Policy           types.String `tfsdk:"policy"`
}

type AWSKeyPolicyTFSDK struct {
	AWSKeyPolicyCommonTFSDK
	PolicyTemplate types.String `tfsdk:"policy_template"`
}

type AWSKeyPolicyTemplateTFSDK struct {
	ID         types.String `tfsdk:"id"`
	KmsID      types.String `tfsdk:"kms_id"`
	KmsName    types.String `tfsdk:"kms_name"`
	Name       types.String `tfsdk:"name"`
	AccountID  types.String `tfsdk:"account_id"`
	AutoPush   types.Bool   `tfsdk:"auto_push"`
	IsVerified types.Bool   `tfsdk:"is_verified"`
	AWSKeyPolicyCommonTFSDK
}

type AWSReplicateKeyTFSDK struct {
	KeyID       types.String `tfsdk:"key_id"`
	MakePrimary types.Bool   `tfsdk:"make_primary"`
}

// AWSKeyMultiRegionTFSDK holds the three multi-region fields shared by
// AWSKeyTFSDK and AWSByokKeyTFSDK. Both structs embed this type.
// MultiRegionConfiguration uses types.Object so the Framework can safely
// decode null, unknown, and concrete values without error.
type AWSKeyMultiRegionTFSDK struct {
	MultiRegionConfiguration types.Object          `tfsdk:"multi_region_configuration"`
	PrimaryRegion            types.String          `tfsdk:"primary_region"`
	ReplicateKey             *AWSReplicateKeyTFSDK `tfsdk:"replicate_key"`
}

// AWSKeyUpdateInputTFSDK carries the minimum fields needed by the shared update helpers
// (updateAwsKeyCommon, updateKeyPolicy, enableDisableKeyRotation, updateDescription).
// Build one directly from any key resource's plan or state struct.
type AWSKeyUpdateInputTFSDK struct {
	KeyID          string
	Description    types.String
	KeyPolicy      *AWSKeyPolicyTFSDK
	EnableRotation *AWSKeyEnableRotationTFSDK
}

// MultiRegionKeyTFSDK holds the ARN and region of a single entry in a multi-region key set.
type MultiRegionKeyTFSDK struct {
	Arn    types.String `tfsdk:"arn"`
	Region types.String `tfsdk:"region"`
}

// MultiRegionConfigTFSDK holds the multi-region configuration for an AWS key.
// It is nil when the key is not a multi-region key.
type MultiRegionConfigTFSDK struct {
	MultiRegionKeyType types.String          `tfsdk:"multi_region_key_type"`
	PrimaryKey         *MultiRegionKeyTFSDK  `tfsdk:"primary_key"`
	ReplicaKeys        []MultiRegionKeyTFSDK `tfsdk:"replica_keys"`
}

// AWSNativeAndByokKeyCommonTFSDK holds the top-level Terraform state fields shared by the
// aws_key and aws_byok_key resources. It is derived from AWSKeyCommonTFSDK.
// XKS and CloudHSM keys continue to use AWSKeyCommonTFSDK unchanged.
type AWSNativeAndByokKeyCommonTFSDK struct {
	ID                      types.String               `tfsdk:"id"`
	Region                  types.String               `tfsdk:"region"`
	EnableKey               types.Bool                 `tfsdk:"enable_key"`
	EnableRotation          *AWSKeyEnableRotationTFSDK `tfsdk:"enable_rotation"`
	KMSName                 types.String               `tfsdk:"kms_name"`
	KMSID                   types.String               `tfsdk:"kms_id"`
	ScheduleForDeletionDays types.Int64                `tfsdk:"schedule_for_deletion_days"`
	CloudName               types.String               `tfsdk:"cloud_name"`
	CreatedAt               types.String               `tfsdk:"created_at"`
	ExternalAccounts        types.Set                  `tfsdk:"external_accounts"`
	KeyAdmins               types.Set                  `tfsdk:"key_admins"`
	KeyAdminsRoles          types.Set                  `tfsdk:"key_admins_roles"`
	KeyMaterialOrigin       types.String               `tfsdk:"key_material_origin"`
	KeyPolicy               *AWSKeyPolicyTFSDK         `tfsdk:"key_policy"`
	KeySource               types.String               `tfsdk:"key_source"`
	KeyType                 types.String               `tfsdk:"key_type"`
	KeyUsers                types.Set                  `tfsdk:"key_users"`
	KeyUsersRoles           types.Set                  `tfsdk:"key_users_roles"`
	Labels                  types.Map                  `tfsdk:"labels"`
	PolicyTemplateTag       types.Map                  `tfsdk:"policy_template_tag"`
	RotatedAt               types.String               `tfsdk:"rotated_at"`
	RotatedFrom             types.String               `tfsdk:"rotated_from"`
	RotatedTo               types.String               `tfsdk:"rotated_to"`
	RotationStatus          types.String               `tfsdk:"rotation_status"`
	SyncedAt                types.String               `tfsdk:"synced_at"`
	UpdatedAt               types.String               `tfsdk:"updated_at"`
}

// AWSKeyTFSDK holds the Terraform state for the aws_key resource.
// Common top-level computed fields are provided by AWSNativeAndByokKeyCommonTFSDK.
// The aws_param-sourced computed fields (arn, aws_account_id, aws_key_id, deletion_date,
// enabled, encryption_algorithms, expiration_model, key_manager, key_rotation_enabled,
// key_state, mac_algorithms, origin, auto_rotation_period_in_days, next_rotation_date)
// now live inside the AWSParam nested block.
// Multi-region fields (replicate_key, primary_region, multi_region_configuration) are
// provided by the embedded AWSKeyMultiRegionTFSDK.
// Input AWS parameters (alias, spec, description, etc.) live inside the AWSParam block.
type AWSKeyTFSDK struct {
	AWSNativeAndByokKeyCommonTFSDK
	AWSKeyMultiRegionTFSDK
	// aws_key-specific input field
	AutoRotate types.Bool `tfsdk:"auto_rotate"`
	// AWS-specific input/output parameters block. types.Object is used so the
	// framework can decode null and unknown plan values without error when
	// aws_param is not set in config (e.g. when replicating a multi-region key).
	AWSParam        types.Object `tfsdk:"aws_param"`
	RotationHistory types.List   `tfsdk:"rotation_history"`
}

// RotationHistoryEntryFullTFSDK holds all available fields from the rotation history API response.
// It extends RotationHistoryEntryTFSDK with every field exposed by the AWSKeyRotation and
// AWSKeyRotationParams server-side structs. Used by the aws_key_material resource.
// RotationHistoryEntryFullTFSDK holds the BYOK full rotation history fields for the
// aws_key_material resource. Used internally for classify/repair logic and for state.
// No uri or account fields are included.
// RotationHistoryEntryFullTFSDK holds the BYOK full rotation history fields for the
// aws_key_material resource. Used internally for classify/repair logic and for state.
// No uri or account fields are included. AWSKeyRotationParams fields are nested
// under AWSParams (tfsdk:"aws_params") to mirror the server-side aws_param structure.
type RotationHistoryEntryFullTFSDK struct {
	// Resource identity (no uri, no account)
	ID        types.String `tfsdk:"id"`
	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
	// Top-level AWSKeyRotation fields
	LocalKeyID             types.String `tfsdk:"local_key_id"`
	KmsID                  types.String `tfsdk:"kms_id"`
	SourceKeyIdentifier    types.String `tfsdk:"source_key_identifier"`
	SourceKeyName          types.String `tfsdk:"source_key_name"`
	SourceKeyTier          types.String `tfsdk:"source_key_tier"`
	KeySource              types.String `tfsdk:"key_source"`
	KeyMaterialOrigin      types.String `tfsdk:"key_material_origin"`
	KeySourceContainerName types.String `tfsdk:"key_source_container_name"`
	KeySourceContainerID   types.String `tfsdk:"key_source_container_id"`
	LastImportStatus       types.String `tfsdk:"last_import_status"`
	LastImportError        types.String `tfsdk:"last_import_error"`
	LastImportAt           types.String `tfsdk:"last_import_at"`
	// AWSKeyRotationParams fields nested under aws_params (mirrors the API response structure).
	AWSParams KeyRotationAwsParamTFSDK `tfsdk:"aws_params"`
}

// AWSCommonAwsParamTFSDK holds the aws_param fields shared by aws_key and aws_byok_key.
// Input fields (alias, bypass_policy_lockout_safety_check, customer_master_key_spec,
// description, key_usage, multi_region, tags) are Optional/Computed.
// Computed-only fields mirror the AwsParam struct returned by the CCKM API under aws_param.
type AWSCommonAwsParamTFSDK struct {
	// Input/Computed fields
	Alias                          types.Set    `tfsdk:"alias"`
	BypassPolicyLockoutSafetyCheck types.Bool   `tfsdk:"bypass_policy_lockout_safety_check"`
	CustomerMasterKeySpec          types.String `tfsdk:"customer_master_key_spec"`
	Description                    types.String `tfsdk:"description"`
	KeyUsage                       types.String `tfsdk:"key_usage"`
	MultiRegion                    types.Bool   `tfsdk:"multi_region"`
	Tags                           types.Map    `tfsdk:"tags"`
	// Computed-only fields (sourced from aws_param in the CCKM API response)
	Arn                  types.String `tfsdk:"arn"`
	AWSAccountID         types.String `tfsdk:"aws_account_id"`
	AWSKeyID             types.String `tfsdk:"key_id"`
	CurrentKeyMaterialID types.String `tfsdk:"current_key_material_id"`
	DeletionDate         types.String `tfsdk:"deletion_date"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel      types.String `tfsdk:"expiration_model"`
	KeyManager           types.String `tfsdk:"key_manager"`
	KeyRotationEnabled   types.Bool   `tfsdk:"key_rotation_enabled"`
	KeyState             types.String `tfsdk:"key_state"`
	MacAlgorithms        types.List   `tfsdk:"mac_algorithms"`
	Origin               types.String `tfsdk:"origin"`
	Policy               types.String `tfsdk:"policy"`
	ReplicaPolicy        types.String `tfsdk:"replica_policy"`
	ReplicaTags          types.String `tfsdk:"replica_tags"`
}

// AWSKeyAwsParamTFSDK is the aws_param block for the aws_key resource.
// It embeds AWSCommonAwsParamTFSDK and adds:
//   - AutoRotationPeriodInDays (Optional/Computed) - rotation period in days for AWS auto-rotation
//   - NextRotationDate (Computed) - date of the next scheduled AWS auto-rotation
//
// These fields are native-key-only because AWS cannot auto-rotate EXTERNAL-origin (BYOK) keys.
type AWSKeyAwsParamTFSDK struct {
	AWSCommonAwsParamTFSDK
	AutoRotationPeriodInDays types.Int64  `tfsdk:"auto_rotation_period_in_days"`
	NextRotationDate         types.String `tfsdk:"next_rotation_date"`
}

// AWSByokAwsParamTFSDK is the aws_param block for the aws_byok_key resource.
// It embeds AWSCommonAwsParamTFSDK and adds:
//   - ValidTo (Optional/Computed) - key material expiry supplied on upload
//
// Note: auto_rotation_period_in_days and next_rotation_date are intentionally
// absent - AWS cannot auto-rotate EXTERNAL-origin (BYOK) keys because they
// require customer-supplied key material.
type AWSByokAwsParamTFSDK struct {
	AWSCommonAwsParamTFSDK
	ValidTo types.String `tfsdk:"valid_to"`
}

// AWSKeyMaterialTFSDK holds the Terraform state for the aws_key_material resource.
// AWSKeyID is the Required input used to look up the CM record for the target key.
// KeyMaterial is the managed set of key-material entries.
// All other fields are Computed from the API response.
type AWSKeyMaterialTFSDK struct {
	AWSKeyID        types.String `tfsdk:"aws_key_id"`
	ID              types.String `tfsdk:"id"`
	KMSID           types.String `tfsdk:"kms_id"`
	KMSName         types.String `tfsdk:"kms_name"`
	KeyMaterial     types.Set    `tfsdk:"key_material"`
	RotationHistory types.List   `tfsdk:"rotation_history"`
}

// AWSByokImportMaterialTFSDK holds a single key-material entry managed by the aws_key_material resource.
// Each entry represents one key-material version to import (or already imported) into an EXTERNAL key.
type AWSByokImportMaterialTFSDK struct {
	SourceKeyID            types.String `tfsdk:"source_key_identifier"`
	SourceKeyTier          types.String `tfsdk:"source_key_tier"`
	ValidTo                types.String `tfsdk:"valid_to"`
	KeyMaterialDescription types.String `tfsdk:"key_material_description"`
}

// AWSByokKeyTFSDK holds the Terraform state for the aws_byok_key resource.
// Top-level computed fields are provided by AWSNativeAndByokKeyCommonTFSDK.
// The 12 aws_param-sourced computed fields now live inside the AWSParam nested block.
// Multi-region fields (replicate_key, primary_region, multi_region_configuration) are
// provided by the embedded AWSKeyMultiRegionTFSDK.
// AWSParam holds the AWS-specific input parameters (alias, spec, tags, etc.) and
// the resulting computed state returned by the API after creation or update.
// Key material import and rotation are managed by the aws_key_material resource.
type AWSByokKeyTFSDK struct {
	AWSNativeAndByokKeyCommonTFSDK
	AWSKeyMultiRegionTFSDK
	// AWS-specific input/output parameters block. types.Object is used so the
	// framework can decode null and unknown plan values without error when
	// aws_param is not set in config (e.g. when replicating a multi-region key).
	AWSParam        types.Object `tfsdk:"aws_param"`
	SourceKeyID     types.String `tfsdk:"source_key_identifier"`
	SourceKeyTier   types.String `tfsdk:"source_key_tier"`
	LocalKeyID      types.String `tfsdk:"local_key_id"`
	LocalKeyName    types.String `tfsdk:"local_key_name"`
	RotationHistory types.List   `tfsdk:"rotation_history"`
}

// AWSNativeKeyRotationTFSDK holds the Terraform state for the aws_key_rotation resource.
// It represents a single on-demand rotation request for an AWS native symmetric key.
// key_id identifies the CipherTrust Manager key to rotate; trigger is an arbitrary
// user-supplied value whose change causes replacement (and therefore a new rotation).
type AWSNativeKeyRotationTFSDK struct {
	KeyID           types.String `tfsdk:"key_id"`
	Trigger         types.String `tfsdk:"trigger"`
	ID              types.String `tfsdk:"id"`
	RotationHistory types.List   `tfsdk:"rotation_history"`
}

type XKSKeyLocalHostedParamsTFSDK struct {
	Blocked          types.Bool   `tfsdk:"blocked"`
	SourceKeyID      types.String `tfsdk:"source_key_id"`
	SourceKeyTier    types.String `tfsdk:"source_key_tier"`
	CustomKeyStoreID types.String `tfsdk:"custom_key_store_id"`
	Linked           types.Bool   `tfsdk:"linked"`
}

// AWSXKSKeyTFSDK holds the Terraform state for the aws_xks_key resource.
// Top-level fields are provided by AWSKeyStoreResourceCommonTFSDK (slim struct).
// All AWS response fields (arn, key_id, key_state, etc.) live inside AWSParam.
type AWSXKSKeyTFSDK struct {
	AWSKeyStoreResourceCommonTFSDK
	LocalHostParams *XKSKeyLocalHostedParamsTFSDK `tfsdk:"local_hosted_params"`
}

// AWSCloudHSMKeyTFSDK holds the Terraform state for the aws_cloudhsm_key resource.
// Top-level fields are provided by AWSKeyStoreResourceCommonTFSDK (slim struct).
// All AWS response fields (arn, key_id, key_state, etc.) live inside AWSParam.
type AWSCloudHSMKeyTFSDK struct {
	AWSKeyStoreResourceCommonTFSDK
}

// AWSKeyStoreAwsParamTFSDK holds the aws_param block shared by both the aws_xks_key and
// aws_cloudhsm_key resources. Alias, Description, and Tags are Optional/Computed inputs;
// Policy is Computed-only (output of the resolved AWS key policy after creation).
// Retained for use by datasource helpers that have not yet been migrated.
type AWSKeyStoreAwsParamTFSDK struct {
	Alias       types.Set    `tfsdk:"alias"`
	Description types.String `tfsdk:"description"`
	Policy      types.String `tfsdk:"policy"`
	Tags        types.Map    `tfsdk:"tags"`
}

// AWSKeyStoreCommonAwsParamTFSDK is the shared base for the aws_param block of the
// aws_xks_key and aws_cloudhsm_key resources. It includes all input and computed fields
// that are common to both key types. XKS and CloudHSM extend it with type-specific fields.
type AWSKeyStoreCommonAwsParamTFSDK struct {
	// Input/Computed fields
	Alias       types.Set    `tfsdk:"alias"`
	Description types.String `tfsdk:"description"`
	Tags        types.Map    `tfsdk:"tags"`
	// Computed-only fields sourced from aws_param in the CCKM API response
	Arn                   types.String `tfsdk:"arn"`
	AWSAccountID          types.String `tfsdk:"aws_account_id"`
	AWSCustomKeyStoreID   types.String `tfsdk:"aws_custom_key_store_id"`
	CustomerMasterKeySpec types.String `tfsdk:"customer_master_key_spec"`
	CreationDate          types.String `tfsdk:"creation_date"`
	DeletionDate          types.String `tfsdk:"deletion_date"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms  types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel       types.String `tfsdk:"expiration_model"`
	KeyID                 types.String `tfsdk:"key_id"`
	KeyManager            types.String `tfsdk:"key_manager"`
	KeyState              types.String `tfsdk:"key_state"`
	KeyUsage              types.String `tfsdk:"key_usage"`
	MacAlgorithms         types.List   `tfsdk:"mac_algorithms"`
	Origin                types.String `tfsdk:"origin"`
	Policy                types.String `tfsdk:"policy"`
}

// XksKeyConfigurationTFSDK holds the XksKeyConfiguration object returned by AWS
// in the aws_param block for XKS keys. It has a single field: the external key ID
// assigned by the XKS proxy (XksKeyConfigurationType.Id).
type XksKeyConfigurationTFSDK struct {
	ID types.String `tfsdk:"id"`
}

// AWSXKSKeyAwsParamTFSDK is the aws_param block for the aws_xks_key resource.
// It embeds AWSKeyStoreCommonAwsParamTFSDK and adds xks_key_configuration (Computed),
// which is a nested object containing the XksKeyConfiguration.Id assigned by AWS.
type AWSXKSKeyAwsParamTFSDK struct {
	AWSKeyStoreCommonAwsParamTFSDK
	XksKeyConfiguration *XksKeyConfigurationTFSDK `tfsdk:"xks_key_configuration"`
}

// AWSCloudHSMKeyAwsParamTFSDK is the aws_param block for the aws_cloudhsm_key resource.
// It embeds AWSKeyStoreCommonAwsParamTFSDK and adds key_rotation_enabled (Computed).
// XKS keys do not support AWS automatic key rotation; CloudHSM keys do.
type AWSCloudHSMKeyAwsParamTFSDK struct {
	AWSKeyStoreCommonAwsParamTFSDK
	KeyRotationEnabled types.Bool `tfsdk:"key_rotation_enabled"`
}

// AWSKeyStoreResourceCommonTFSDK holds the top-level Terraform state fields shared by
// the aws_xks_key and aws_cloudhsm_key resources. It is a slim struct: fields that come
// from the API aws_param block (arn, key_id, enabled, key_state, etc.) are now inside
// the AWSParam nested object rather than at the top level.
type AWSKeyStoreResourceCommonTFSDK struct {
	ID                      types.String               `tfsdk:"id"`
	Region                  types.String               `tfsdk:"region"`
	EnableKey               types.Bool                 `tfsdk:"enable_key"`
	EnableRotation          *AWSKeyEnableRotationTFSDK `tfsdk:"enable_rotation"`
	KMSName                 types.String               `tfsdk:"kms_name"`
	KMSID                   types.String               `tfsdk:"kms_id"`
	ScheduleForDeletionDays types.Int64                `tfsdk:"schedule_for_deletion_days"`
	CloudName               types.String               `tfsdk:"cloud_name"`
	CreatedAt               types.String               `tfsdk:"created_at"`
	ExternalAccounts        types.Set                  `tfsdk:"external_accounts"`
	KeyAdmins               types.Set                  `tfsdk:"key_admins"`
	KeyAdminsRoles          types.Set                  `tfsdk:"key_admins_roles"`
	KeyMaterialOrigin       types.String               `tfsdk:"key_material_origin"`
	KeyPolicy               *AWSKeyPolicyTFSDK         `tfsdk:"key_policy"`
	KeySource               types.String               `tfsdk:"key_source"`
	KeyType                 types.String               `tfsdk:"key_type"`
	KeyUsers                types.Set                  `tfsdk:"key_users"`
	KeyUsersRoles           types.Set                  `tfsdk:"key_users_roles"`
	Labels                  types.Map                  `tfsdk:"labels"`
	PolicyTemplateTag       types.Map                  `tfsdk:"policy_template_tag"`
	RotatedAt               types.String               `tfsdk:"rotated_at"`
	RotatedFrom             types.String               `tfsdk:"rotated_from"`
	RotatedTo               types.String               `tfsdk:"rotated_to"`
	RotationStatus          types.String               `tfsdk:"rotation_status"`
	SyncedAt                types.String               `tfsdk:"synced_at"`
	UpdatedAt               types.String               `tfsdk:"updated_at"`
	// Keystore-specific fields
	BypassPolicyLockoutSafetyCheck types.Bool   `tfsdk:"bypass_policy_lockout_safety_check"`
	ValidTo                        types.String `tfsdk:"valid_to"`
	KeySourceContainerName         types.String `tfsdk:"key_source_container_name"`
	KeySourceContainerID           types.String `tfsdk:"key_source_container_id"`
	CustomKeyStoreID               types.String `tfsdk:"custom_key_store_id"`
	Linked                         types.Bool   `tfsdk:"linked"`
	Blocked                        types.Bool   `tfsdk:"blocked"`
	LocalKeyID                     types.String `tfsdk:"local_key_id"`
	LocalKeyName                   types.String `tfsdk:"local_key_name"`
	// aws_param holds the full AWS parameter block as a typed Object.
	AWSParam types.Object `tfsdk:"aws_param"`
}

type AWSAccountDetailsModelTFSDK struct {
	ConnectionID         types.String `tfsdk:"connection_id"`
	AssumeRoleArn        types.String `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID types.String `tfsdk:"assume_role_external_id"`
	AccountID            types.String `tfsdk:"account_id"`
	Regions              types.List   `tfsdk:"regions"`
	Validate             types.Bool   `tfsdk:"validate"`
}

type KMSModelTFSDK struct {
	Account              types.String `tfsdk:"account"`
	AccountID            types.String `tfsdk:"account_id"`
	Acls                 types.Set    `tfsdk:"acls"`
	Application          types.String `tfsdk:"application"`
	Arn                  types.String `tfsdk:"arn"`
	AssumeRoleARN        types.String `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID types.String `tfsdk:"assume_role_external_id"`
	AutoAdded            types.Bool   `tfsdk:"auto_added"`
	ConnectionID         types.String `tfsdk:"connection_id"`
	ConnectionName       types.String `tfsdk:"connection_name"`
	CreatedAt            types.String `tfsdk:"created_at"`
	DevAccount           types.String `tfsdk:"dev_account"`
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Regions              types.List   `tfsdk:"regions"`
	Status               types.String `tfsdk:"status"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
	URI                  types.String `tfsdk:"uri"`
}

// AWSKeyDSAwsParamTFSDK is the computed-only aws_param block for the aws_key data source.
// It contains the full set of fields from AwsParam (minus AWSAccountID and uri) as
// Computed-only attributes. This covers all AWS key types since there is a single datasource.
type AWSKeyDSAwsParamTFSDK struct {
	Alias                    types.Set    `tfsdk:"alias"`
	Arn                      types.String `tfsdk:"arn"`
	AWSCustomKeyStoreID      types.String `tfsdk:"aws_custom_key_store_id"`
	CreationDate             types.String `tfsdk:"creation_date"`
	CurrentKeyMaterialID     types.String `tfsdk:"current_key_material_id"`
	CustomerMasterKeySpec    types.String `tfsdk:"customer_master_key_spec"`
	DeletionDate             types.String `tfsdk:"deletion_date"`
	Description              types.String `tfsdk:"description"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms     types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel          types.String `tfsdk:"expiration_model"`
	KeyID                    types.String `tfsdk:"key_id"`
	KeyManager               types.String `tfsdk:"key_manager"`
	KeyRotationEnabled       types.Bool   `tfsdk:"key_rotation_enabled"`
	KeyState                 types.String `tfsdk:"key_state"`
	KeyUsage                 types.String `tfsdk:"key_usage"`
	MacAlgorithms            types.List   `tfsdk:"mac_algorithms"`
	MultiRegion              types.Bool   `tfsdk:"multi_region"`
	MultiRegionConfiguration types.Object `tfsdk:"multi_region_configuration"`
	NextRotationDate         types.String `tfsdk:"next_rotation_date"`
	Origin                   types.String `tfsdk:"origin"`
	Policy                   types.String `tfsdk:"policy"`
	ReplicaPolicy            types.String `tfsdk:"replica_policy"`
	ReplicaTags              types.String `tfsdk:"replica_tags"`
	RotationPeriodInDays     types.Int64  `tfsdk:"rotation_period_in_days"`
	Tags                     types.Map    `tfsdk:"tags"`
	ValidTo                  types.String `tfsdk:"valid_to"`
	XksKeyConfiguration      types.String `tfsdk:"xks_key_configuration"`
}

// AWSKeyStoreDSAwsParamTFSDK is the computed-only aws_param block for the
// aws_xks_key and aws_cloudhsm_key data sources.
// It covers all fields from AwsParam that are relevant to key-store (XKS/CloudHSM) keys.
// All fields are Computed. Fields that are type-specific (xks_key_configuration for XKS,
// key_rotation_enabled for CloudHSM) are present in both but will be null/zero for the
// key type that does not use them.
type AWSKeyStoreDSAwsParamTFSDK struct {
	// Input/Computed fields (populated only for linked keys)
	Alias       types.Set    `tfsdk:"alias"`
	Description types.String `tfsdk:"description"`
	Tags        types.Map    `tfsdk:"tags"`
	// Computed-only fields sourced from aws_param in the CCKM API response
	Arn                   types.String `tfsdk:"arn"`
	AWSAccountID          types.String `tfsdk:"aws_account_id"`
	AWSCustomKeyStoreID   types.String `tfsdk:"aws_custom_key_store_id"`
	CustomerMasterKeySpec types.String `tfsdk:"customer_master_key_spec"`
	CreationDate          types.String `tfsdk:"creation_date"`
	DeletionDate          types.String `tfsdk:"deletion_date"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms  types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel       types.String `tfsdk:"expiration_model"`
	KeyID                 types.String `tfsdk:"key_id"`
	KeyManager            types.String `tfsdk:"key_manager"`
	// key_rotation_enabled is populated for CloudHSM keys; null for XKS keys.
	KeyRotationEnabled types.Bool   `tfsdk:"key_rotation_enabled"`
	KeyState           types.String `tfsdk:"key_state"`
	KeyUsage           types.String `tfsdk:"key_usage"`
	MacAlgorithms      types.List   `tfsdk:"mac_algorithms"`
	Origin             types.String `tfsdk:"origin"`
	Policy             types.String `tfsdk:"policy"`
	// xks_key_configuration is populated for XKS keys (raw JSON); null for CloudHSM keys.
	XksKeyConfiguration types.String `tfsdk:"xks_key_configuration"`
}

type AWSKeyDataSourceTFSDK struct {
	AWSKeyDataSourceCommonTFSDK
	AutoRotate               types.Bool             `tfsdk:"auto_rotate"`
	AutoRotationPeriodInDays types.Int64            `tfsdk:"auto_rotation_period_in_days"`
	AWSParam                 *AWSKeyDSAwsParamTFSDK `tfsdk:"aws_param"`
	KMSName                  types.String           `tfsdk:"kms_name"`
	KMSID                    types.String           `tfsdk:"kms_id"`
	MultiRegion              types.Bool             `tfsdk:"multi_region"`
	MultiRegionConfiguration types.Object           `tfsdk:"multi_region_configuration"`
	NextRotationDate         types.String           `tfsdk:"next_rotation_date"`
}

// AWSKeyDataSourceCommonTFSDK holds the Terraform state fields that are common to all three
// AWS key list datasource item types (aws_key, aws_xks_key, aws_cloudhsm_key) and that do
// not originate from the API aws_param block.
type AWSKeyDataSourceCommonTFSDK struct {
	ID                types.String `tfsdk:"id"`
	Region            types.String `tfsdk:"region"`
	CloudName         types.String `tfsdk:"cloud_name"`
	CreatedAt         types.String `tfsdk:"created_at"`
	ExternalAccounts  types.Set    `tfsdk:"external_accounts"`
	KeyAdmins         types.Set    `tfsdk:"key_admins"`
	KeyAdminsRoles    types.Set    `tfsdk:"key_admins_roles"`
	KeyID             types.String `tfsdk:"key_id"`
	KeyMaterialOrigin types.String `tfsdk:"key_material_origin"`
	KeySource         types.String `tfsdk:"key_source"`
	KeyType           types.String `tfsdk:"key_type"`
	KeyUsers          types.Set    `tfsdk:"key_users"`
	KeyUsersRoles     types.Set    `tfsdk:"key_users_roles"`
	Labels            types.Map    `tfsdk:"labels"`
	LocalKeyID        types.String `tfsdk:"local_key_id"`
	LocalKeyName      types.String `tfsdk:"local_key_name"`
	PolicyTemplateTag types.Map    `tfsdk:"policy_template_tag"`
	RotatedAt         types.String `tfsdk:"rotated_at"`
	RotatedFrom       types.String `tfsdk:"rotated_from"`
	RotatedTo         types.String `tfsdk:"rotated_to"`
	RotationStatus    types.String `tfsdk:"rotation_status"`
	SyncedAt          types.String `tfsdk:"synced_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

type AWSKeyStoreKeyDataSourceCommonTFSDK struct {
	AWSKeyDataSourceCommonTFSDK
	AWSParam            *AWSKeyStoreDSAwsParamTFSDK `tfsdk:"aws_param"`
	KMSName             types.String                `tfsdk:"kms_name"`
	KMSID               types.String                `tfsdk:"kms_id"`
	CustomKeyStoreID    types.String                `tfsdk:"custom_key_store_id"`
	Linked              types.Bool                  `tfsdk:"linked"`
	Blocked             types.Bool                  `tfsdk:"blocked"`
	AWSCustomKeyStoreID types.String                `tfsdk:"aws_custom_key_store_id"`
}

type AWSXKSKeyDataSourceTFSDK struct {
	AWSKeyStoreKeyDataSourceCommonTFSDK
	AWSXKSKeyID   types.String `tfsdk:"aws_xks_key_id"`
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
}

type AWSCloudHSMKeyDataSourceTFSDK struct {
	AWSKeyStoreKeyDataSourceCommonTFSDK
}

// AWSKeyListDataSourceTFSDK is the Terraform state for the aws_key list data source.
// Filters is an optional map of API query parameters. Keys holds all matching keys.
// Matched is the total count returned by the API.
type AWSKeyListDataSourceTFSDK struct {
	Filters types.Map               `tfsdk:"filters"`
	Keys    []AWSKeyDataSourceTFSDK `tfsdk:"keys"`
	Matched types.Int64             `tfsdk:"matched"`
}

// AWSXKSKeyListDataSourceTFSDK is the Terraform state for the aws_xks_key list data source.
type AWSXKSKeyListDataSourceTFSDK struct {
	Filters types.Map                  `tfsdk:"filters"`
	Keys    []AWSXKSKeyDataSourceTFSDK `tfsdk:"keys"`
	Matched types.Int64                `tfsdk:"matched"`
}

// AWSCloudHSMKeyListDataSourceTFSDK is the Terraform state for the aws_cloudhsm_key list data source.
type AWSCloudHSMKeyListDataSourceTFSDK struct {
	Filters types.Map                       `tfsdk:"filters"`
	Keys    []AWSCloudHSMKeyDataSourceTFSDK `tfsdk:"keys"`
	Matched types.Int64                     `tfsdk:"matched"`
}

type AWSEnableXksCredentialRotationJobTFSDK struct {
	JobConfigID types.String `tfsdk:"job_config_id"`
}

type KeyRotationAwsParamTFSDK struct {
	ExpirationModel        types.String `tfsdk:"expiration_model"`
	ImportState            types.String `tfsdk:"import_state"`
	KeyID                  types.String `tfsdk:"key_id"`
	KeyMaterialDescription types.String `tfsdk:"key_material_description"`
	KeyMaterialID          types.String `tfsdk:"key_material_id"`
	KeyMaterialState       types.String `tfsdk:"key_material_state"`
	RotationDate           types.String `tfsdk:"rotation_date"`
	RotationType           types.String `tfsdk:"rotation_type"`
	ValidTo                types.String `tfsdk:"valid_to"`
}

type KeyRotationTFSDK struct {
	Account                types.String             `tfsdk:"account"`
	AwsParam               KeyRotationAwsParamTFSDK `tfsdk:"aws_params"`
	CreatedAt              types.String             `tfsdk:"created_at"`
	ID                     types.String             `tfsdk:"id"`
	KeyMaterialOrigin      types.String             `tfsdk:"key_material_origin"`
	KeySource              types.String             `tfsdk:"key_source"`
	KeySourceContainerID   types.String             `tfsdk:"key_source_container_id"`
	KeySourceContainerName types.String             `tfsdk:"key_source_container_name"`
	KmsID                  types.String             `tfsdk:"kms_id"`
	SourceKeyID            types.String             `tfsdk:"source_key_id"`
	SourceKeyName          types.String             `tfsdk:"source_key_name"`
	UpdatedAt              types.String             `tfsdk:"updated_at"`
	URI                    types.String             `tfsdk:"uri"`
}

type KMSAclTFSDK struct {
	ID         types.String `tfsdk:"id"`
	KmsID      types.String `tfsdk:"kms_id"`
	KmsActions types.Set    `tfsdk:"kms_actions"`
	acls.AclTFSDK
}

// commonAwsParamSchemaAttributes returns the schema attributes shared by the aws_param block
// in both the aws_key and aws_byok_key resources. These correspond to AWSCommonAwsParamTFSDK.
// For aws_byok_key the caller adds the additional valid_to attribute.
func commonAwsParamSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"alias": schema.SetAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable) Alias(es) of the key. To allow for key rotation changing or removing original aliases, all aliases already assigned to another key will be ignored.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
						"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
					),
				),
			},
		},
		"bypass_policy_lockout_safety_check": schema.BoolAttribute{
			Optional:    true,
			Description: "Whether to bypass the key policy lockout safety check.",
		},
		"customer_master_key_spec": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair. Valid values: " + strings.Join(awsKeySpecs, ", ") + ". Default is SYMMETRIC_DEFAULT.",
			Validators:  []validator.String{stringvalidator.OneOf(awsKeySpecs...)},
		},
		"description": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "(Updatable) Description of the AWS key. Descriptions can be updated but not removed.",
			Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
		},
		"key_usage": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Specifies the intended use of the key. Options are ENCRYPT_DECRYPT, SIGN_VERIFY and GENERATE_VERIFY_MAC.",
		},
		"multi_region": schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Creates or identifies a multi-region key.",
		},
		"current_key_material_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key material ID that is currently active for this key. Populated for EXTERNAL-origin keys.",
		},
		"policy": schema.StringAttribute{
			Computed:    true,
			Description: "Resulting AWS key policy after inputs are applied.",
		},
		"tags": schema.MapAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable) A list of tags assigned to the AWS key.",
		},
		// Computed-only fields sourced from aws_param in the CCKM API response.
		"arn": schema.StringAttribute{
			Computed:    true,
			Description: "The Amazon Resource Name (ARN) of the key.",
		},
		"aws_account_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS account ID.",
		},
		"key_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key ID.",
		},
		"deletion_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key is scheduled for deletion. Populated only when the key is pending deletion.",
		},
		"enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if the key is enabled in AWS.",
		},
		"encryption_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Encryption algorithms supported by the key. Populated for asymmetric keys.",
		},
		"expiration_model": schema.StringAttribute{
			Computed:    true,
			Description: "Expiration model for EXTERNAL-origin keys.",
		},
		"key_manager": schema.StringAttribute{
			Computed:    true,
			Description: "Key manager (e.g. CUSTOMER).",
		},
		"key_rotation_enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if AWS automatic key rotation is enabled.",
		},
		"key_state": schema.StringAttribute{
			Computed:    true,
			Description: "State of the key in AWS (e.g. Enabled, Disabled, PendingDeletion).",
		},
		"mac_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "MAC algorithms supported by the key. Populated for HMAC keys.",
		},
		"origin": schema.StringAttribute{
			Computed:    true,
			Description: "Origin of the key material (e.g. AWS_KMS, EXTERNAL).",
		},
		"replica_policy": schema.StringAttribute{
			Computed:    true,
			Description: "Key policy applied to replica keys for this multi-region key. Populated for multi-region primary keys.",
		},
		"replica_tags": schema.StringAttribute{
			Computed:    true,
			Description: "Tags applied to replica keys for this multi-region key. Raw JSON string. Populated for multi-region primary keys.",
		},
	}
}

// nativeKeyAwsParamSchemaAttributes returns the schema attributes for the aws_param block
// of the aws_key resource. It extends commonAwsParamSchemaAttributes with:
//   - auto_rotation_period_in_days (Optional/Computed) - rotation period in days for AWS auto-rotation
//   - next_rotation_date (Computed) - next scheduled AWS auto-rotation date
//
// These fields are native-key-only because AWS cannot auto-rotate EXTERNAL-origin (BYOK) keys.
func nativeKeyAwsParamSchemaAttributes() map[string]schema.Attribute {
	attrs := commonAwsParamSchemaAttributes()
	attrs["auto_rotation_period_in_days"] = schema.Int64Attribute{
		Optional:    true,
		Computed:    true,
		Description: "(Updatable) Rotation period in days for AWS auto-rotation. Only applicable to native symmetric keys.",
	}
	attrs["next_rotation_date"] = schema.StringAttribute{
		Computed:    true,
		Description: "Date of the next scheduled automatic rotation in AWS.",
	}
	return attrs
}

// byokAwsParamSchemaAttributes returns the schema attributes for the aws_param block
// of the aws_byok_key resource. It extends commonAwsParamSchemaAttributes with:
//   - valid_to (Optional/Computed) - expiry date supplied when uploading key material
//
// Note: auto_rotation_period_in_days and next_rotation_date are intentionally
// absent - AWS cannot auto-rotate EXTERNAL-origin (BYOK) keys because they
// require customer-supplied key material.
func byokAwsParamSchemaAttributes() map[string]schema.Attribute {
	attrs := commonAwsParamSchemaAttributes()
	attrs["valid_to"] = schema.StringAttribute{
		Optional:    true,
		Computed:    true,
		Description: "Date the key material expires (RFC3339). Set when uploading key material to apply an expiry; populated from the API response after creation.",
	}
	return attrs
}

// keyPolicySchemaAttribute returns the key_policy schema attribute shared by all four
// AWS key resources (aws_key, aws_byok_key, aws_xks_key, aws_cloudhsm_key).
func keyPolicySchemaAttribute() schema.Attribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Description: "(Updatable) Key policy parameters.",
		Attributes: map[string]schema.Attribute{
			"external_accounts": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that can access the key.",
			},
			"key_admins": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_users": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"policy": schema.StringAttribute{
				Optional:    true,
				Description: "AWS key policy json.",
			},
			"policy_template": schema.StringAttribute{
				Optional:    true,
				Description: "CipherTrust Manager policy template ID.",
			},
		},
	}
}

// enableRotationSchemaAttribute returns the enable_rotation schema attribute shared by all four
// AWS key resources (aws_key, aws_byok_key, aws_xks_key, aws_cloudhsm_key).
func enableRotationSchemaAttribute() schema.Attribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Description: "(Updatable) Register the key with a CipherTrust Manager scheduled rotation job. The 'disable_encrypt' and 'disable_encrypt_on_all_accounts' parameters are mutually exclusive.",
		Attributes: map[string]schema.Attribute{
			"job_config_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the scheduler configuration job.",
			},
			"key_source": schema.StringAttribute{
				Required:    true,
				Description: "Key source for rotation. Options: 'ciphertrust', 'local'.",
				Validators:  []validator.String{stringvalidator.OneOf([]string{"ciphertrust", "local"}...)},
			},
			"disable_encrypt": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable encryption on the old key after rotation.",
			},
			"disable_encrypt_on_all_accounts": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable encryption on the old key for all accounts after rotation.",
			},
		},
	}
}

// rotationHistoryNativeSummarySchemaAttribute returns the rotation_history schema for the
// aws_key resource. Shows a concise summary of each rotation entry for a native symmetric
// key. Fields are read-only (Computed). No uri or account fields are included.
func rotationHistoryNativeSummarySchemaAttribute() schema.Attribute {
	return schema.ListNestedAttribute{
		Computed:    true,
		Description: "Key material rotation history (up to 10 most recent entries, newest first).",
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"key_material_id": schema.StringAttribute{
					Computed:    true,
					Description: "AWS key material identifier.",
				},
				"rotation_date": schema.StringAttribute{
					Computed:    true,
					Description: "Date and time the rotation occurred.",
				},
				"key_material_state": schema.StringAttribute{
					Computed:    true,
					Description: "State of the key material (e.g. CURRENT, NON_CURRENT).",
				},
				"import_state": schema.StringAttribute{
					Computed:    true,
					Description: "AWS import state of the key material.",
				},
				"last_import_status": schema.StringAttribute{
					Computed:    true,
					Description: "Status of the last import operation.",
				},
			},
		},
	}
}

// rotationHistoryByokSummarySchemaAttribute returns the rotation_history schema for the
// aws_byok_key resource. Extends the native summary with source key fields relevant to
// EXTERNAL (BYOK) keys. Fields are read-only (Computed). No uri or account fields.
func rotationHistoryByokSummarySchemaAttribute() schema.Attribute {
	return schema.ListNestedAttribute{
		Computed:    true,
		Description: "Key material rotation history (up to 10 most recent entries, newest first).",
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"key_material_id": schema.StringAttribute{
					Computed:    true,
					Description: "AWS key material identifier.",
				},
				"rotation_date": schema.StringAttribute{
					Computed:    true,
					Description: "Date and time the rotation occurred.",
				},
				"key_material_state": schema.StringAttribute{
					Computed:    true,
					Description: "State of the key material (e.g. CURRENT, NON_CURRENT).",
				},
				"import_state": schema.StringAttribute{
					Computed:    true,
					Description: "AWS import state of the key material.",
				},
				"last_import_status": schema.StringAttribute{
					Computed:    true,
					Description: "Status of the last import operation.",
				},
				"source_key_identifier": schema.StringAttribute{
					Computed:    true,
					Description: "CipherTrust Manager key ID of the source key used for this material.",
				},
				"source_key_tier": schema.StringAttribute{
					Computed:    true,
					Description: "Tier of the source key (e.g. local).",
				},
			},
		},
	}
}

// rotationHistoryByokFullSchemaAttribute returns the full rotation_history schema for the
// aws_key_material resource (EXTERNAL/BYOK keys). Extends the native full schema with
// BYOK-specific source key fields. AWSKeyRotationParams fields are nested under aws_params
// to mirror the API response structure.
func rotationHistoryByokFullSchemaAttribute() schema.Attribute {
	return schema.ListNestedAttribute{
		Computed:    true,
		Description: "Rotation history for the key. Each entry represents one key material version.",
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"id": schema.StringAttribute{
					Computed:    true,
					Description: "Rotation history record ID.",
				},
				"created_at": schema.StringAttribute{
					Computed:    true,
					Description: "Date the rotation record was created.",
				},
				"updated_at": schema.StringAttribute{
					Computed:    true,
					Description: "Date the rotation record was last updated.",
				},
				"last_import_status": schema.StringAttribute{
					Computed:    true,
					Description: "Status of the last import operation.",
				},
				"last_import_error": schema.StringAttribute{
					Computed:    true,
					Description: "Error message from the last failed import, if any.",
				},
				"last_import_at": schema.StringAttribute{
					Computed:    true,
					Description: "Timestamp of the last import operation.",
				},
				"local_key_id": schema.StringAttribute{
					Computed:    true,
					Description: "CipherTrust Manager key ID of the AWS key.",
				},
				"source_key_identifier": schema.StringAttribute{
					Computed:    true,
					Description: "CipherTrust Manager ID of the source key used for this material.",
				},
				"source_key_name": schema.StringAttribute{
					Computed:    true,
					Description: "Name of the source key in CipherTrust Manager.",
				},
				"source_key_tier": schema.StringAttribute{
					Computed:    true,
					Description: "Tier of the source key (e.g. local).",
				},
				"key_source": schema.StringAttribute{
					Computed:    true,
					Description: "Source of the key material.",
				},
				"key_material_origin": schema.StringAttribute{
					Computed:    true,
					Description: "Origin of the key material (e.g. cckm).",
				},
				"kms_id": schema.StringAttribute{
					Computed:    true,
					Description: "KMS ID associated with this rotation record.",
				},
				"key_source_container_name": schema.StringAttribute{
					Computed:    true,
					Description: "Name of the container that holds the source key.",
				},
				"key_source_container_id": schema.StringAttribute{
					Computed:    true,
					Description: "ID of the container that holds the source key.",
				},
				// aws_params nests all AWSKeyRotationParams fields, matching the API response structure.
				"aws_params": schema.SingleNestedAttribute{
					Computed:    true,
					Description: "AWS key rotation parameters for this rotation entry.",
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Computed:    true,
							Description: "AWS key ID for this material entry.",
						},
						"rotation_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date this key material was rotated.",
						},
						"rotation_type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of rotation (e.g. ON_DEMAND).",
						},
						"key_material_id": schema.StringAttribute{
							Computed:    true,
							Description: "AWS key material ID.",
						},
						"key_material_description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of this key material version.",
						},
						"valid_to": schema.StringAttribute{
							Computed:    true,
							Description: "Expiry date of this key material.",
						},
						"expiration_model": schema.StringAttribute{
							Computed:    true,
							Description: "Expiration model for this key material.",
						},
						"key_material_state": schema.StringAttribute{
							Computed:    true,
							Description: "State of the key material (e.g. CURRENT, PENDING_ROTATION).",
						},
						"import_state": schema.StringAttribute{
							Computed:    true,
							Description: "Import state of the key material (e.g. IMPORTED, PENDING_IMPORT).",
						},
					},
				},
			},
		},
	}
}

// keyStoreResourceCommonAwsParamSchemaAttributes returns the schema attributes shared by the
// full aws_param block for both aws_xks_key and aws_cloudhsm_key resource types. The caller
// adds any type-specific fields (xks_key_configuration for XKS; key_rotation_enabled for CloudHSM).
func keyStoreResourceCommonAwsParamSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		// Input/Computed fields
		"alias": schema.SetAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable for linked keys) Alias(es) assigned to the key.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
						"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
					),
				),
			},
		},
		"description": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "(Updatable for linked keys) Description of the AWS key.",
		},
		"tags": schema.MapAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable for linked keys) Tags assigned to the key.",
		},
		// Computed-only fields sourced from aws_param in the CCKM API response
		"arn": schema.StringAttribute{
			Computed:    true,
			Description: "The Amazon Resource Name (ARN) of the key.",
		},
		"aws_account_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS account ID.",
		},
		"aws_custom_key_store_id": schema.StringAttribute{
			Computed:    true,
			Description: "Custom keystore ID in AWS.",
		},
		"customer_master_key_spec": schema.StringAttribute{
			Computed:    true,
			Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
		},
		"creation_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was created in AWS.",
		},
		"deletion_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key is scheduled for deletion. Populated only when the key is pending deletion.",
		},
		"enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if the key is enabled in AWS.",
		},
		"encryption_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Encryption algorithms supported by the key. Populated for asymmetric keys.",
		},
		"expiration_model": schema.StringAttribute{
			Computed:    true,
			Description: "Expiration model for the key material.",
		},
		"key_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key ID.",
		},
		"key_manager": schema.StringAttribute{
			Computed:    true,
			Description: "Key manager (e.g. CUSTOMER).",
		},
		"key_state": schema.StringAttribute{
			Computed:    true,
			Description: "State of the key in AWS (e.g. Enabled, Disabled, PendingDeletion).",
		},
		"key_usage": schema.StringAttribute{
			Computed:    true,
			Description: "Intended use of the key (e.g. ENCRYPT_DECRYPT).",
		},
		"mac_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "MAC algorithms supported by the key. Populated for HMAC keys.",
		},
		"origin": schema.StringAttribute{
			Computed:    true,
			Description: "Origin of the key material (e.g. EXTERNAL_KEY_STORE, AWS_CLOUDHSM).",
		},
		"policy": schema.StringAttribute{
			Computed:    true,
			Description: "Resulting AWS key policy. Output only.",
		},
	}
}

// xksKeyAwsParamSchemaAttributes returns the full aws_param schema for the aws_xks_key
// resource. It extends keyStoreResourceCommonAwsParamSchemaAttributes with xks_key_configuration,
// which holds the XksKeyConfiguration.Id value returned by AWS.
func xksKeyAwsParamSchemaAttributes() map[string]schema.Attribute {
	attrs := keyStoreResourceCommonAwsParamSchemaAttributes()
	attrs["xks_key_configuration"] = schema.SingleNestedAttribute{
		Computed:    true,
		Description: "XKS key configuration assigned by AWS. Present only for keys in an external key store.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the external key in its external key manager, used by the XKS proxy to identify the key.",
			},
		},
	}
	return attrs
}

// cloudHSMKeyAwsParamSchemaAttributes returns the full aws_param schema for the aws_cloudhsm_key
// resource. It extends keyStoreResourceCommonAwsParamSchemaAttributes with key_rotation_enabled.
// CloudHSM keys support AWS automatic key rotation; XKS keys do not.
func cloudHSMKeyAwsParamSchemaAttributes() map[string]schema.Attribute {
	attrs := keyStoreResourceCommonAwsParamSchemaAttributes()
	attrs["key_rotation_enabled"] = schema.BoolAttribute{
		Computed:    true,
		Description: "True if AWS automatic key rotation is enabled for this CloudHSM key.",
	}
	return attrs
}

// keyStoreAwsParamSchemaAttributes returns the schema attributes for the aws_param block
// shared by both the aws_xks_key and aws_cloudhsm_key resources. Alias, description, and
// tags are Optional/Computed inputs; policy is Computed-only (the resolved AWS key policy).
// Retained for use by datasource helpers that have not yet been migrated.
func keyStoreAwsParamSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"alias": schema.SetAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable for linked keys) Alias(es) assigned to the key.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
						"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
					),
				),
			},
		},
		"description": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "(Updatable for linked keys) Description of the AWS key.",
		},
		"policy": schema.StringAttribute{
			Computed:    true,
			Description: "Resulting AWS key policy. Output only.",
		},
		"tags": schema.MapAttribute{
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
			Description: "(Updatable for linked keys) Tags assigned to the key.",
		},
	}
}
