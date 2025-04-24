package cckm

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AWSParamTFSDK struct {
	CloudHSMClusterID              types.String `tfsdk:"cloud_hsm_cluster_id"`
	ConnectionState                types.String `tfsdk:"connection_state"`
	CustomKeystoreID               types.String `tfsdk:"custom_key_store_id"`
	CustomKeystoreName             types.String `tfsdk:"custom_key_store_name"`
	CustomKeystoreType             types.String `tfsdk:"custom_key_store_type"`
	KeyStorePassword               types.String `tfsdk:"key_store_password"`
	TrustAnchorCertificate         types.String `tfsdk:"trust_anchor_certificate"`
	XKSProxyConnectivity           types.String `tfsdk:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            types.String `tfsdk:"xks_proxy_uri_endpoint"`
	XKSProxyURIPath                types.String `tfsdk:"xks_proxy_uri_path"`
	XKSProxyVPCEndpointServiceName types.String `tfsdk:"xks_proxy_vpc_endpoint_service_name"`
}

type LocalHostedParamsTFSDK struct {
	Blocked               types.Bool   `tfsdk:"blocked"`
	HealthCheckCiphertext types.String `tfsdk:"health_check_ciphertext"`
	HealthCheckKeyID      types.String `tfsdk:"health_check_key_id"`
	LinkedState           types.Bool   `tfsdk:"linked_state"`
	MaxCredentials        types.Int32  `tfsdk:"max_credentials"`
	MTLSEnabled           types.Bool   `tfsdk:"mtls_enabled"`
	PartitionID           types.String `tfsdk:"partition_id"`
	PartitionLabel        types.String `tfsdk:"partition_label"`
	SourceContainerID     types.String `tfsdk:"source_container_id"`
	SourceContainerType   types.String `tfsdk:"source_container_type"`
	SourceKeyTier         types.String `tfsdk:"source_key_tier"`
}

type AWSCustomKeyStoreTFSDK struct {
	ID                        types.String   `tfsdk:"id"`
	AccessKeyID               types.String   `tfsdk:"access_key_id"`
	SecretAccessKey           types.String   `tfsdk:"secret_access_key"`
	CloudName                 types.String   `tfsdk:"cloud_name"`
	CredentialVersion         types.String   `tfsdk:"credential_version"`
	KMS                       types.String   `tfsdk:"kms"`
	KMSID                     types.String   `tfsdk:"kms_id"`
	Type                      types.String   `tfsdk:"type"`
	CreatedAt                 types.String   `tfsdk:"created_at"`
	UpdatedAt                 types.String   `tfsdk:"updated_at"`
	Name                      types.String   `tfsdk:"name"`
	Region                    types.String   `tfsdk:"region"`
	EnableSuccessAuditEvent   types.Bool     `tfsdk:"enable_success_audit_event"`
	LinkedState               types.Bool     `tfsdk:"linked_state"`
	ConnectDisconnectKeystore types.String   `tfsdk:"connect_disconnect_keystore"`
	AWSParams                 types.List     `tfsdk:"aws_param"`
	LocalHostedParams         types.List     `tfsdk:"local_hosted_params"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
}

type AWSKeyEnableRotationTFSDK struct {
	JobConfigID              types.String `tfsdk:"job_config_id"`
	AutoRotateDisableEncrypt types.Bool   `tfsdk:"disable_encrypt"`
	AutoRotateKeySource      types.String `tfsdk:"key_source"`
}

type AWSKeyImportKeyMaterialTFSDK struct {
	SourceKeyName types.String `tfsdk:"source_key_name"`
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
	KeyExpiration types.Bool   `tfsdk:"key_expiration"`
	ValidTo       types.String `tfsdk:"valid_to"`
}

type AWSKeyPolicyCommonTFSDK struct {
	ExternalAccounts types.List   `tfsdk:"external_accounts"`
	KeyAdmins        types.List   `tfsdk:"key_admins"`
	KeyAdminsRoles   types.List   `tfsdk:"key_admins_roles"`
	KeyUsers         types.List   `tfsdk:"key_users"`
	KeyUsersRoles    types.List   `tfsdk:"key_users_roles"`
	Policy           types.String `tfsdk:"policy"`
}

type AWSKeyPolicyTFSDK struct {
	AWSKeyPolicyCommonTFSDK
	PolicyTemplate types.String `tfsdk:"policy_template"`
}

type AWSKeyPolicyTemplateTFSDK struct {
	ID         types.String `tfsdk:"id"`
	Kms        types.String `tfsdk:"kms"`
	Name       types.String `tfsdk:"name"`
	AccountID  types.String `tfsdk:"account_id"`
	AutoPush   types.Bool   `tfsdk:"auto_push"`
	IsVerified types.Bool   `tfsdk:"is_verified"`
	AWSKeyPolicyCommonTFSDK
}

type AWSReplicateKeyTFSDK struct {
	KeyID             types.String `tfsdk:"key_id"`
	ImportKeyMaterial types.Bool   `tfsdk:"import_key_material"`
	KeyExpiration     types.Bool   `tfsdk:"key_expiration"`
	MakePrimary       types.Bool   `tfsdk:"make_primary"`
	ValidTo           types.String `tfsdk:"valid_to"`
}

type AWSUploadKeyTFSDK struct {
	SourceKeyID   types.String `tfsdk:"source_key_identifier"`
	KeyExpiration types.Bool   `tfsdk:"key_expiration"`
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
	ValidTo       types.String `tfsdk:"valid_to"`
}

type AWSKeyCommonTFSDK struct {
	ID                             types.String `tfsdk:"id"`
	Region                         types.String `tfsdk:"region"`
	Alias                          types.Set    `tfsdk:"alias"`
	BypassPolicyLockoutSafetyCheck types.Bool   `tfsdk:"bypass_policy_lockout_safety_check"`
	CustomerMasterKeySpec          types.String `tfsdk:"customer_master_key_spec"`
	Description                    types.String `tfsdk:"description"`
	EnableKey                      types.Bool   `tfsdk:"enable_key"`
	EnableRotation                 types.List   `tfsdk:"enable_rotation"`
	KeyUsage                       types.String `tfsdk:"key_usage"`
	Origin                         types.String `tfsdk:"origin"`
	ScheduleForDeletionDays        types.Int64  `tfsdk:"schedule_for_deletion_days"`
	Tags                           types.Map    `tfsdk:"tags"`
	ARN                            types.String `tfsdk:"arn"`
	AWSAccountID                   types.String `tfsdk:"aws_account_id"`
	AWSKeyID                       types.String `tfsdk:"aws_key_id"`
	CloudName                      types.String `tfsdk:"cloud_name"`
	CreatedAt                      types.String `tfsdk:"created_at"`
	DeletionDate                   types.String `tfsdk:"deletion_date"`
	Enabled                        types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms           types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel                types.String `tfsdk:"expiration_model"`
	ExternalAccounts               types.List   `tfsdk:"external_accounts"`
	KeyAdmins                      types.List   `tfsdk:"key_admins"`
	KeyAdminsRoles                 types.List   `tfsdk:"key_admins_roles"`
	KeyID                          types.String `tfsdk:"key_id"`
	KeyManager                     types.String `tfsdk:"key_manager"`
	KeyMaterialOrigin              types.String `tfsdk:"key_material_origin"`
	KeyPolicy                      types.List   `tfsdk:"key_policy"`
	KeyRotationEnabled             types.Bool   `tfsdk:"key_rotation_enabled"`
	KeySource                      types.String `tfsdk:"key_source"`
	KeyState                       types.String `tfsdk:"key_state"`
	KeyType                        types.String `tfsdk:"key_type"`
	KeyUsers                       types.List   `tfsdk:"key_users"`
	KeyUsersRoles                  types.List   `tfsdk:"key_users_roles"`
	Labels                         types.Map    `tfsdk:"labels"`
	LocalKeyID                     types.String `tfsdk:"local_key_id"`
	LocalKeyName                   types.String `tfsdk:"local_key_name"`
	Policy                         types.String `tfsdk:"policy"`
	PolicyTemplateTag              types.Map    `tfsdk:"policy_template_tag"`
	RotatedAt                      types.String `tfsdk:"rotated_at"`
	RotatedFrom                    types.String `tfsdk:"rotated_from"`
	RotatedTo                      types.String `tfsdk:"rotated_to"`
	RotationStatus                 types.String `tfsdk:"rotation_status"`
	SyncedAt                       types.String `tfsdk:"synced_at"`
	UpdatedAt                      types.String `tfsdk:"updated_at"`
	ValidTo                        types.String `tfsdk:"valid_to"`
}

type AWSKeyTFSDK struct {
	AWSKeyCommonTFSDK
	AutoRotate               types.Bool   `tfsdk:"auto_rotate"`
	AutoRotationPeriodInDays types.Int64  `tfsdk:"auto_rotation_period_in_days"`
	ImportKeyMaterial        types.List   `tfsdk:"import_key_material"`
	KMS                      types.String `tfsdk:"kms"`
	KMSID                    types.String `tfsdk:"kms_id"`
	MultiRegion              types.Bool   `tfsdk:"multi_region"`
	MultiRegionKeyType       types.String `tfsdk:"multi_region_key_type"`
	MultiRegionPrimaryKey    types.Map    `tfsdk:"multi_region_primary_key"`
	MultiRegionReplicaKeys   types.List   `tfsdk:"multi_region_replica_keys"`
	NextRotationDate         types.String `tfsdk:"next_rotation_date"`
	PrimaryRegion            types.String `tfsdk:"primary_region"`
	ReplicaPolicy            types.String `tfsdk:"replica_policy"`
	ReplicateKey             types.List   `tfsdk:"replicate_key"`
	UploadKey                types.List   `tfsdk:"upload_key"`
}

type XKSKeyLocalHostedParamsTFSDK struct {
	Blocked          types.Bool   `tfsdk:"blocked"`
	SourceKeyID      types.String `tfsdk:"source_key_id"`
	SourceKeyTier    types.String `tfsdk:"source_key_tier"`
	CustomKeyStoreID types.String `tfsdk:"custom_key_store_id"`
	Linked           types.Bool   `tfsdk:"linked"`
}

type AWSXKSKeyTFSDK struct {
	AWSKeyCommonTFSDK
	LocalHostParams        types.List   `tfsdk:"local_hosted_params"`
	KeySourceContainerName types.String `tfsdk:"key_source_container_name"`
	KeySourceContainerID   types.String `tfsdk:"key_source_container_id"`
	CustomKeyStoreID       types.String `tfsdk:"custom_key_store_id"`
	Linked                 types.Bool   `tfsdk:"linked"`
	Blocked                types.Bool   `tfsdk:"blocked"`
	AWSXKSKeyID            types.String `tfsdk:"aws_xks_key_id"`
	AWSCustomKeyStoreID    types.String `tfsdk:"aws_custom_key_store_id"`
}

type AWSAccountDetailsModelTFSDK struct {
	Connection           types.String `tfsdk:"aws_connection"`
	AssumeRoleArn        types.String `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID types.String `tfsdk:"assume_role_external_id"`
	AccountID            types.String `tfsdk:"account_id"`
	Regions              types.List   `tfsdk:"regions"`
	Validate             types.Bool   `tfsdk:"validate"`
}

type AWSParamJSON struct {
	CloudHSMClusterID              string `json:"cloud_hsm_cluster_id"`
	CustomKeystoreType             string `json:"custom_key_store_type"`
	KeyStorePassword               string `json:"key_store_password"`
	TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
	XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
}

type AWSParamJSONResponse struct {
	CloudHSMClusterID              string `json:"cloud_hsm_cluster_id"`
	ConnectionState                string `json:"connection_state"`
	CustomKeystoreID               string `json:"custom_key_store_id"`
	CustomKeystoreName             string `json:"custom_key_store_name"`
	CustomKeystoreType             string `json:"custom_key_store_type"`
	KeyStorePassword               string `json:"key_store_password"`
	TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
	XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
	XKSProxyURIPath                string `json:"xks_proxy_uri_path"`
	XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
}

type LocalHostedParamsJSON struct {
	Blocked          bool   `json:"blocked"`
	HealthCheckKeyID string `json:"health_check_key_id"`
	MaxCredentials   int32  `json:"max_credentials"`
	MTLSEnabled      bool   `json:"mtls_enabled"`
	PartitionID      string `json:"partition_id"`
	SourceKeyTier    string `json:"source_key_tier"`
}

type LocalHostedParamsJSONResponse struct {
	Blocked               bool   `json:"blocked"`
	HealthCheckCiphertext string `json:"health_check_ciphertext"`
	HealthCheckKeyID      string `json:"health_check_key_id"`
	LinkedState           bool   `json:"linked_state"`
	MaxCredentials        int32  `json:"max_credentials"`
	MTLSEnabled           bool   `json:"mtls_enabled"`
	PartitionID           string `json:"partition_id"`
	PartitionLabel        string `json:"partition_label"`
	SourceContainerID     string `json:"source_container_id"`
	SourceContainerType   string `json:"source_container_type"`
	SourceKeyTier         string `json:"source_key_tier"`
}

type AWSCustomKeyStoreJSON struct {
	ID                      string                 `json:"id"`
	AWSParams               *AWSParamJSON          `json:"aws_param"`
	KMS                     string                 `json:"kms"`
	Name                    string                 `json:"name"`
	Region                  string                 `json:"region"`
	EnableSuccessAuditEvent bool                   `json:"enable_success_audit_event"`
	LinkedState             bool                   `json:"linked_state"`
	LocalHostedParams       *LocalHostedParamsJSON `json:"local_hosted_params"`
	KeyStorePassword        string                 `json:"key_store_password"`
}

type AWSKeyParamTagJSON struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}

type CommonAWSParamsJSON struct {
	Alias                          string               `json:"Alias"`
	BypassPolicyLockoutSafetyCheck bool                 `json:"BypassPolicyLockoutSafetyCheck"`
	CustomerMasterKeySpec          string               `json:"CustomerMasterKeySpec"`
	Description                    string               `json:"Description"`
	KeyUsage                       string               `json:"KeyUsage"`
	MultiRegion                    bool                 `json:"MultiRegion"`
	Policy                         json.RawMessage      `json:"Policy"`
	Tags                           []AWSKeyParamTagJSON `json:"Tags"`
}

type AWSKeyParamJSON struct {
	CommonAWSParamsJSON
	Origin string `json:"Origin"`
}

type CommonAWSKeyCreatePayloadJSON struct {
	KMS              string    `json:"kms"`
	Region           string    `json:"region"`
	ExternalAccounts *[]string `json:"external_accounts"`
	KeyAdmins        *[]string `json:"key_admins"`
	KeyAdminsRoles   *[]string `json:"key_admins_roles"`
	KeyUsers         *[]string `json:"key_users"`
	KeyUsersRoles    *[]string `json:"key_users_roles"`
	PolicyTemplate   *string   `json:"policytemplate"`
}

type CreateAWSKeyPayloadJSON struct {
	CommonAWSKeyCreatePayloadJSON
	AWSParam AWSKeyParamJSON `json:"aws_param"`
}

type UploadAWSKeyParamJSON struct {
	CommonAWSParamsJSON
	ValidTo string `json:"ValidTo"`
}

type UploadAWSKeyPayloadJSON struct {
	CommonAWSKeyCreatePayloadJSON
	AWSParam            *UploadAWSKeyParamJSON `json:"aws_param"`
	SourceKeyIdentifier string                 `json:"source_key_identifier"`
	KeyExpiration       bool                   `json:"key_expiration"`
	SourceKeyTier       string                 `json:"source_key_tier"`
}

type AWSKeyImportKeyPayloadJSON struct {
	SourceKeyID   string `json:"source_key_identifier"`
	SourceKeyTier string `json:"source_key_tier"`
	KeyExpiration bool   `json:"key_expiration"`
	ValidTo       string `json:"valid_to"`
}

type AWSEnableKeyRotationJobPayloadJSON struct {
	JobConfigID              string  `json:"job_config_id"`
	AutoRotateDisableEncrypt bool    `json:"auto_rotate_disable_encrypt"`
	AutoRotateKeySource      *string `json:"auto_rotate_key_source"`
}

type AWSKeyJSON struct {
	ID                           string               `json:"id"`
	KMS                          string               `json:"kms"`
	Region                       string               `json:"region"`
	AWSParam                     *AWSKeyParamJSON     `json:"aws_param"`
	JobConfigID                  string               `json:"job_config_id"`
	AutoRotateDisableEncrypt     bool                 `json:"auto_rotate_disable_encrypt"`
	AutoRotateDomainID           string               `json:"auto_rotate_domain_id"`
	AutoRotateExternalCMDomainID string               `json:"auto_rotate_external_cm_domain_id"`
	AutoRotateKeySource          string               `json:"auto_rotate_key_source"`
	AutoRotatePartitionID        string               `json:"auto_rotate_partition_id"`
	KeyExpiration                bool                 `json:"key_expiration"`
	SourceKeyIdentifier          string               `json:"source_key_identifier"`
	SourceKeyTier                string               `json:"source_key_tier"`
	ValidTo                      string               `json:"valid_to"`
	DisableEncrypt               bool                 `json:"disable_encrypt"`
	RetainAlias                  bool                 `json:"retain_alias"`
	SourceKeyID                  string               `json:"source_key_id"`
	Days                         int64                `json:"days"`
	Tags                         []AWSKeyParamTagJSON `json:"tags"`
	//	DeleteTags                            []string             `json:"delete_tags"`
	Alias                string `json:"alias"`
	RotationPeriodInDays int64  `json:"rotation_period_in_days"`
}

type KMSModelTFSDK struct {
	ID                   types.String `tfsdk:"id"`
	URI                  types.String `tfsdk:"uri"`
	Account              types.String `tfsdk:"account"`
	Application          types.String `tfsdk:"application"`
	DevAccount           types.String `tfsdk:"dev_account"`
	CreatedAt            types.String `tfsdk:"created_at"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
	AccountID            types.String `tfsdk:"account_id"`
	Connection           types.String `tfsdk:"aws_connection"`
	Name                 types.String `tfsdk:"name"`
	Regions              types.List   `tfsdk:"regions"`
	AssumeRoleARN        types.String `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID types.String `tfsdk:"assume_role_external_id"`
	Arn                  types.String `tfsdk:"arn"`
}

type KMSModelJSON struct {
	AccountID            string   `json:"account_id"`
	Connection           string   `json:"connection"`
	Name                 string   `json:"name"`
	Regions              []string `json:"regions"`
	AssumeRoleARN        string   `json:"assume_role_arn"`
	AssumeRoleExternalID string   `json:"assume_role_external_id"`
}

type AccountDetailsInputModelJSON struct {
	AwsConnection        string `json:"connection"`
	AssumeRoleArn        string `json:"assume_role_arn"`
	AssumeRoleExternalID string `json:"assume_role_external_id"`
}

type AccountDetailsOutputModelJSON struct {
	AccountID string   `json:"account_id"`
	Regions   []string `json:"regions"`
}

type AddTagPayloadJSON struct {
	TagKey   string `json:"tag_key"`
	TagValue string `json:"tag_value"`
}

type CreateReplicaKeyPayloadJSON struct {
	AwsParams        CommonAWSParamsJSON `json:"aws_param"`
	ReplicaRegion    *string             `json:"replica_region"`
	Tags             []AddTagPayloadJSON `json:"tags"`
	KmsID            string              `json:"kms"`
	KeyUsers         *[]string           `json:"key_users"`
	KeyAdmins        *[]string           `json:"key_admins"`
	KeyAdminsRoles   *[]string           `json:"key_admins_roles"`
	KeyUsersRoles    *[]string           `json:"key_users_roles"`
	ExternalAccounts *[]string           `json:"external_accounts"`
	PolicyTemplate   *string             `json:"policytemplate"`
}

type AddRemoveAliasPayloadJSON struct {
	Alias string `json:"alias"`
}

type UpdateKeyDescriptionPayloadJSON struct {
	Description string `json:"description"`
}

type ScheduleForDeletionJSON struct {
	Days int64 `json:"days"`
}

type RemoveTagsJSON struct {
	Tags []*string `json:"tags"`
}

type AddTagsJSON struct {
	Tags []AddTagPayloadJSON `json:"tags"`
}

type KeyPolicyParamsJSON struct {
	ExternalAccounts *[]string        `json:"external_accounts"`
	KeyAdmins        *[]string        `json:"key_admins"`
	KeyAdminsRoles   *[]string        `json:"key_admins_roles"`
	KeyUsers         *[]string        `json:"key_users"`
	KeyUsersRoles    *[]string        `json:"key_users_roles"`
	Policy           *json.RawMessage `json:"Policy"`
}

type KeyPolicyPayloadJSON struct {
	KeyPolicyParamsJSON
	PolicyTemplate *string `json:"policytemplate"`
}

type PolicyTemplatePayloadJSON struct {
	AccountID string `json:"account_id"`
	Kms       string `json:"kms"`
	Name      string `json:"name"`
	KeyPolicyParamsJSON
}

type KeyPolicyTemplateUpdatePayloadJSON struct {
	KeyPolicyParamsJSON
	AutoPush bool `json:"auto_push"`
}

type EnableAutoRotationPayloadJSON struct {
	RotationPeriodInDays *int64 `json:"rotation_period_in_days"`
}

type UpdatePrimaryRegionJSON struct {
	PrimaryRegion *string `json:"PrimaryRegion"`
}

type XKSKeyCommonAWSParamsJSON struct {
	Description *string               `json:"Description"`
	Policy      *json.RawMessage      `json:"Policy,omitempty"`
	Tags        []*AWSKeyParamTagJSON `json:"Tags"`
	Alias       string                `json:"Alias"`
}

type LinkXKSKeyAWSParamsJSON struct {
	AwsParams                      XKSKeyCommonAWSParamsJSON `json:"aws_param"`
	BypassPolicyLockoutSafetyCheck *bool                     `json:"BypassPolicyLockoutSafetyCheck"`
}

type XKSKeyLocalHostedInputParamsJSON struct {
	SourceKeyIdentifier string `json:"source_key_id"`
	CustomKeyStoreID    string `json:"custom_key_store_id"`
	Blocked             bool   `json:"blocked"`
	LinkedState         bool   `json:"linked_state"`
	SourceKeyTier       string `json:"source_key_tier"`
}

type CreateXKSKeyInputPayloadJSON struct {
	AwsParams                        XKSKeyCommonAWSParamsJSON `json:"aws_param"`
	KeyUsers                         *[]string                 `json:"key_users"`
	KeyAdmins                        *[]string                 `json:"key_admins"`
	KeyUsersRoles                    *[]string                 `json:"key_users_roles"`
	KeyAdminsRoles                   *[]string                 `json:"key_admins_roles"`
	ExternalAccounts                 *[]string                 `json:"external_accounts"`
	PolicyTemplate                   *string                   `json:"policytemplate"`
	XKSKeyLocalHostedInputParamsJSON `json:"local_hosted_params"`
}

type AWSKeyDataSourceTFSDK struct {
	AWSKeyDataSourceCommonTFSDK
	AutoRotate               types.Bool   `tfsdk:"auto_rotate"`
	AutoRotationPeriodInDays types.Int64  `tfsdk:"auto_rotation_period_in_days"`
	KMS                      types.String `tfsdk:"kms"`
	KMSID                    types.String `tfsdk:"kms_id"`
	MultiRegion              types.Bool   `tfsdk:"multi_region"`
	MultiRegionKeyType       types.String `tfsdk:"multi_region_key_type"`
	MultiRegionPrimaryKey    types.Map    `tfsdk:"multi_region_primary_key"`
	MultiRegionReplicaKeys   types.List   `tfsdk:"multi_region_replica_keys"`
	NextRotationDate         types.String `tfsdk:"next_rotation_date"`
	ReplicaPolicy            types.String `tfsdk:"replica_policy"`
}

type AWSKeyDataSourceCommonTFSDK struct {
	ID                    types.String `tfsdk:"id"`
	Region                types.String `tfsdk:"region"`
	Alias                 types.Set    `tfsdk:"alias"`
	CustomerMasterKeySpec types.String `tfsdk:"customer_master_key_spec"`
	Description           types.String `tfsdk:"description"`
	EnableKey             types.Bool   `tfsdk:"enable_key"`
	KeyUsage              types.String `tfsdk:"key_usage"`
	Origin                types.String `tfsdk:"origin"`
	Tags                  types.Map    `tfsdk:"tags"`
	ARN                   types.String `tfsdk:"arn"`
	AWSAccountID          types.String `tfsdk:"aws_account_id"`
	AWSKeyID              types.String `tfsdk:"aws_key_id"`
	CloudName             types.String `tfsdk:"cloud_name"`
	CreatedAt             types.String `tfsdk:"created_at"`
	DeletionDate          types.String `tfsdk:"deletion_date"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	EncryptionAlgorithms  types.List   `tfsdk:"encryption_algorithms"`
	ExpirationModel       types.String `tfsdk:"expiration_model"`
	ExternalAccounts      types.List   `tfsdk:"external_accounts"`
	KeyAdmins             types.List   `tfsdk:"key_admins"`
	KeyAdminsRoles        types.List   `tfsdk:"key_admins_roles"`
	KeyID                 types.String `tfsdk:"key_id"`
	KeyManager            types.String `tfsdk:"key_manager"`
	KeyMaterialOrigin     types.String `tfsdk:"key_material_origin"`
	KeyRotationEnabled    types.Bool   `tfsdk:"key_rotation_enabled"`
	KeySource             types.String `tfsdk:"key_source"`
	KeyState              types.String `tfsdk:"key_state"`
	KeyType               types.String `tfsdk:"key_type"`
	KeyUsers              types.List   `tfsdk:"key_users"`
	KeyUsersRoles         types.List   `tfsdk:"key_users_roles"`
	Labels                types.Map    `tfsdk:"labels"`
	LocalKeyID            types.String `tfsdk:"local_key_id"`
	LocalKeyName          types.String `tfsdk:"local_key_name"`
	Policy                types.String `tfsdk:"policy"`
	PolicyTemplateTag     types.Map    `tfsdk:"policy_template_tag"`
	RotatedAt             types.String `tfsdk:"rotated_at"`
	RotatedFrom           types.String `tfsdk:"rotated_from"`
	RotatedTo             types.String `tfsdk:"rotated_to"`
	RotationStatus        types.String `tfsdk:"rotation_status"`
	SyncedAt              types.String `tfsdk:"synced_at"`
	UpdatedAt             types.String `tfsdk:"updated_at"`
	ValidTo               types.String `tfsdk:"valid_to"`
}

type AWSXKSKeyDataSourceTFSDK struct {
	AWSKeyDataSourceCommonTFSDK
	KMS                 types.String `tfsdk:"kms"`
	Linked              types.Bool   `tfsdk:"linked"`
	Blocked             types.Bool   `tfsdk:"blocked"`
	AWSXKSKeyID         types.String `tfsdk:"aws_xks_key_id"`
	AWSCustomKeyStoreID types.String `tfsdk:"aws_custom_key_store_id"`
	SourceKeyTier       types.String `tfsdk:"source_key_tier"`
}
