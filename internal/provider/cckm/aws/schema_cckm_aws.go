package cckm

import "github.com/hashicorp/terraform-plugin-framework/types"

type AWSParamTFSDK struct {
	CloudHSMClusterID              types.String `tfsdk:"cloud_hsm_cluster_id"`
	XKSType                        types.String `tfsdk:"custom_key_store_type"`
	KeyStorePassword               types.String `tfsdk:"key_store_password"`
	TrustAnchorCertificate         types.String `tfsdk:"trust_anchor_certificate"`
	XKSProxyConnectivity           types.String `tfsdk:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            types.String `tfsdk:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName types.String `tfsdk:"xks_proxy_vpc_endpoint_service_name"`
}
type LocalHostedParamsTFSDK struct {
	Blocked          types.Bool   `tfsdk:"blocked"`
	HealthCheckKeyID types.String `tfsdk:"health_check_key_id"`
	MaxCredentials   types.String `tfsdk:"max_credentials"`
	MTLSEnabled      types.Bool   `tfsdk:"mtls_enabled"`
	PartitionID      types.String `tfsdk:"partition_id"`
	SourceKeyTier    types.String `tfsdk:"source_key_tier"`
}
type AWSCustomKeyStoreTFSDK struct {
	ID                      types.String           `tfsdk:"id"`
	AccessKeyID             types.String           `tfsdk:"access_key_id"`
	CloudName               types.String           `tfsdk:"cloud_name"`
	CreatedAt               types.String           `tfsdk:"created_at"`
	CredentialVersion       types.String           `tfsdk:"credential_version"`
	KMSID                   types.String           `tfsdk:"kms_id"`
	SecretAccessKey         types.String           `tfsdk:"secret_access_key"`
	Type                    types.String           `tfsdk:"type"`
	UpdatedAt               types.String           `tfsdk:"updated_at"`
	AWSParams               AWSParamTFSDK          `tfsdk:"aws_param"`
	KMS                     types.String           `tfsdk:"kms"`
	Name                    types.String           `tfsdk:"name"`
	Region                  types.String           `tfsdk:"region"`
	EnableSuccessAuditEvent types.Bool             `tfsdk:"enable_success_audit_event"`
	LinkedState             types.Bool             `tfsdk:"linked_state"`
	LocalHostedParams       LocalHostedParamsTFSDK `tfsdk:"local_hosted_params"`
	UpdateOpType            types.String           `tfsdk:"update_op_type"`
}
type AWSKeyParamTagTFSDK struct {
	TagKey   types.String `tfsdk:"tag_key"`
	TagValue types.String `tfsdk:"tag_values"`
}
type AWSKeyParamTFSDK struct {
	Alias                          types.String          `tfsdk:"alias"`
	BypassPolicyLockoutSafetyCheck types.Bool            `tfsdk:"bypass_policy_lockout_safety_check"`
	CustomerMasterKeySpec          types.String          `tfsdk:"customer_master_key_spec"`
	Description                    types.String          `tfsdk:"description"`
	KeyUsage                       types.String          `tfsdk:"key_usage"`
	MultiRegion                    types.Bool            `tfsdk:"multi_region"`
	Origin                         types.String          `tfsdk:"origin"`
	Policy                         types.Map             `tfsdk:"policy"`
	Tags                           []AWSKeyParamTagTFSDK `tfsdk:"tags"`
}
type AWSKeyEnableRotationTFSDK struct {
	JobConfigID                           types.String `tfsdk:"job_config_id"`
	AutoRotateDisableEncrypt              types.Bool   `tfsdk:"disable_encrypt"`
	AutoRotateDisableEncryptOnAllAccounts types.Bool   `tfsdk:"disable_encrypt_on_all_accounts"`
	AutoRotateDomainID                    types.String `tfsdk:"dsm_domain_id"`
	AutoRotateExternalCMDomainID          types.String `tfsdk:"external_cm_domain_id"`
	AutoRotateKeySource                   types.String `tfsdk:"key_source"`
	AutoRotatePartitionID                 types.String `tfsdk:"hsm_partition_id"`
}
type AWSKeyImportKeyMaterialTFSDK struct {
	SourceKeyName  types.String `tfsdk:"source_key_name"`
	DSMDomainID    types.String `tfsdk:"dsm_domain_id"`
	HSMPartitionID types.String `tfsdk:"hsm_partition_id"`
	SourceKeyTier  types.String `tfsdk:"source_key_tier"`
	KeyExpiration  types.Bool   `tfsdk:"key_expiration"`
	ValidTo        types.String `tfsdk:"valid_to"`
}
type AWSKeyPolicyTFSDK struct {
	ExternalAccounts []types.String `tfsdk:"external_accounts"`
	KeyAdmins        []types.String `tfsdk:"key_admins"`
	KeyAdminRoles    []types.String `tfsdk:"key_admins_roles"`
	KeyUsers         []types.String `tfsdk:"key_users"`
	KeyUserRoles     []types.String `tfsdk:"key_users_roles"`
	Policy           types.String   `tfsdk:"policy"`
	PolicyTemplate   types.String   `tfsdk:"policytemplate"`
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
type AWSKeyTFSDK struct {
	ID                             types.String                  `tfsdk:"id"`
	Region                         types.String                  `tfsdk:"region"`
	AliasKMSKey                    types.String                  `tfsdk:"alias_kms_key"`
	Alias                          []types.String                `tfsdk:"alias"`
	AWSKeyPolicy                   types.Map                     `tfsdk:"policy"`
	AutoRotate                     types.Bool                    `tfsdk:"auto_rotate"`
	BypassPolicyLockoutSafetyCheck types.Bool                    `tfsdk:"bypass_policy_lockout_safety_check"`
	CustomerMasterKeySpec          types.String                  `tfsdk:"customer_master_key_spec"`
	Description                    types.String                  `tfsdk:"description"`
	EnableKey                      types.Bool                    `tfsdk:"enable_key"`
	EnableRotation                 *AWSKeyEnableRotationTFSDK    `tfsdk:"enable_rotation"`
	ImportKeyMaterials             *AWSKeyImportKeyMaterialTFSDK `tfsdk:"import_key_material"`
	KeyPolicy                      *AWSKeyPolicyTFSDK            `tfsdk:"key_policy"`
	KeyUsage                       types.String                  `tfsdk:"key_usage"`
	KMS                            types.String                  `tfsdk:"kms"`
	MultiRegion                    types.Bool                    `tfsdk:"multi_region"`
	Origin                         types.String                  `tfsdk:"origin"`
	PrimaryRegion                  types.Bool                    `tfsdk:"primary_region"`
	ReplicateKey                   *AWSReplicateKeyTFSDK         `tfsdk:"replicate_key"`
	ScheduleForDeletionDays        types.Int64                   `tfsdk:"schedule_for_deletion_days"`
	Tags                           []AWSKeyParamTagTFSDK         `tfsdk:"tags"`
	UploadKey                      *AWSUploadKeyTFSDK            `tfsdk:"upload_key"`
	ARN                            types.String                  `tfsdk:"arn"`
	AWSAccountID                   types.String                  `tfsdk:"aws_account_id"`
	AWSKeyID                       types.String                  `tfsdk:"aws_key_id"`
	CloudName                      types.String                  `tfsdk:"cloud_name"`
	CreatedAt                      types.String                  `tfsdk:"created_at"`
	DeletionDate                   types.String                  `tfsdk:"deletion_date"`
	Enabled                        types.Bool                    `tfsdk:"enabled"`
	EncryptionAlgorithms           []types.String                `tfsdk:"encryption_algorithms"`
	ExpirationModel                types.String                  `tfsdk:"expiration_model"`
	ExternalAccounts               []types.String                `tfsdk:"external_accounts"`
	KeyAdmins                      []types.String                `tfsdk:"key_admins"`
	KeyAdminsRoles                 []types.String                `tfsdk:"key_admins_roles"`
	KeyID                          types.String                  `tfsdk:"key_id"`
	KeyManager                     types.String                  `tfsdk:"key_manager"`
	KeyMaterialOrigin              types.String                  `tfsdk:"key_material_origin"`
	KeyRotationEnabled             types.Bool                    `tfsdk:"key_rotation_enabled"`
	KeySource                      types.String                  `tfsdk:"key_source"`
	KeyState                       types.String                  `tfsdk:"key_state"`
	KeyType                        types.String                  `tfsdk:"key_type"`
	KeyUsers                       []types.String                `tfsdk:"key_users"`
	KeyUsersRoles                  []types.String                `tfsdk:"key_users_roles"`
	KMSID                          types.String                  `tfsdk:"kms_id"`
	Labels                         types.Map                     `tfsdk:"labels"`
	LocalKeyID                     types.String                  `tfsdk:"local_key_id"`
	LocalKeyName                   types.String                  `tfsdk:"local_key_name"`
	MultiRegionKeyType             types.String                  `tfsdk:"multi_region_key_type"`
	MultiRegionPrimaryKey          types.Map                     `tfsdk:"multi_region_primary_key"`
	MultiRegionReplicaKeys         []types.Map                   `tfsdk:"multi_region_replica_keys"`
	Policy                         types.String                  `tfsdk:"policy"`
	PolicyTemplateTag              types.Map                     `tfsdk:"policy_template_tag"`
	ReplicaPolicy                  types.String                  `tfsdk:"replica_policy"`
	RotatedAt                      types.String                  `tfsdk:"rotated_at"`
	RotatedFrom                    types.String                  `tfsdk:"rotated_from"`
	RotatedTo                      types.String                  `tfsdk:"rotated_to"`
	RotationStatus                 types.String                  `tfsdk:"rotation_status"`
	SyncedAt                       types.String                  `tfsdk:"synced_at"`
	UpdatedAt                      types.String                  `tfsdk:"updated_at"`
	ValidTo                        types.String                  `tfsdk:"valid_to"`
}

type AWSParamJSON struct {
	CloudHSMClusterID              string `json:"cloud_hsm_cluster_id"`
	XKSType                        string `json:"custom_key_store_type"`
	KeyStorePassword               string `json:"key_store_password"`
	TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
	XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
}
type LocalHostedParamsJSON struct {
	Blocked          bool   `json:"blocked"`
	HealthCheckKeyID string `json:"health_check_key_id"`
	MaxCredentials   string `json:"max_credentials"`
	MTLSEnabled      bool   `json:"mtls_enabled"`
	PartitionID      string `json:"partition_id"`
	SourceKeyTier    string `json:"source_key_tier"`
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
	Alias                          string                 `json:"Alias"`
	BypassPolicyLockoutSafetyCheck bool                   `json:"BypassPolicyLockoutSafetyCheck"`
	CustomerMasterKeySpec          string                 `json:"CustomerMasterKeySpec"`
	Description                    string                 `json:"Description"`
	KeyUsage                       string                 `json:"KeyUsage"`
	MultiRegion                    bool                   `json:"MultiRegion"`
	Policy                         map[string]interface{} `json:"Policy"`
	Tags                           []AWSKeyParamTagJSON   `json:"Tags"`
}
type AWSKeyParamJSON struct {
	CommonAWSParamsJSON
	Origin string `json:"Origin"`
}
type CommonAWSKeyCreatePayloadJSON struct {
	KMS              string   `json:"kms"`
	Region           string   `json:"region"`
	ExternalAccounts []string `json:"external_accounts"`
	KeyAdmins        []string `json:"key_admins"`
	KeyAdminsRoles   []string `json:"key_admins_roles"`
	KeyUsers         []string `json:"key_users"`
	KeyUsersRoles    []string `json:"key_users_roles"`
	PolicyTemplate   string   `json:"policytemplate"`
}
type CreateAWSKeyPayloadJSON struct {
	CommonAWSKeyCreatePayloadJSON
	AWSParam *AWSKeyParamJSON `json:"aws_param"`
}
type UploadAWSKeyParamJSON struct {
	CommonAWSParamsJSON
	ValidTo string `json:"validTo"`
}
type UploadAWSKeyPayloadJSON struct {
	CommonAWSKeyCreatePayloadJSON
	AWSParam            *UploadAWSKeyParamJSON `json:"aws_param"`
	SourceKeyIdentifier string                 `json:"source_key_identifier"`
	KeyExpiration       bool                   `json:"key_expiration"`
	SourceKeyTier       string                 `json:"source_key_tier"`
}
type AWSKeyImportKeyPayloadJSON struct {
	SourceKeyID   string `tfsdk:"source_key_identifier"`
	SourceKeyTier string `tfsdk:"source_key_tier"`
	KeyExpiration bool   `tfsdk:"key_expiration"`
	ValidTo       string `tfsdk:"valid_to"`
}
type AWSEnableKeyRotationJobPayloadJSON struct {
	JobConfigID                           string `json:"job_config_id"`
	AutoRotateDisableEncrypt              bool   `json:"auto_rotate_disable_encrypt"`
	AutoRotateDisableEncryptOnAllAccounts bool   `json:"auto_rotate_disable_encrypt_on_all_accounts"`
	AutoRotateDomainID                    string `json:"auto_rotate_domain_id"`
	AutoRotateExternalCMDomainID          string `json:"auto_rotate_external_cm_domain_id"`
	AutoRotateKeySource                   string `json:"auto_rotate_key_source"`
	AutoRotatePartitionID                 string `json:"auto_rotate_partition_id"`
}
type AWSKeyJSON struct {
	ID                                    string               `json:"id"`
	KMS                                   string               `json:"kms"`
	Region                                string               `json:"region"`
	AWSParam                              *AWSKeyParamJSON     `json:"aws_param"`
	JobConfigID                           string               `json:"job_config_id"`
	AutoRotateDisableEncrypt              bool                 `json:"auto_rotate_disable_encrypt"`
	AutoRotateDisableEncryptOnAllAccounts bool                 `json:"auto_rotate_disable_encrypt_on_all_accounts"`
	AutoRotateDomainID                    string               `json:"auto_rotate_domain_id"`
	AutoRotateExternalCMDomainID          string               `json:"auto_rotate_external_cm_domain_id"`
	AutoRotateKeySource                   string               `json:"auto_rotate_key_source"`
	AutoRotatePartitionID                 string               `json:"auto_rotate_partition_id"`
	KeyExpiration                         bool                 `json:"key_expiration"`
	SourceKeyIdentifier                   string               `json:"source_key_identifier"`
	SourceKeyTier                         string               `json:"source_key_tier"`
	ValidTo                               string               `json:"valid_to"`
	DisableEncrypt                        bool                 `json:"disable_encrypt"`
	DisableEncryptOnAllAccounts           bool                 `json:"disable_encrypt_on_all_accounts"`
	RetainAlias                           bool                 `json:"retain_alias"`
	SourceKeyID                           string               `json:"source_key_id"`
	Days                                  int64                `json:"days"`
	Tags                                  []AWSKeyParamTagJSON `json:"tags"`
	DeleteTags                            []string             `json:"delete_tags"`
	Alias                                 string               `json:"alias"`
	RotationPeriodInDays                  int64                `json:"rotation_period_in_days"`
}

type KMSModelTFSDK struct {
	ID                   types.String   `tfsdk:"id"`
	URI                  types.String   `tfsdk:"uri"`
	Account              types.String   `tfsdk:"account"`
	Application          types.String   `tfsdk:"application"`
	DevAccount           types.String   `tfsdk:"dev_account"`
	CreatedAt            types.String   `tfsdk:"created_at"`
	UpdatedAt            types.String   `tfsdk:"updated_at"`
	AccountID            types.String   `tfsdk:"account_id"`
	Connection           types.String   `tfsdk:"connection"`
	Name                 types.String   `tfsdk:"name"`
	Regions              []types.String `tfsdk:"regions"`
	AssumeRoleARN        types.String   `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID types.String   `tfsdk:"assume_role_external_id"`
}

type KMSModelJSON struct {
	AccountID            string   `json:"account_id"`
	Connection           string   `json:"connection"`
	Name                 string   `json:"name"`
	Regions              []string `json:"regions"`
	AssumeRoleARN        string   `json:"assume_role_arn"`
	AssumeRoleExternalID string   `json:"assume_role_external_id"`
}
