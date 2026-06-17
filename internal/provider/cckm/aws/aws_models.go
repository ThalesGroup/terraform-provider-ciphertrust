package cckm

import (
	"encoding/json"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
)

// RotateMaterialPayloadJSON is the request body for the rotate-material API.
// When source_key_identifier and source_key_tier are supplied, CCKM both imports
// the material and rotates to it (two AWS API calls). When all fields are empty,
// only the AWS rotate-material API is called - used to resume a PENDING_ROTATION.
type RotateMaterialPayloadJSON struct {
	SourceKeyID            string `json:"source_key_identifier,omitempty"`
	SourceKeyTier          string `json:"source_key_tier,omitempty"`
	KeyMaterialDescription string `json:"key_material_description,omitempty"`
	ValidTo                string `json:"valid_to,omitempty"`
	KeyExpiration          bool   `json:"key_expiration"`
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
	ConnectionErrorDetails         string `json:"connection_error_details"`
	CustomKeystoreID               string `json:"custom_key_store_id"`
	CustomKeystoreName             string `json:"custom_key_store_name"`
	CustomKeystoreType             string `json:"custom_key_store_type"`
	KeyStorePassword               string `json:"key_store_password"`
	NumberOfHSMsInCloudHSMCluster  *int   `json:"number_of_hsms_in_cloudhsm_cluster"`
	TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
	XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
	XKSProxyURIPath                string `json:"xks_proxy_uri_path"`
	XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
	AWSAccountID                   string `json:"aws_account_id"`
	Arn                            string `json:"arn"`
}

type LocalHostedParamsJSON struct {
	Blocked          bool   `json:"blocked"`
	HealthCheckKeyID string `json:"health_check_key_id"`
	MaxCredentials   int32  `json:"max_credentials"`
	PartitionID      string `json:"partition_id"`
	SourceKeyTier    string `json:"source_key_tier"`
}

type LocalHostedParamsJSONResponse struct {
	Blocked               bool   `json:"blocked"`
	HealthCheckCiphertext string `json:"health_check_ciphertext"`
	HealthCheckKeyID      string `json:"health_check_key_id"`
	HealthCheckURIPath    string `json:"health_check_uri_path"`
	LinkedState           bool   `json:"linked_state"`
	MaxCredentials        int32  `json:"max_credentials"`
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
	VersionCount            int                    `json:"version_count"`
	EnableSuccessAuditEvent bool                   `json:"enable_success_audit_event"`
	LinkedState             bool                   `json:"linked_state"`
	LocalHostedParams       *LocalHostedParamsJSON `json:"local_hosted_params"`
	KeyStorePassword        string                 `json:"key_store_password"`
}

// AWSCustomKeyStoreOutputJSON is used to unmarshal the create/read API response for a custom key store.
// It extends AWSCustomKeyStoreJSON with output-only fields.
type AWSCustomKeyStoreOutputJSON struct {
	AWSCustomKeyStoreJSON
	CredentialVersion   int    `json:"credential_version"`
	CredentialCount     int    `json:"credential_count"`
	OldestCredentialsID string `json:"oldest_credentials_id"`
}

type AWSCustomKeyStoreConnectPayloadJSON struct {
	KeyStorePassword string `json:"key_store_password"`
}

type AWSKeyParamTagJSON struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}

type CommonAWSParamsJSON struct {
	Alias                          string               `json:"Alias"`
	BypassPolicyLockoutSafetyCheck bool                 `json:"BypassPolicyLockoutSafetyCheck"`
	CurrentKeyMaterialID           *string              `json:"CurrentKeyMaterialId,omitempty"`
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

// UploadAWSKeyParamJSON extends CommonAWSParamsJSON with upload-specific fields.
type UploadAWSKeyParamJSON struct {
	CommonAWSParamsJSON
	ValidTo string `json:"ValidTo,omitempty"`
	Origin  string `json:"Origin"`
}

// UploadAWSKeyPayloadJSON is the request body for the upload-key API.
type UploadAWSKeyPayloadJSON struct {
	CommonAWSKeyCreatePayloadJSON
	AWSParam               *UploadAWSKeyParamJSON `json:"aws_param"`
	SourceKeyIdentifier    string                 `json:"source_key_identifier"`
	SourceKeyTier          string                 `json:"source_key_tier"`
	KeyExpiration          bool                   `json:"key_expiration"`
	KeyMaterialDescription string                 `json:"key_material_description,omitempty"`
}

type AWSKeyImportKeyPayloadJSON struct {
	SourceKeyID   string `json:"source_key_identifier"`
	SourceKeyTier string `json:"source_key_tier"`
	KeyExpiration bool   `json:"key_expiration"`
	ValidTo       string `json:"valid_to"`
}

type AWSKeyImportMaterialJSON struct {
	ImportType             *string `json:"import_type,omitempty"`
	KeyMaterialDescription *string `json:"key_material_description"`
	KeyMaterialID          *string `json:"key_material_id"`
	SourceKeyID            string  `json:"source_key_identifier"`
	SourceKeyTier          string  `json:"source_key_tier"`
	KeyExpiration          bool    `json:"key_expiration"`
	ValidTo                string  `json:"valid_to"`
}

type AWSEnableKeyRotationJobPayloadJSON struct {
	JobConfigID                           string  `json:"job_config_id"`
	AutoRotateDisableEncrypt              bool    `json:"auto_rotate_disable_encrypt"`
	AutoRotateKeySource                   *string `json:"auto_rotate_key_source"`
	AutoRotateDisableEncryptOnAllAccounts bool    `json:"auto_rotate_disable_encrypt_on_all_accounts"`
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
	AWSConnection        string `json:"connection"`
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
	AWSParams        AWSKeyParamJSON     `json:"aws_param"`
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
	KmsID     string `json:"kms"`
	Name      string `json:"name"`
	KeyPolicyParamsJSON
}

type KeyPolicyTemplateUpdatePayloadJSON struct {
	KeyPolicyParamsJSON
	AutoPush bool `json:"auto_push"`
}

type EnableAutoRotationPayloadJSON struct {
	RotationPeriodInDays *int64 `json:"rotation_period_in_days,omitempty"`
}

type UpdatePrimaryRegionPayloadJSON struct {
	PrimaryRegion *string `json:"PrimaryRegion"`
}

type XKSKeyCommonAWSParamsJSON struct {
	Description *string               `json:"Description"`
	Policy      *json.RawMessage      `json:"Policy,omitempty"`
	Tags        []*AWSKeyParamTagJSON `json:"Tags"`
	Alias       string                `json:"Alias"`
}

type LinkXKSKeyAWSParamsJSON struct {
	AWSParams                      XKSKeyCommonAWSParamsJSON `json:"aws_param"`
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
	AWSParams                        XKSKeyCommonAWSParamsJSON `json:"aws_param"`
	KeyUsers                         *[]string                 `json:"key_users"`
	KeyAdmins                        *[]string                 `json:"key_admins"`
	KeyUsersRoles                    *[]string                 `json:"key_users_roles"`
	KeyAdminsRoles                   *[]string                 `json:"key_admins_roles"`
	ExternalAccounts                 *[]string                 `json:"external_accounts"`
	PolicyTemplate                   *string                   `json:"policytemplate"`
	XKSKeyLocalHostedInputParamsJSON `json:"local_hosted_params"`
}

type CreateCloudHSMKeyInputPayloadJSON struct {
	AWSParams        XKSKeyCommonAWSParamsJSON `json:"aws_param"`
	KeyUsers         *[]string                 `json:"key_users"`
	KeyAdmins        *[]string                 `json:"key_admins"`
	KeyUsersRoles    *[]string                 `json:"key_users_roles"`
	KeyAdminsRoles   *[]string                 `json:"key_admins_roles"`
	ExternalAccounts *[]string                 `json:"external_accounts"`
	PolicyTemplate   *string                   `json:"policytemplate"`
}

type AWSEnableXksCredentialRotationJobPayloadJSON struct {
	JobConfigID string `json:"job_config_id"`
}

type KeyRotationAwsParamJSON struct {
	ExpirationModel        string `json:"ExpirationModel"`
	ImportState            string `json:"ImportState"`
	KeyId                  string `json:"KeyId"`
	KeyMaterialDescription string `json:"KeyMaterialDescription"`
	KeyMaterialID          string `json:"KeyMaterialId"`
	KeyMaterialState       string `json:"KeyMaterialState"`
	RotationDate           string `json:"RotationDate"`
	RotationType           string `json:"RotationType"`
	ValidTo                string `json:"ValidTo"`
}

type KeyRotationJSON struct {
	Account                 string `json:"account"`
	KeyRotationAwsParamJSON `json:"aws_param"`
	CreatedAt               string `json:"createdAt"`
	ID                      string `json:"id"`
	KeyMaterialOrigin       string `json:"key_material_origin"`
	KeySource               string `json:"key_source"`
	KeySourceContainerID    string `json:"key_source_container_id"`
	KeySourceContainerName  string `json:"key_source_container_name,omitempty"`
	KmsID                   string `json:"kms_id"`
	SourceKeyID             string `json:"source_key_identifier"`
	SourceKeyName           string `json:"source_key_name"`
	UpdatedAt               string `json:"updatedAt"`
	URI                     string `json:"uri"`
}

type DataSourceKeyRotationsJSON struct {
	Resources []KeyRotationJSON `json:"resources"`
}

// NativeKeyRotationAwsParamJSON holds the aws_param fields from a native-key rotation list entry.
// Fields specific to EXTERNAL keys (ExpirationModel, KeyMaterialDescription, ValidTo) are omitted.
type NativeKeyRotationAwsParamJSON struct {
	ImportState      string `json:"ImportState"`
	KeyID            string `json:"KeyId"`
	KeyMaterialID    string `json:"KeyMaterialId"`
	KeyMaterialState string `json:"KeyMaterialState"`
	RotationDate     string `json:"RotationDate"`
	RotationType     string `json:"RotationType"`
}

// NativeKeyRotationEntryJSON holds one item from the rotation list for a native symmetric key.
type NativeKeyRotationEntryJSON struct {
	AwsParam          NativeKeyRotationAwsParamJSON `json:"aws_param"`
	CreatedAt         string                        `json:"createdAt"`
	ID                string                        `json:"id"`
	KeyMaterialOrigin string                        `json:"key_material_origin"`
	KmsID             string                        `json:"kms_id"`
	LocalKeyID        string                        `json:"local_key_id"`
	UpdatedAt         string                        `json:"updatedAt"`
}

// NativeKeyRotationListJSON is the response wrapper for the key rotation list endpoint
// when used by the aws_key_rotation resource (native symmetric keys only).
type NativeKeyRotationListJSON struct {
	Resources []NativeKeyRotationEntryJSON `json:"resources"`
	Total     int64                        `json:"total"`
}

type DataSourceKmsJSON struct {
	Account              string         `json:"account"`
	AccountID            string         `json:"account_id"`
	Acls                 []acls.AclJSON `json:"acls"`
	Application          string         `json:"application"`
	Arn                  string         `json:"arn"`
	AssumeRoleARN        string         `json:"assume_role_arn"`
	AssumeRoleExternalID string         `json:"assume_role_external_id"`
	AutoAdded            bool           `json:"auto_added"`
	Connection           string         `json:"connection"`
	CreatedAt            string         `json:"createdAt"`
	DevAccount           string         `json:"devAccount"`
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	Regions              []string       `json:"regions"`
	Status               string         `json:"status"`
	UpdatedAt            string         `json:"updatedAt"`
	URI                  string         `json:"uri"`
}

type DataSourceKmsListJSON struct {
	Resources []DataSourceKmsJSON `json:"resources"`
}
