package models

import (
	"encoding/json"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type VaultTFSDK struct {
	VaultCommonTFSDK
	BucketParamsTFSDK
	FreeformTags types.Map `tfsdk:"freeform_tags"`
	DefinedTags  types.Set `tfsdk:"defined_tags"`
}

type ExternalVaultTFSDK struct {
	VaultCommonTFSDK
	ExternalVaultParamsTFSDK
	WrappingkeyID      types.String `tfsdk:"wrappingkey_id"`
	ManagementEndpoint types.String `tfsdk:"management_endpoint"`
}

type ExternalVaultParamsJSON struct {
	VaultName           string          `json:"vault_name"`
	EndpointURL         string          `json:"endpoint_url"`
	Policy              json.RawMessage `json:"policy"`
	EndpointURLHostname string          `json:"endpoint_url_hostname"`
	LinkedState         *bool           `json:"linked_state"`
	ExternalVaultType   string          `json:"external_vault_type"`
	ClientApplicationID string          `json:"client_application_id"`
	IssuerID            string          `json:"issuer_id"`
	Blocked             *bool           `json:"blocked"`
	State               string          `json:"state"`
	PartitionID         string          `json:"partition_id"`
	SourceKeyTier       string          `json:"source_key_tier"`
	EndpointURLPort     *int            `json:"endpoint_url_port"`
	EnableAuditEvent    *bool           `json:"enable_success_audit_event"`
}

type ExternalVaultParamsTFSDK struct {
	VaultName           types.String `tfsdk:"vault_name"`
	EndpointURL         types.String `tfsdk:"endpoint_url"`
	Policy              types.String `tfsdk:"policy"`
	EndpointURLHostname types.String `tfsdk:"endpoint_url_hostname"`
	LinkedState         types.Bool   `tfsdk:"linked_state"`
	ExternalVaultType   types.String `tfsdk:"external_vault_type"`
	ClientApplicationID types.String `tfsdk:"client_application_id"`
	IssuerID            types.String `tfsdk:"issuer_id"`
	Blocked             types.Bool   `tfsdk:"blocked"`
	State               types.String `tfsdk:"state"`
	PartitionID         types.String `tfsdk:"partition_id"`
	SourceKeyTier       types.String `tfsdk:"source_key_tier"`
	EndpointURLPort     types.Int64  `tfsdk:"endpoint_url_port"`
	EnableAuditEvent    types.Bool   `tfsdk:"enable_success_audit_event"`
}

type BucketParamsJSON struct {
	BucketName      *string `json:"bucket_name"`
	BucketNamespace *string `json:"bucket_namespace"`
}

type BucketParamsTFSDK struct {
	BucketName      types.String `tfsdk:"bucket_name"`
	BucketNamespace types.String `tfsdk:"bucket_namespace"`
}

type UpdateVaultCommonJSON struct {
	Connection *string `json:"connection"`
}
type UpdateExternalVaultJSON struct {
	UpdateVaultCommonJSON
	VaultName           *string          `json:"vault_name"`
	IssuerID            *string          `json:"issuer_id"`
	EndpointURLHostname *string          `json:"endpoint_url_hostname"`
	EndpointURLPort     *int             `json:"endpoint_url_port" validate:"omitempty,gte=1,lte=65535"`
	Policy              *json.RawMessage `json:"policy"`
	EnableAuditEvent    *bool            `json:"enable_success_audit_event,omitempty"`
}

type UpdateVaultJSON struct {
	UpdateVaultCommonJSON
	BucketParamsJSON
}

type VaultAclTFSDK struct {
	ID      types.String `tfsdk:"id"`
	VaultID types.String `tfsdk:"vault_id"`
	acls.AclTFSDK
}

type AddVaultsPayloadJSON struct {
	Connection string   `json:"connection"`
	Region     string   `json:"region"`
	VaultIDs   []string `json:"vault_id"`
	BucketParamsJSON
}

type VaultCommonTFSDK struct {
	ID                  types.String `tfsdk:"id"`
	URI                 types.String `tfsdk:"uri"`
	Account             types.String `tfsdk:"account"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	CompartmentID       types.String `tfsdk:"compartment_id"`
	DisplayName         types.String `tfsdk:"name"`
	VaultID             types.String `tfsdk:"vault_id"`
	LifecycleState      types.String `tfsdk:"lifecycle_state"`
	ManagementEndpoint  types.String `tfsdk:"management_endpoint"`
	TimeCreated         types.String `tfsdk:"time_created"`
	CloudName           types.String `tfsdk:"cloud_name"`
	Connection          types.String `tfsdk:"connection_id"`
	VaultType           types.String `tfsdk:"vault_type"`
	WrappingkeyID       types.String `tfsdk:"wrappingkey_id"`
	RestoredFromVaultID types.String `tfsdk:"restored_from_vault_id"`
	ReplicationID       types.String `tfsdk:"replication_id"`
	IsPrimary           types.Bool   `tfsdk:"is_primary"`
	Acls                types.Set    `tfsdk:"acls"`
	RefreshedAt         types.String `tfsdk:"refreshed_at"`
	Tenancy             types.String `tfsdk:"tenancy"`
	Region              types.String `tfsdk:"region"`
	CompartmentName     types.String `tfsdk:"compartment_name"`
}

type GetOCIVaultsPayloadJSON struct {
	Connection    string  `json:"connection"`
	CompartmentID string  `json:"compartment_id"`
	Region        string  `json:"region"`
	Limit         *int64  `json:"limit"`
	NextPage      *string `json:"ociNextPage"`
}

type GetOCIVaultsJSON struct {
	Data     []DataSourceGetOCIVaultJSON `json:"data"`
	NextPage string                      `json:"ociNextPage"`
}

type DataSourceGetOCIVaultTFSDK struct {
	CompartmentID      types.String `tfsdk:"compartment_id"`
	DisplayName        types.String `tfsdk:"display_name"`
	VaultID            types.String `tfsdk:"vault_id"`
	LifecycleState     types.String `tfsdk:"lifecycle_state"`
	ManagementEndpoint types.String `tfsdk:"management_endpoint"`
	TimeCreated        types.String `tfsdk:"time_created"`
	VaultType          types.String `tfsdk:"vault_type"`
	DefinedTags        types.Set    `tfsdk:"defined_tags"`
	FreeformTags       types.Map    `tfsdk:"freeform_tags"`
}

type DataSourceGetOCIVaultJSON struct {
	CompartmentID      string                       `json:"compartment_id"`
	DisplayName        string                       `json:"display_name"`
	VaultID            string                       `json:"vault_id"`
	LifecycleState     string                       `json:"lifecycleState"`
	ManagementEndpoint string                       `json:"management_endpoint"`
	TimeCreated        string                       `json:"time_created"`
	VaultType          string                       `json:"vault_type"`
	FreeformTags       map[string]string            `json:"freeformTags"`
	DefinedTags        map[string]map[string]string `json:"definedTags"`
}

type DataSourceGetOCIVaultsTFSDK struct {
	Connection    types.String                 `tfsdk:"connection_id"`
	CompartmentID types.String                 `tfsdk:"compartment_id"`
	Region        types.String                 `tfsdk:"region"`
	Limit         types.Int64                  `tfsdk:"limit"`
	Vaults        []DataSourceGetOCIVaultTFSDK `tfsdk:"vaults"`
}

type DataSourceVaultJSON struct {
	ID                  string                       `json:"id"`
	URI                 string                       `json:"uri"`
	Account             string                       `json:"account"`
	CreatedAt           string                       `json:"createdAt"`
	UpdatedAt           string                       `json:"updatedAt"`
	CompartmentID       string                       `json:"compartment_id"`
	DisplayName         string                       `json:"display_name"`
	VaultID             string                       `json:"vault_id"`
	LifecycleState      string                       `json:"lifecycle_state"`
	ManagementEndpoint  string                       `json:"management_endpoint"`
	TimeCreated         string                       `json:"time_created"`
	CloudName           string                       `json:"cloud_name"`
	Connection          string                       `json:"connection"`
	VaultType           string                       `json:"vault_type"`
	WrappingkeyID       string                       `json:"wrappingkey_id"`
	FreeformTags        map[string]string            `json:"freeform_tags"`
	DefinedTags         map[string]map[string]string `json:"defined_tags"`
	RestoredFromVaultID string                       `json:"restored_from_vault_id"`
	ReplicationID       string                       `json:"replication_id"`
	IsPrimary           bool                         `json:"is_primary"`
	Acls                []acls.AclJSON               `json:"acls"`
	RefreshedAt         string                       `json:"refreshed_at"`
	Tenancy             string                       `json:"tenancy"`
	Region              string                       `json:"region"`
	CompartmentName     string                       `json:"compartment_name"`
	ExternalVaultParamsJSON
	BucketParamsJSON
}

type DataSourceVaultsJSON struct {
	Resources []DataSourceVaultJSON `json:"resources"`
}
