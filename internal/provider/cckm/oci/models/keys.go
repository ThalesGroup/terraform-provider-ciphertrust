package models

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KeyCommonTFSDK struct {
	Account                 types.String             `tfsdk:"account"`
	AutoRotate              types.Bool               `tfsdk:"auto_rotate"`
	CloudName               types.String             `tfsdk:"cloud_name"`
	CompartmentName         types.String             `tfsdk:"compartment_name"`
	CreatedAt               types.String             `tfsdk:"created_at"`
	EnableAutoRotation      *EnableAutoRotationTFSDK `tfsdk:"enable_auto_rotation"`
	EnableKey               types.Bool               `tfsdk:"enable_key"`
	ID                      types.String             `tfsdk:"id"`
	KeyMaterialOrigin       types.String             `tfsdk:"key_material_origin"`
	Labels                  types.Map                `tfsdk:"labels"`
	Name                    types.String             `tfsdk:"name"`
	RefreshedAt             types.String             `tfsdk:"refreshed_at"`
	Region                  types.String             `tfsdk:"region"`
	ScheduleForDeletionDays types.Int64              `tfsdk:"schedule_for_deletion_days"`
	Tenancy                 types.String             `tfsdk:"tenancy"`
	UpdatedAt               types.String             `tfsdk:"updated_at"`
	URI                     types.String             `tfsdk:"uri"`
	KeyVersionSummary       types.List               `tfsdk:"version_summary"`
	KeyParams               *KeyParamsTFSDK          `tfsdk:"oci_key_params"`
}

type KeyParamsTFSDK struct {
	Algorithm         types.String `tfsdk:"algorithm"`
	CompartmentID     types.String `tfsdk:"compartment_id"`
	CurrentKeyVersion types.String `tfsdk:"current_key_version"`
	CurveID           types.String `tfsdk:"curve_id"`
	DefinedTags       types.Set    `tfsdk:"defined_tags"`
	DisplayName       types.String `tfsdk:"display_name"`
	FreeformTags      types.Map    `tfsdk:"freeform_tags"`
	IsPrimary         types.Bool   `tfsdk:"is_primary"`
	KeyID             types.String `tfsdk:"key_id"`
	Length            types.Int64  `tfsdk:"length"`
	LifecycleState    types.String `tfsdk:"lifecycle_state"`
	ProtectionMode    types.String `tfsdk:"protection_mode"`
	ReplicationID     types.String `tfsdk:"replication_id"`
	RestoredFromKeyID types.String `tfsdk:"restored_from_key_id"`
	TimeCreated       types.String `tfsdk:"time_created"`
	TimeOfDeletion    types.String `tfsdk:"time_of_deletion"`
	VaultName         types.String `tfsdk:"vault_name"`
}

type UploadKeyCommonTFSDK struct {
	SourceKeyIdentifier types.String `tfsdk:"source_key_id"`
	SourceKeyTier       types.String `tfsdk:"source_key_tier"`
}

type KeyTFSDK struct {
	KeyCommonTFSDK
	Vault   types.String `tfsdk:"vault"`
	VaultID types.String `tfsdk:"vault_id"`
}

type BYOKKeyTFSDK struct {
	UploadKeyCommonTFSDK
	KeyTFSDK
}

type HYOKKeyTFSDK struct {
	KeyCommonTFSDK
	UploadKeyCommonTFSDK
	Blocked       types.Bool   `tfsdk:"blocked"`
	CCKMVaultID   types.String `tfsdk:"cckm_vault_id"`
	CCKMVaultName types.String `tfsdk:"cckm_vault_name"`
	KeyLength     types.String `tfsdk:"key_length"`
	LinkedState   types.Bool   `tfsdk:"linked_state"`
	Policy        types.String `tfsdk:"policy"`
	PolicyFile    types.String `tfsdk:"policy_file"`
	State         types.String `tfsdk:"state"`
}

type KeyVersionSummaryTFSDK struct {
	CCKMVersionID types.String `tfsdk:"cckm_version_id"`
	CreatedAt     types.String `tfsdk:"created_at"`
	SourceKeyID   types.String `tfsdk:"source_key_id"`
	SourceKeyName types.String `tfsdk:"source_key_name"`
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
	VersionID     types.String `tfsdk:"version_id"`
}

var KeyVersionSummaryAttribs = map[string]attr.Type{
	"cckm_version_id": types.StringType,
	"created_at":      types.StringType,
	"source_key_id":   types.StringType,
	"source_key_name": types.StringType,
	"source_key_tier": types.StringType,
	"version_id":      types.StringType,
}

type CreateKeyRequest struct {
	Algorithm      string                       `json:"algorithm"`
	CompartmentID  string                       `json:"compartment_id"`
	Curve          string                       `json:"curve_id"`
	DefinedTags    map[string]map[string]string `json:"defined_tags"`
	FreeformTags   map[string]string            `json:"freeform_tags"`
	Length         int64                        `json:"length"`
	Name           string                       `json:"name"`
	ProtectionMode string                       `json:"protection_mode"`
	Vault          string                       `json:"vault" `
}

type UploadKeyPayloadJSON struct {
	SourceKeyTier       string                       `json:"source_key_tier"`
	SourceKeyIdentifier string                       `json:"source_key_identifier"`
	Vault               string                       `json:"vault"`
	Name                string                       `json:"name"`
	ProtectionMode      string                       `json:"protection_mode"`
	CompartmentID       string                       `json:"compartment_id"`
	FreeformTags        map[string]string            `json:"freeform_tags"`
	DefinedTags         map[string]map[string]string `json:"defined_tags"`
}

type CreateExternalKeyPayloadJSON struct {
	Vault               string           `json:"vault"`
	Name                string           `json:"name"`
	Policy              *json.RawMessage `json:"policy"`
	SourceKeyIdentifier string           `json:"source_key_identifier"`
	SourceKeyTier       string           `json:"source_key_tier"`
}

type ScheduleForDeletionJSON struct {
	Days int64 `json:"days"`
}

type EnableAutoRotationTFSDK struct {
	JobConfigID types.String `tfsdk:"job_config_id"`
	KeySource   types.String `tfsdk:"key_source"`
}

type EnableAutoRotationJSON struct {
	JobConfigId         string `json:"job_config_id"`
	AutoRotateKeySource string `json:"auto_rotate_key_source"`
}

type ChangeCompartmentPayload struct {
	CompartmentID string `json:"compartment_id"`
}

type PatchKeyCommonPayload struct {
	DisplayName  *string                      `json:"display_name"`
	FreeformTags map[string]string            `json:"freeform_tags"`
	DefinedTags  map[string]map[string]string `json:"defined_tags"`
}

type UpdateHYOKKeyRequest struct {
	PatchKeyCommonPayload
	Name   *string          `json:"name"`
	Policy *json.RawMessage `json:"policy"`
}

type DataSourceKeyJSON struct {
	Account                     string            `json:"account"`
	AutoRotate                  bool              `json:"auto_rotate"`
	CckmVaultID                 string            `json:"cckm_vault_id"`
	CloudName                   string            `json:"cloud_name"`
	CompartmentName             string            `json:"compartment_name"`
	CreatedAt                   string            `json:"created_at"`
	ID                          string            `json:"id"`
	KeyMaterialOrigin           string            `json:"key_material_origin"`
	Labels                      map[string]string `json:"labels"`
	RefreshedAt                 string            `json:"refreshed_at"`
	Region                      string            `json:"region"`
	Tenancy                     string            `json:"tenancy"`
	UpdatedAt                   string            `json:"updated_at"`
	URI                         string            `json:"uri"`
	VaultID                     string            `json:"vault_id"`
	DataSourceKeyParamsJSON     `json:"oci_params"`
	DataSourceHYOKKeyParamsJSON `json:"hyok_key_params"`
}

type DataSourceKeyTFSDK struct {
	Account           types.String                 `tfsdk:"account"`
	AutoRotate        types.Bool                   `tfsdk:"auto_rotate"`
	CckmVaultID       types.String                 `tfsdk:"cckm_vault_id"`
	CloudName         types.String                 `tfsdk:"cloud_name"`
	CompartmentName   types.String                 `tfsdk:"compartment_name"`
	CreatedAt         types.String                 `tfsdk:"created_at"`
	ID                types.String                 `tfsdk:"id"`
	KeyMaterialOrigin types.String                 `tfsdk:"key_material_origin"`
	Labels            types.Map                    `tfsdk:"labels"`
	RefreshedAt       types.String                 `tfsdk:"refreshed_at"`
	Region            types.String                 `tfsdk:"region"`
	Tenancy           types.String                 `tfsdk:"tenancy"`
	UpdatedAt         types.String                 `tfsdk:"updated_at"`
	URI               types.String                 `tfsdk:"uri"`
	VaultID           types.String                 `tfsdk:"vault_id"`
	KeyParams         KeyParamsTFSDK               `tfsdk:"oci_key_params"`
	HYOKKeyParams     DataSourceHYOKKeyParamsTFSDK `tfsdk:"external_key_params"`
	KeyVersionSummary types.List                   `tfsdk:"version_summary"`
}

type DataSourceKeyParamsJSON struct {
	Algorithm         string                       `json:"algorithm"`
	CompartmentID     string                       `json:"compartment_id"`
	CurrentKeyVersion string                       `json:"current_key_version"`
	CurveID           string                       `json:"curve_id"`
	DefinedTags       map[string]map[string]string `json:"defined_tags"`
	DisplayName       string                       `json:"display_name"`
	FreeformTags      map[string]string            `json:"freeform_tags"`
	IsPrimary         bool                         `json:"is_primary"`
	KeyID             string                       `json:"key_id"`
	Length            int64                        `json:"length"`
	LifecycleState    string                       `json:"lifecycle_state"`
	ProtectionMode    string                       `json:"protection_mode"`
	ReplicationID     string                       `json:"replication_id"`
	RestoredFromKeyID string                       `json:"restored_from_key_id"`
	TimeCreated       string                       `json:"time_created"`
	TimeOfDeletion    string                       `json:"time_of_deletion"`
	VaultName         string                       `json:"vault_name"`
}

type DataSourceHYOKKeyParamsJSON struct {
	Blocked     bool   `json:"blocked"`
	LinkedState bool   `json:"linked_state"`
	Name        string `json:"name"`
	Policy      string `json:"policy"`
	State       string `json:"state"`
}

type DataSourceHYOKKeyParamsTFSDK struct {
	Name        types.String `tfsdk:"name"`
	LinkedState types.Bool   `tfsdk:"linked_state"`
	Blocked     types.Bool   `tfsdk:"blocked"`
	State       types.String `tfsdk:"state"`
	Policy      types.String `tfsdk:"policy"`
}

type DataSourceKeysJSON struct {
	Resources []DataSourceKeyJSON `json:"resources"`
}
