package models

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KeyVersionTFSDK struct {
	Account                 types.String `tfsdk:"account"`
	CCKMKeyID               types.String `tfsdk:"cckm_key_id"`
	CloudName               types.String `tfsdk:"cloud_name"`
	CreatedAt               types.String `tfsdk:"created_at"`
	ID                      types.String `tfsdk:"id"`
	KeyMaterialOrigin       types.String `tfsdk:"key_material_origin"`
	KeyVersionParams        types.Object `tfsdk:"oci_key_version_params"`
	RefreshedAt             types.String `tfsdk:"refreshed_at"`
	ScheduleForDeletionDays types.Int64  `tfsdk:"schedule_for_deletion_days"`
	UpdatedAt               types.String `tfsdk:"updated_at"`
	URI                     types.String `tfsdk:"uri"`
}

type KeyVersionParamsTFSDK struct {
	CompartmentID            types.String `tfsdk:"compartment_id"`
	IsPrimary                types.Bool   `tfsdk:"is_primary"`
	KeyID                    types.String `tfsdk:"key_id"`
	LifecycleState           types.String `tfsdk:"lifecycle_state"`
	Origin                   types.String `tfsdk:"origin"`
	PublicKey                types.String `tfsdk:"public_key"`
	ReplicationID            types.String `tfsdk:"replication_id"`
	RestoredFromKeyVersionID types.String `tfsdk:"restored_from_key_version_id"`
	TimeCreated              types.String `tfsdk:"time_created"`
	TimeOfDeletion           types.String `tfsdk:"time_of_deletion"`
	VaultID                  types.String `tfsdk:"vault_id"`
	VersionID                types.String `tfsdk:"version_id"`
}

var KeyVersionParamsTFSDKAttribs = map[string]attr.Type{
	"compartment_id":               types.StringType,
	"is_primary":                   types.BoolType,
	"key_id":                       types.StringType,
	"lifecycle_state":              types.StringType,
	"origin":                       types.StringType,
	"public_key":                   types.StringType,
	"replication_id":               types.StringType,
	"restored_from_key_version_id": types.StringType,
	"time_created":                 types.StringType,
	"time_of_deletion":             types.StringType,
	"vault_id":                     types.StringType,
	"version_id":                   types.StringType,
}

type BYOKKeyVersionTFSDK struct {
	KeyVersionTFSDK
	SourceKeyID   types.String `tfsdk:"source_key_id"`
	SourceKeyName types.String `tfsdk:"source_key_name"`
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
}

type HYOKKeyVersionTFSDK struct {
	KeyVersionTFSDK
	OCIKeyID       types.String `tfsdk:"oci_key_id"`
	PartitionID    types.String `tfsdk:"partition_id"`
	PartitionLabel types.String `tfsdk:"partition_label"`
	State          types.String `tfsdk:"state"`
}

type AddKeyVersionPayloadJSON struct {
	SourceKeyID   string `json:"source_key_identifier"`
	SourceKeyTier string `json:"source_key_tier"`
	IsNative      bool   `json:"is_native"`
	RotationType  string `json:"rotation_type"`
}

type DataSourceKeyVersionJSON struct {
	Account                            string            `json:"account"`
	CloudName                          string            `json:"cloud_name"`
	CreatedAt                          string            `json:"createdAt"`
	Gone                               bool              `json:"gone"`
	ID                                 string            `json:"id"`
	KeyMaterialOrigin                  string            `json:"key_material_origin"`
	Labels                             map[string]string `json:"labels"`
	RefreshedAt                        string            `json:"refreshed_at"`
	SourceKeyID                        string            `json:"source_key_identifier"`
	SourceKeyName                      string            `json:"source_key_name"`
	SourceKeyTier                      string            `json:"source_key_tier"`
	UpdatedAt                          string            `json:"updatedAt"`
	URI                                string            `json:"uri"`
	DataSourceKeyVersionParamsJSON     `json:"oci_key_version_params"`
	DataSourceHYOKKeyVersionParamsJSON `json:"hyok_key_version_params"`
}

type DataSourceKeyVersionTFSDK struct {
	Account              types.String `tfsdk:"account"`
	CreatedAt            types.String `tfsdk:"created_at"`
	ID                   types.String `tfsdk:"id"`
	KeyMaterialOrigin    types.String `tfsdk:"key_material_origin"`
	RefreshedAt          types.String `tfsdk:"refreshed_at"`
	SourceKeyID          types.String `tfsdk:"source_key_id"`
	SourceKeyName        types.String `tfsdk:"source_key_name"`
	SourceKeyTier        types.String `tfsdk:"source_key_tier"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
	URI                  types.String `tfsdk:"uri"`
	HYOKKeyVersionParams types.Object `tfsdk:"hyok_key_version_params"`
	KeyVersionParams     types.Object `tfsdk:"oci_key_version_params"`
}

type DataSourceKeyVersionParamsJSON struct {
	CompartmentID            string `json:"compartment_id"`
	IsPrimary                bool   `json:"is_primary"`
	KeyID                    string `json:"key_id"`
	LifecycleState           string `json:"lifecycle_state"`
	Origin                   string `json:"origin"`
	PublicKey                string `json:"public_key"`
	ReplicationID            string `json:"replication_id"`
	RestoredFromKeyVersionID string `json:"restored_from_key_version_id"`
	TimeCreated              string `json:"time_created"`
	TimeOfDeletion           string `json:"time_of_deletion"`
	VaultID                  string `json:"vault_id"`
	VersionID                string `json:"version_id"`
}

type DataSourceHYOKKeyVersionParamsJSON struct {
	OCIKeyID       string `json:"oci_key_id"`
	PartitionID    string `json:"partition_id"`
	PartitionLabel string `json:"partition_label"`
	State          string `json:"state"`
}

type DataSourceHYOKKeyVersionParamsTFSDK struct {
	OCIKeyID       types.String `tfsdk:"oci_key_id"`
	PartitionID    types.String `tfsdk:"partition_id"`
	PartitionLabel types.String `tfsdk:"partition_label"`
	State          types.String `tfsdk:"state"`
}

var HYOKKeyVersionParamsTFSDKAttribs = map[string]attr.Type{
	"oci_key_id":      types.StringType,
	"partition_id":    types.StringType,
	"partition_label": types.StringType,
	"state":           types.StringType,
}

type DataSourceKeyVersionsJSON struct {
	Resources []DataSourceKeyVersionJSON `json:"resources"`
}
