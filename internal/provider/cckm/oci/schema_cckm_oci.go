package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type GetOCIRegionsPayloadJSON struct {
	Connection string `json:"connection"`
}

type GetOCIRegionsDataSourceTFSDK struct {
	Connection types.String `tfsdk:"connection_id"`
	Regions    types.List   `tfsdk:"regions"`
}

type GetOCICompartmentTFSDK struct {
	ID             types.String         `tfsdk:"id"`
	CompartmentID  types.String         `tfsdk:"compartment_id"`
	Name           types.String         `tfsdk:"name"`
	Description    types.String         `tfsdk:"description"`
	TimeCreated    types.String         `tfsdk:"time_created"`
	LifecycleState types.String         `tfsdk:"lifecycle_state"`
	InactiveStatus types.Int64          `tfsdk:"inactive_status"`
	IsAccessible   types.Bool           `tfsdk:"is_accessible"`
	FreeformTags   types.Map            `tfsdk:"freeform_tags"`
	DefinedTags    map[string]types.Map `tfsdk:"defined_tags"`
}

type GetOCICompartmentJSON struct {
	ID             string                       `json:"id"`
	CompartmentID  string                       `json:"compartmentId"`
	Name           string                       `json:"name"`
	Description    string                       `json:"description"`
	TimeCreated    string                       `json:"timeCreated"`
	LifecycleState string                       `json:"lifecycleState"`
	InactiveStatus int64                        `json:"inactiveStatus"`
	IsAccessible   bool                         `json:"isAccessible"`
	FreeformTags   map[string]string            `json:"freeformTags"`
	DefinedTags    map[string]map[string]string `json:"definedTags"`
}

type GetOCICompartmentsPayloadJSON struct {
	Connection string  `tfsdk:"connection_id"`
	Limit      *int64  `tfsdk:"limit"`
	NextPage   *string `json:"ociNextPage"`
}

type GetOCICompartmentsJSON struct {
	Data     []GetOCICompartmentJSON `json:"data"`
	NextPage string                  `json:"ociNextPage"`
}

type GetOCICompartmentsDataSourceModelTFSDK struct {
	Connection   types.String             `tfsdk:"connection_id"`
	Limit        types.Int64              `tfsdk:"limit"`
	Compartments []GetOCICompartmentTFSDK `tfsdk:"compartments"`
}

type GetOCIVaultTFSDK struct {
	CompartmentID      types.String         `tfsdk:"compartment_id"`
	DisplayName        types.String         `tfsdk:"display_name"`
	VaultID            types.String         `tfsdk:"vault_id"`
	LifecycleState     types.String         `tfsdk:"lifecycle_state"`
	ManagementEndpoint types.String         `tfsdk:"management_endpoint"`
	TimeCreated        types.String         `tfsdk:"time_created"`
	VaultType          types.String         `tfsdk:"vault_type"`
	DefinedTags        map[string]types.Map `tfsdk:"defined_tags"`
	FreeformTags       types.Map            `tfsdk:"freeform_tags"`
}

type GetOCIVaultJSON struct {
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

type GetOCIVaultsPayloadJSON struct {
	Connection    string  `json:"connection"`
	CompartmentID string  `json:"compartment_id"`
	Region        string  `json:"region"`
	Limit         *int64  `json:"limit"`
	NextPage      *string `json:"ociNextPage"`
}

type GetOCIVaultsJSON struct {
	Data     []GetOCIVaultJSON `json:"data"`
	NextPage string            `json:"ociNextPage"`
}

type GetOCIVaultsDataSourceModelTFSDK struct {
	Connection    types.String       `tfsdk:"connection_id"`
	CompartmentID types.String       `tfsdk:"compartment_id"`
	Region        types.String       `tfsdk:"region"`
	Limit         types.Int64        `tfsdk:"limit"`
	Vaults        []GetOCIVaultTFSDK `tfsdk:"vaults"`
}
