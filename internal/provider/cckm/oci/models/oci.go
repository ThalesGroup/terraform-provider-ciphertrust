package models

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type GetOCIRegionsPayloadJSON struct {
	Connection string `json:"connection"`
}

type GetOCIRegionsDataSourceTFSDK struct {
	Connection types.String `tfsdk:"connection_id"`
	Regions    types.List   `tfsdk:"oci_regions"`
}

type GetOCICompartmentTFSDK struct {
	ID             types.String `tfsdk:"id"`
	CompartmentID  types.String `tfsdk:"compartment_id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	TimeCreated    types.String `tfsdk:"time_created"`
	LifecycleState types.String `tfsdk:"lifecycle_state"`
	InactiveStatus types.Int64  `tfsdk:"inactive_status"`
	IsAccessible   types.Bool   `tfsdk:"is_accessible"`
	FreeformTags   types.Map    `tfsdk:"freeform_tags"`
	DefinedTags    types.Set    `tfsdk:"defined_tags"`
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

type DefinedTagTFSDK struct {
	Tag    types.String `tfsdk:"tag"`
	Values types.Map    `tfsdk:"values"`
}

var DefinedTagAttribs = map[string]attr.Type{
	"tag":    types.StringType,
	"values": types.MapType{ElemType: types.StringType},
}
