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
	CompartmentID  string                       `json:"compartment_id"`
	Name           string                       `json:"name"`
	Description    string                       `json:"description"`
	TimeCreated    string                       `json:"time_created"`
	LifecycleState string                       `json:"lifecycle_state"`
	InactiveStatus int64                        `json:"inactive_status"`
	IsAccessible   bool                         `json:"is_accessible"`
	FreeformTags   map[string]string            `json:"freeform_tags"`
	DefinedTags    map[string]map[string]string `json:"defined_tags"`
}

type GetOCICompartmentsPayloadJSON struct {
	Connection string  `json:"connection"`
	Limit      *int64  `json:"limit,omitempty"`
	NextPage   *string `json:"ociNextPage,omitempty"`
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
