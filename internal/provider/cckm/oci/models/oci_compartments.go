// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package models

import "github.com/hashicorp/terraform-plugin-framework/types"

// OCICompartmentJSON is a single compartment resource returned by the CM list endpoint.
type OCICompartmentJSON struct {
	ID                  string                       `json:"id"`
	CreatedAt           string                       `json:"createdAt"`
	UpdatedAt           string                       `json:"updatedAt"`
	Tenancy             string                       `json:"tenancy"`
	CompartmentID       string                       `json:"compartment_id"`
	ParentCompartmentID string                       `json:"parent_compartment_id"`
	Name                string                       `json:"name"`
	Description         string                       `json:"description"`
	TimeCreated         string                       `json:"time_created"`
	LifecycleState      string                       `json:"lifecycle_state"`
	IsAccessible        bool                         `json:"is_accessible"`
	FreeformTags        map[string]string            `json:"freeform_tags"`
	DefinedTags         map[string]map[string]string `json:"defined_tags"`
}

// OCICompartmentListJSON is the paginated list response from the CM OCI compartments endpoint.
type OCICompartmentListJSON struct {
	Skip      int64                `json:"skip"`
	Limit     int64                `json:"limit"`
	Total     int64                `json:"total"`
	Resources []OCICompartmentJSON `json:"resources"`
}

// OCICompartmentTFSDK holds the Terraform state for a single compartment.
type OCICompartmentTFSDK struct {
	ID                  types.String `tfsdk:"id"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	Tenancy             types.String `tfsdk:"tenancy"`
	CompartmentID       types.String `tfsdk:"compartment_id"`
	ParentCompartmentID types.String `tfsdk:"parent_compartment_id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	TimeCreated         types.String `tfsdk:"time_created"`
	LifecycleState      types.String `tfsdk:"lifecycle_state"`
	IsAccessible        types.Bool   `tfsdk:"is_accessible"`
	FreeformTags        types.Map    `tfsdk:"freeform_tags"`
	DefinedTags         types.Set    `tfsdk:"defined_tags"`
}

// OCICompartmentListDataSourceModelTFSDK is the top-level state for the
// ciphertrust_oci_compartments_list data source.
type OCICompartmentListDataSourceModelTFSDK struct {
	Filters      types.Map             `tfsdk:"filters"`
	Matched      types.Int64           `tfsdk:"matched"`
	Compartments []OCICompartmentTFSDK `tfsdk:"compartments"`
}
