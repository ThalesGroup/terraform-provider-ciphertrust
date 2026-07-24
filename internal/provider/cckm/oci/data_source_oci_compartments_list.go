// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceOCICompartmentsList{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCICompartmentsList{}
)

func NewDataSourceOCICompartmentsList() datasource.DataSource {
	return &dataSourceOCICompartmentsList{}
}

type dataSourceOCICompartmentsList struct {
	client *common.Client
}

func (d *dataSourceOCICompartmentsList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *dataSourceOCICompartmentsList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_compartments_list"
}

func (d *dataSourceOCICompartmentsList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI compartments saved in CipherTrust Manager.\n\n" +
			"Give a filter of 'limit=-1' to list more than 10 matches.\n\n" +
			"Available filters: id, name, compartment_id (compartment OCID), tenancy.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key:value filter pairs. Supported keys: id, name, " +
					"compartment_id (the parent compartment OCID), tenancy.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of compartments that matched the filters.",
			},
			"compartments": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of OCI compartments stored in CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the compartment.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the compartment record was created in CipherTrust Manager.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the compartment record was last updated in CipherTrust Manager.",
						},
						"tenancy": schema.StringAttribute{
							Computed:    true,
							Description: "The tenancy name associated with the compartment.",
						},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The parent compartment OCID.",
						},
						"parent_compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The OCID of this compartment's parent.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's name.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's description.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The time the compartment was created in OCI.",
						},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's current lifecycle state (e.g. ACTIVE).",
						},
						"is_accessible": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the compartment is accessible to the requesting user.",
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The compartment's freeform tags.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The compartment's defined tags.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed:    true,
										Description: "The tag's namespace.",
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
										Description: "The key:value pairs associated with the tag.",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read lists OCI compartments stored in CipherTrust Manager, optionally filtered
// by the key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceOCICompartmentsList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_oci_compartments_list.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_oci_compartments_list.go -> Read]["+id+"]")

	var state models.OCICompartmentListDataSourceModelTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/compartments/", filters)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_compartments_list.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI compartments from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var list models.OCICompartmentListJSON
	err = json.Unmarshal([]byte(jsonStr), &list)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_compartments_list.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI compartments from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for _, c := range list.Resources {
		compartment := models.OCICompartmentTFSDK{
			ID:                  types.StringValue(c.ID),
			CreatedAt:           types.StringValue(c.CreatedAt),
			UpdatedAt:           types.StringValue(c.UpdatedAt),
			Tenancy:             types.StringValue(c.Tenancy),
			CompartmentID:       types.StringValue(c.CompartmentID),
			ParentCompartmentID: types.StringValue(c.ParentCompartmentID),
			Name:                types.StringValue(c.Name),
			Description:         types.StringValue(c.Description),
			TimeCreated:         types.StringValue(c.TimeCreated),
			LifecycleState:      types.StringValue(c.LifecycleState),
			IsAccessible:        types.BoolValue(c.IsAccessible),
		}
		setFreeformTagsState(ctx, c.FreeformTags, &compartment.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, c.DefinedTags, &compartment.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Compartments = append(state.Compartments, compartment)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
