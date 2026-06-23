// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

var (
	_ resource.Resource                = &resourceCTEClientGroupDesignatedPrimarySet{}
	_ resource.ResourceWithConfigure   = &resourceCTEClientGroupDesignatedPrimarySet{}
	_ resource.ResourceWithImportState = &resourceCTEClientGroupDesignatedPrimarySet{}
)

func NewResourceCTEClientGroupDesignatedPrimarySet() resource.Resource {
	return &resourceCTEClientGroupDesignatedPrimarySet{}
}

type resourceCTEClientGroupDesignatedPrimarySet struct {
	client *common.Client
}

func (r *resourceCTEClientGroupDesignatedPrimarySet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_clientgroup_designatedprimaryset"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClientGroupDesignatedPrimarySet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Designated Primary Set (DPS) within a CTE Client Group. A DPS defines a named set of clients and an associated LDT communication group service within a client group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the Designated Primary Set, generated on successful creation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"client_group_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the CTE Client Group to which this Designated Primary Set belongs.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the Designated Primary Set within the client group.",
			},
			"client_list": schema.StringAttribute{
				Required:    true,
				Description: "Comma-separated list of clients to be included in the Designated Primary Set.",
			},
			"ldt_comm_group_service_id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the LDT communication group service to be associated with this Designated Primary Set.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClientGroupDesignatedPrimarySet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_clientgroup_dps.go -> Create]["+id+"]")

	var plan CTEClientGroupDesignatedPrimarySetTFSDK
	var payload CTEClientGroupDesignatedPrimarySetJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.ValueString())
	payload.ClientList = common.TrimString(plan.ClientList.ValueString())
	payload.LDTCommGroupServiceID = common.TrimString(plan.LDTCommGroupServiceID.ValueString())

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Group Designated Primary Set Creation",
			err.Error(),
		)
		return
	}

	url := fmt.Sprintf("%s/%s/dps", common.URL_CTE_CLIENT_GROUP, plan.ClientGroupID.ValueString())
	response, err := r.client.PostData(ctx, id, url, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client Group Designated Primary Set on CipherTrust Manager: ",
			"Could not create Designated Primary Set, unexpected error: "+err.Error(),
		)
		return
	}

	// response holds the dps_id returned by the API, stored in plan.ID
	// and used in Update/Delete URLs as {dpsId}
	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup_dps.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClientGroupDesignatedPrimarySet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGroupDesignatedPrimarySetTFSDK
	id := uuid.New().String()

	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_clientgroup_dps.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/dps", common.URL_CTE_CLIENT_GROUP, state.ClientGroupID.ValueString())
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), url)
	if err != nil {
		if strings.Contains(err.Error(), "record not found") || strings.Contains(err.Error(), "status: 404") {
			tflog.Debug(ctx, "[resource_cte_clientgroup_dps.go -> Read] DPS not found, removing from state: "+state.ID.ValueString())
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CTE Client Group Designated Primary Set on CipherTrust Manager: ",
			"Could not read Designated Primary Set id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Resource was deleted outside Terraform — remove from state so it gets recreated
	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "RAW DPS API RESPONSE: "+response)

	var apiResp CTEClientGroupDesignatedPrimarySetListJSON
	if err := json.Unmarshal([]byte(response), &apiResp); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error parsing CTE Client Group Designated Primary Set API response",
			err.Error(),
		)
		return
	}

	setCTEClientGroupDesignatedPrimarySetState(&state, &apiResp)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup_dps.go -> Read]["+id+"]")
}

// Update updates the resource and sets the updated Terraform state on success.
// Only client_list is updatable; all other fields either require replacement or are immutable.
func (r *resourceCTEClientGroupDesignatedPrimarySet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGroupDesignatedPrimarySetTFSDK
	var payload CTEClientGroupDesignatedPrimarySetUpdateJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	//handle immutable fields
	if plan.ClientGroupID.ValueString() != state.ClientGroupID.ValueString() {
		resp.Diagnostics.AddError("Cannot change client group id", "client group id is an immutable field")
		return
	}

	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannt change designated primary set name", "name is an immutable field")
		return
	}

	if plan.LDTCommGroupServiceID.ValueString() != state.LDTCommGroupServiceID.ValueString() {
		resp.Diagnostics.AddError("Cannt change LDT comm group service id", "LDT comm group service id is an immutable field")
		return
	}

	if plan.ClientList.ValueString() != "" && plan.ClientList.ValueString() != types.StringNull().ValueString() {
		payload.ClientList = common.TrimString(plan.ClientList.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Group Designated Primary Set Update",
			err.Error(),
		)
		return
	}

	// plan.ID holds the dps_id returned from Create, used as {dpsId} in the PATCH URL
	url := fmt.Sprintf("%s/%s/dps", common.URL_CTE_CLIENT_GROUP, plan.ClientGroupID.ValueString())
	_, err = r.client.UpdateData(ctx, plan.ID.ValueString(), url, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup_dps.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Client Group Designated Primary Set on CipherTrust Manager: ",
			"Could not update Designated Primary Set, unexpected error: "+err.Error(),
		)
		return
	}

	// Only client_list is updatable; set state directly from plan since
	// ID, ClientGroupID, Name, and LDTCommGroupServiceID are unchanged by the API.
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClientGroupDesignatedPrimarySet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGroupDesignatedPrimarySetTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// state.ID holds the dps_id returned from Create, used as {dpsId} in the DELETE URL
	url := fmt.Sprintf("%s/%s/%s/dps/%s", r.client.CipherTrustURL, common.URL_CTE_CLIENT_GROUP, state.ClientGroupID.ValueString(), state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup_dps.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Client Group Designated Primary Set",
			"Could not delete Designated Primary Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *resourceCTEClientGroupDesignatedPrimarySet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func setCTEClientGroupDesignatedPrimarySetState(
	state *CTEClientGroupDesignatedPrimarySetTFSDK,
	apiResp *CTEClientGroupDesignatedPrimarySetListJSON,
) {
	state.ID = types.StringValue(apiResp.ID)
	state.Name = types.StringValue(apiResp.Name)
	state.ClientList = types.StringValue(apiResp.PrimaryClientNameList)
	state.LDTCommGroupServiceID = types.StringValue(apiResp.LdtCommGroupServiceID)
}

func (r *resourceCTEClientGroupDesignatedPrimarySet) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_clientgroup_dps.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup_dps.go -> ImportState]["+id+"]")

	// Expect import ID in format: "client_group_id:dps_id"
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			"Expected import ID in format: <client_group_id>:<dps_id>, got: "+req.ID,
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_group_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
}
