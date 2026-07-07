// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTESignatureSet{}
	_ resource.ResourceWithConfigure   = &resourceCTESignatureSet{}
	_ resource.ResourceWithImportState = &resourceCTESignatureSet{}
)

func NewResourceCTESignatureSet() resource.Resource {
	return &resourceCTESignatureSet{}
}

type resourceCTESignatureSet struct {
	client *common.Client
}

func (r *resourceCTESignatureSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_signature_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTESignatureSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A signature set is a collection of hashes of processes and executables that you want to grant or deny access to GuardPoints. A signature set can be configured in a policy as part of a process set to verify the integrity of a process before it is allowed access to guarded data. Policies are applied to signature sets, not to individual signatures. \nNote:\nK8 resources supported are: Pods, Deployment, ReplicaSet, StatefulSets, DaemonSet",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Description: "A human readable unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
				Description: "The developer account which owns this resource's application.",
				Computed:    true,
			},
			"application": schema.StringAttribute{
				Description: "The application this resource belongs to.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Name of the signature set.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the signature set.",
				Optional:    true,
			},
			"labels": schema.MapAttribute{
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/. To add a label, set the label's value as follows.\n\"labels\": {\n\t\"key1\": \"value1\",\n\t\"key2\": \"value2\"\n}",
				ElementType: types.StringType,
				Optional:    true,
				Default: mapdefault.StaticValue(
					types.MapValueMust(types.StringType, map[string]attr.Value{}),
				),
				Computed: true,
			},
			"type": schema.StringAttribute{
				Description: "Type of the signature set. The valid values are Application and Container-Image. The default value is Application.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Application"),
			},
			"source_list": schema.ListAttribute{
				Description: "Path of the directory or file to be signed. If a directory is specified, all files in the directory and its subdirectories are signed.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTESignatureSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_signature_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTESignatureSetTFSDK
	var payload CTESignatureSetJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.Type.ValueString() != "" && plan.Type.ValueString() != types.StringNull().ValueString() {
		payload.Type = common.TrimString(plan.Type.String())
	}
	if plan.Sources != nil {
		for _, source := range plan.Sources {
			payload.Sources = append(payload.Sources, source.ValueString())
		}
	}

	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_signature_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Signature Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_SIGNATURE_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_signature_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Signature Set on CipherTrust Manager: ",
			"Could not create CTE Signature Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_signature_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTESignatureSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTESignatureSetTFSDK
	id := uuid.New().String()

	tflog.Trace(
		ctx,
		common.MSG_METHOD_START+
			"[resource_cte_signature_set.go -> Read]["+id+"]",
	)

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_SIGNATURE_SET)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp CTESignatureSetJSON

	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing API response",
			err.Error(),
		)
		return
	}

	setCTESignatureSetState(&state, &apiResp, resp)

	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(
		ctx,
		common.MSG_METHOD_END+
			"[resource_cte_signature_set.go -> Read]["+id+"]",
	)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTESignatureSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTESignatureSetTFSDK
	var payload CTESignatureSetJSON

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
	//immutable fields handling
	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannot change signature set name once it is created", "Name is an immutable field")
		return
	}
	if plan.Type.ValueString() != state.Type.ValueString() {
		resp.Diagnostics.AddError("Cannot change signature set type", "Type is an immutable field")
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}

	stateSet := make(map[string]bool)
	for _, s := range state.Sources {
		stateSet[s.String()] = true
	}

	planSet := make(map[string]bool)
	for _, s := range plan.Sources {
		planSet[s.String()] = true
	}

	// Find removed elements
	removedList := []string{}
	for k := range stateSet {
		if !planSet[k] {
			removedList = append(removedList, common.TrimString(k))
		}
	}
	if len(removedList) > 0 {
		var payloaddelete CTESignatureSetJSON
		payloaddelete.Sources = removedList
		payloadJSONd, err := json.Marshal(payloaddelete)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_signature_set.go -> delete-sources]["+plan.ID.ValueString()+"]")
			diags.AddError(
				"[resource_cte_signature_set.go -> Signature set delete sources]",
				err.Error(),
			)
		}
		_, err = r.client.UpdateData(
			ctx,
			plan.ID.ValueString()+"/delete-sources",
			common.URL_CTE_SIGNATURE_SET,
			payloadJSONd,
			"id")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_signature_set.go -> Delete]["+plan.ID.ValueString()+"]")
			diags.AddError(
				"Error deleting clients list from the Signature set on CipherTrust Manager: ",
				"Could not delete clients list from the Signature set, unexpected error: "+err.Error()+fmt.Sprintf("%s", removedList),
			)
		}
	}
	if plan.Sources != nil {
		for _, source := range plan.Sources {
			payload.Sources = append(payload.Sources, source.ValueString())
		}
	}
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_signature_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Signature Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_CTE_SIGNATURE_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_signature_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Signature Set on CipherTrust Manager: ",
			"Could not update CTE Signature Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	diags = resp.State.Set(ctx, plan)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTESignatureSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTESignatureSetTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_SIGNATURE_SET, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_signature_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Signature Set",
			"Could not delete CTE Signature Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTESignatureSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	d.client = client
}

func setCTESignatureSetState(
	state *CTESignatureSetTFSDK,
	apiResp *CTESignatureSetJSON,
	resp *resource.ReadResponse,
) {
	state.ID = types.StringValue(apiResp.ID)
	state.URI = types.StringValue(apiResp.URI)
	state.Account = types.StringValue(apiResp.Account)
	state.DevAccount = types.StringValue(apiResp.DevAccount)
	state.Application = types.StringValue(apiResp.Application)
	state.Name = types.StringValue(apiResp.Name)
	state.Type = types.StringValue(apiResp.Type)

	if apiResp.Description != "" {
		state.Description = types.StringValue(apiResp.Description)
	} else {
		state.Description = types.StringNull()
	}

	// Labels
	labelsMap := map[string]attr.Value{}
	for k, v := range apiResp.Labels {
		if strVal, ok := v.(string); ok {
			labelsMap[k] = types.StringValue(strVal)
		}
	}
	labelsValue, diags := types.MapValue(types.StringType, labelsMap)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Labels = labelsValue

	// Sources
	var sources []types.String
	for _, src := range apiResp.Sources {
		sources = append(sources, types.StringValue(src))
	}
	state.Sources = sources
}

func (r *resourceCTESignatureSet) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_signature_set.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_signature_set.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
