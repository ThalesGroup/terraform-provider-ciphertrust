// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEClientGP{}
	_ resource.ResourceWithConfigure = &resourceCTEClientGP{}
)

func NewResourceCTEClientGP() resource.Resource {
	return &resourceCTEClientGP{}
}

type resourceCTEClientGP struct {
	client *common.Client
}

func (r *resourceCTEClientGP) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_guardpoint"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClientGP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A GuardPoint specifies the list of folders that contains paths to be protected." +
			" Access to files and encryption of files under the GuardPoint is controlled by security policies." +
			"GuardPoints created on a client group are applied to all clients in the group." +
			"NOTE: Any updation performed will be applicable to each gurad paths.Terraform Destroy will unguard the paths.",
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				Required:    true,
				Description: "CTE Client ID to be updated",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CTE Client Guardpoint ID to be updated or deleted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"guard_paths": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "List of GuardPaths to be created.",
			},
			"guard_point_params": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Parameters for creating a GuardPoint",
				Attributes: map[string]schema.Attribute{
					"guard_point_type": schema.StringAttribute{
						Required:    true,
						Description: "Type of the GuardPoint",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"directory_auto", "directory_manual", "rawdevice_manual", "rawdevice_auto", "cloudstorage_auto", "cloudstorage_manual", "ransomware_protection"}...),
						},
					},
					"policy_id": schema.StringAttribute{
						Required:    true,
						Description: "ID of the policy applied with this GuardPoint. This parameter is not valid for Ransomware GuardPoints as they will not be associated with any CTE policy.",
					},
					"automount_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether automount is enabled with the GuardPoint. Supported for Standard and LDT policies.",
					},
					"cifs_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to enable CIFS. Available on LDT enabled windows clients only. The default value is false. If you enable the setting, it cannot be disabled. Supported for only LDT policies.",
					},
					"data_classification_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether data classification (tagging) is enabled. Enabled by default if the aligned policy contains ClassificationTags. Supported for Standard and LDT policies.",
					},
					"data_lineage_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether data lineage (tracking) is enabled. Enabled only if data classification is enabled. Supported for Standard and LDT policies.",
					},
					"disk_name": schema.StringAttribute{
						Optional:    true,
						Description: "Name of the disk if the selected raw partition is a member of an Oracle ASM disk group.",
					},
					"diskgroup_name": schema.StringAttribute{
						Optional:    true,
						Description: "Name of the disk group if the selected raw partition is a member of an Oracle ASM disk group.",
					},
					"early_access": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether secure start (early access) is turned on. Secure start is applicable to Windows clients only. Supported for Standard and LDT policies. The default value is false.",
					},
					"intelligent_protection": schema.BoolAttribute{
						Optional:    true,
						Description: "Flag to enable intelligent protection for this GuardPoint. This flag is valid for GuardPoints with classification based policy only. Can only be set during GuardPoint creation.",
					},
					"is_idt_capable_device": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether the device where GuardPoint is applied is IDT capable or not. Supported for IDT policies.",
					},
					"mfa_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether MFA is enabled",
					},
					"network_share_credentials_id": schema.StringAttribute{
						Optional:    true,
						Description: "ID/Name of the credentials if the GuardPoint is applied to a network share. Supported for only LDT policies.",
					},
					"preserve_sparse_regions": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to preserve sparse file regions. Available on LDT enabled clients only. The default value is true. If you disable the setting, it cannot be enabled again. Supported for only LDT policies.",
					},
					"guard_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Returned from POST api after creating Guardpoints, can be updated later.",
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClientGP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEClientGuardPointTFSDK
	var guardpointParamsPlan CTEClientGuardPointParamsTFSDK
	var payload CTEClientGuardPointJSON
	var guardpointParamsPayload CTEClientGuardPointParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	guardpointParamsPlan = plan.GuardPointParams
	if plan.GuardPointParams.GPType.ValueString() != "" && plan.GuardPointParams.GPType.ValueString() != types.StringNull().ValueString() {
		guardpointParamsPayload.GPType = plan.GuardPointParams.GPType.ValueString()
	}
	if plan.GuardPointParams.PolicyID.ValueString() != "" && plan.GuardPointParams.PolicyID.ValueString() != types.StringNull().ValueString() {
		guardpointParamsPayload.PolicyID = plan.GuardPointParams.PolicyID.ValueString()
	}

	if plan.GuardPointParams.IsAutomountEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsAutomountEnabled = bool(guardpointParamsPlan.IsAutomountEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsCIFSEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsCIFSEnabled = bool(guardpointParamsPlan.IsCIFSEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsDataClassificationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsDataClassificationEnabled = bool(guardpointParamsPlan.IsDataClassificationEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsDataLineageEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsDataLineageEnabled = bool(guardpointParamsPlan.IsDataLineageEnabled.ValueBool())
	}
	if guardpointParamsPlan.DiskName.ValueString() != "" && guardpointParamsPlan.DiskName.ValueString() != types.StringNull().ValueString() {
		guardpointParamsPayload.DiskName = string(guardpointParamsPlan.DiskName.ValueString())
	}
	if guardpointParamsPlan.DiskgroupName.ValueString() != "" && guardpointParamsPlan.DiskgroupName.ValueString() != types.StringNull().ValueString() {
		guardpointParamsPayload.DiskgroupName = string(guardpointParamsPlan.DiskgroupName.ValueString())
	}
	if guardpointParamsPlan.IsEarlyAccessEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsEarlyAccessEnabled = bool(guardpointParamsPlan.IsEarlyAccessEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsIntelligentProtectionEnabled.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsIntelligentProtectionEnabled = bool(guardpointParamsPlan.IsIntelligentProtectionEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsDeviceIDTCapable.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.IsDeviceIDTCapable = bool(guardpointParamsPlan.IsDeviceIDTCapable.ValueBool())
	}
	if plan.GuardPointParams.IsMFAEnabled.ValueBool() != types.BoolNull().IsNull() {
		guardpointParamsPayload.IsMFAEnabled = plan.GuardPointParams.IsMFAEnabled.ValueBool()
	}
	if guardpointParamsPlan.NWShareCredentialsID.ValueString() != "" && guardpointParamsPlan.NWShareCredentialsID.ValueString() != types.StringNull().ValueString() {
		guardpointParamsPayload.NWShareCredentialsID = string(guardpointParamsPlan.NWShareCredentialsID.ValueString())
	}
	if guardpointParamsPlan.PreserveSparseRegions.ValueBool() != types.BoolNull().ValueBool() {
		guardpointParamsPayload.PreserveSparseRegions = bool(guardpointParamsPlan.PreserveSparseRegions.ValueBool())
	}
	payload.GuardPointParams = &guardpointParamsPayload

	for _, gp := range plan.GuardPaths {
		payload.GuardPaths = append(payload.GuardPaths, gp.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Guardpoint Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints",
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client Guardpoint on CipherTrust Manager: ",
			"Could not create CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(parseConfig(response))
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClientGP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGuardPointTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	client_id := state.CTEClientID.ValueString()
	_, err := r.client.GetById(ctx, id, "", common.URL_CTE_CLIENT+"/"+client_id+"/guardpoints")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Read]["+client_id+"]")
		resp.Diagnostics.AddError(
			"Error reading Guardpoints for Client id "+client_id+" on CipherTrust Manager: ",
			"Could not read CTE Client id :"+client_id+" unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client.go -> Read]["+id+"]")
}

// Update updates the each guardpoints created and sets the updated Terraform state on success.
func (r *resourceCTEClientGP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGuardPointTFSDK
	var guardpointParamsPlan CTEClientGuardPointParamsTFSDK
	var payload UpdateCTEGuardPointJSON

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
	id_list := strings.Split(state.ID.ValueString(), ",")
	var id []string

	guardpointParamsPlan = plan.GuardPointParams

	if guardpointParamsPlan.IsDataClassificationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsDataClassificationEnabled = bool(guardpointParamsPlan.IsDataClassificationEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsDataLineageEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsDataLineageEnabled = bool(guardpointParamsPlan.IsDataLineageEnabled.ValueBool())
	}
	if guardpointParamsPlan.IsGuardEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsGuardEnabled = guardpointParamsPlan.IsGuardEnabled.ValueBool()
	}
	if guardpointParamsPlan.IsMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsMFAEnabled = bool(guardpointParamsPlan.IsMFAEnabled.ValueBool())
	}
	if guardpointParamsPlan.NWShareCredentialsID.ValueString() != "" && guardpointParamsPlan.NWShareCredentialsID.ValueString() != types.StringNull().ValueString() {
		payload.NWShareCredentialsID = string(guardpointParamsPlan.NWShareCredentialsID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Update]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Guardpoint Update",
			err.Error(),
		)
		return
	}
	client_id := state.CTEClientID.ValueString()
	for _, gpId := range id_list {
		_, err := r.client.UpdateData(
			ctx,
			gpId,
			common.URL_CTE_CLIENT+"/"+client_id+"/guardpoints",
			payloadJSON,
			"")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Update]["+gpId+"]")
			resp.Diagnostics.AddError(
				"Error updating Guardpoint id "+gpId+" for client id "+client_id+" on CipherTrust Manager: ",
				"Could not update Guardpoint id "+gpId+", for client id "+client_id+" unexpected error: "+err.Error(),
			)
			return
		} else {
			tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Update]["+gpId+"]")
			id = append(id, gpId)
		}
	}
	state.ID = types.StringValue(strings.Join(id, ","))
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClientGP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGuardPointTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var payload CTEClientGuardPointUnguardJSON
	id_list := strings.Split(state.ID.ValueString(), ",")

	payload.GuardPointIdList = id_list

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Delete/Unguard]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Guardpoint Creation",
			err.Error(),
		)
		return
	}
	// Delete existing order
	output, err := r.client.UpdateData(ctx, "", common.URL_CTE_CLIENT+"/"+state.CTEClientID.ValueString()+"/guardpoints/unguard", payloadJSON, "")
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Delete/Unguard]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting/Unguarding CipherTrust CTE Client Guardpoint",
			"Could not delete/unguard CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}
	resp.State.RemoveResource(ctx)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *resourceCTEClientGP) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func parseConfig(response string) string {
	var ids []string
	guardpointSize := int((gjson.Get(string(response), "guardpoints.#")).Int())

	k := 0
	for k < guardpointSize {
		ids = append(ids, gjson.Get(string(response), fmt.Sprintf("guardpoints.%d.guardpoint.id", k)).String())
		k++
	}

	return strings.Join(ids, ",")
}
