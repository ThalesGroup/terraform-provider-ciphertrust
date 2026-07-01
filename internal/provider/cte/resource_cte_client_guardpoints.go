// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

var (
	_ resource.Resource                = &resourceCTEClientGP{}
	_ resource.ResourceWithConfigure   = &resourceCTEClientGP{}
	_ resource.ResourceWithImportState = &resourceCTEClientGP{}
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

func (r *resourceCTEClientGP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A GuardPoint specifies the list of folders that contains paths to be protected." +
			" Access to files and encryption of files under the GuardPoint is controlled by security policies." +
			" Terraform Destroy will unguard the paths.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Comma-separated list of GuardPoint IDs managed by this resource.",
			},
			"client_id": schema.StringAttribute{
				Required:    true,
				Description: "CTE Client ID.",
			},
			"guard_points": schema.MapNestedAttribute{
				Required:    true,
				Description: "Map of GuardPoints keyed by guard_path. Each key is the path to guard.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "GuardPoint ID returned by the API.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"guard_point_params": schema.SingleNestedAttribute{
							Required:    true,
							Description: "Parameters for this GuardPoint.",
							Attributes: map[string]schema.Attribute{
								"guard_point_type": schema.StringAttribute{
									Required:    true,
									Description: "Type of the GuardPoint.",
								},
								"policy_id": schema.StringAttribute{
									Required:    true,
									Description: "ID of the policy applied with this GuardPoint.",
								},
								"automount_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether automount is enabled with the GuardPoint.",
								},
								"cifs_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether to enable CIFS.",
								},
								"data_classification_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data classification is enabled.",
								},
								"data_lineage_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data lineage is enabled.",
								},
								"disk_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk for Oracle ASM disk group.",
								},
								"diskgroup_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk group for Oracle ASM.",
								},
								"early_access": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether secure start is turned on.",
								},
								"intelligent_protection": schema.BoolAttribute{
									Optional:    true,
									Description: "Flag to enable intelligent protection.",
								},
								"is_idt_capable_device": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether the device is IDT capable.",
								},
								"mfa_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether MFA is enabled.",
								},
								"network_share_credentials_id": schema.StringAttribute{
									Optional:    true,
									Description: "ID of the credentials for network share.",
								},
								"preserve_sparse_regions": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether to preserve sparse file regions.",
								},
								"guard_enabled": schema.BoolAttribute{
									Optional:    true,
									Computed:    true,
									Default:     booldefault.StaticBool(true),
									Description: "Whether the GuardPoint is enabled.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")

	var plan CTEClientGuardPointTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	type batchKey struct {
		GPType                string
		PolicyID              string
		IsAutomountEnabled    bool
		IsCIFSEnabled         bool
		IsEarlyAccessEnabled  bool
		IsDeviceIDTCapable    bool
		IsMFAEnabled          bool
		PreserveSparseRegions bool
		NWShareCredentialsID  string
		DiskName              string
		DiskgroupName         string
	}
	type batchEntry struct {
		params     CTEClientGuardPointParamsTFSDK
		guardPaths []string // ordered list of paths in this batch
	}

	batchMap := make(map[batchKey]*batchEntry)
	var batchOrder []batchKey

	for guardPath, entry := range plan.GuardPoints {
		p := entry.GuardPointParams
		key := batchKey{
			GPType:                p.GPType.ValueString(),
			PolicyID:              p.PolicyID.ValueString(),
			IsAutomountEnabled:    p.IsAutomountEnabled.ValueBool(),
			IsCIFSEnabled:         p.IsCIFSEnabled.ValueBool(),
			IsEarlyAccessEnabled:  p.IsEarlyAccessEnabled.ValueBool(),
			IsDeviceIDTCapable:    p.IsDeviceIDTCapable.ValueBool(),
			IsMFAEnabled:          p.IsMFAEnabled.ValueBool(),
			PreserveSparseRegions: p.PreserveSparseRegions.ValueBool(),
			NWShareCredentialsID:  p.NWShareCredentialsID.ValueString(),
			DiskName:              p.DiskName.ValueString(),
			DiskgroupName:         p.DiskgroupName.ValueString(),
		}
		if _, exists := batchMap[key]; !exists {
			batchMap[key] = &batchEntry{params: p}
			batchOrder = append(batchOrder, key)
		}
		batchMap[key].guardPaths = append(batchMap[key].guardPaths, guardPath)
	}

	// pathToID collects the API-assigned ID for each guard_path after creation.
	pathToID := make(map[string]string)

	for _, key := range batchOrder {
		entry := batchMap[key]
		p := entry.params

		paramsPayload := buildParamsPayload(p)
		payload := CTEClientGuardPointJSON{
			GuardPaths:       entry.guardPaths,
			GuardPointParams: &paramsPayload,
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Creation", err.Error())
			return
		}

		response, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Error creating CTE Client Guardpoint on CipherTrust Manager: ",
				"Could not create CTE Client Guardpoint, unexpected error: "+err.Error(),
			)
			return
		}

		// Parse IDs from the API response JSON by matching guard_path, not position.
		gpSize := int(gjson.Get(response, "guardpoints.#").Int())
		for i := 0; i < gpSize; i++ {
			returnedPath := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.guard_path", i)).String()
			returnedID := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.id", i)).String()
			if returnedPath != "" && returnedID != "" {
				pathToID[returnedPath] = returnedID
			}
		}
	}

	// Write IDs back into the plan map and build the top-level composite ID.
	var allIDs []string
	for guardPath, entry := range plan.GuardPoints {
		gpID := pathToID[guardPath]
		entry.ID = types.StringValue(gpID)
		plan.GuardPoints[guardPath] = entry
		allIDs = append(allIDs, gpID)
	}
	sort.Strings(allIDs)
	plan.ID = types.StringValue(strings.Join(allIDs, ","))

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGuardPointTFSDK
	id := uuid.New().String()

	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_client_guardpoints.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	clientID := state.CTEClientID.ValueString()

	response, err := r.client.GetById(ctx, id, "", common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints")
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			tflog.Debug(ctx, "[resource_cte_client_guardpoints.go -> Read] parent client "+clientID+" not found (404), removing guardpoint resource from state")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Read]["+clientID+"]")
		resp.Diagnostics.AddError(
			"Error reading Guardpoints for Client id "+clientID+" on CipherTrust Manager: ",
			"Could not read CTE Client id: "+clientID+", unexpected error: "+err.Error(),
		)
		return
	}

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var envelope struct {
		Resources []CTEClientGuardPointListJSON `json:"resources"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Read]["+clientID+"]")
		resp.Diagnostics.AddError(
			"Error parsing Guardpoints response for Client id "+clientID,
			err.Error(),
		)
		return
	}

	newGuardPoints := make(map[string]CTEClientGroupGuardPointEntryTFSDK)
	var allIDs []string

	for _, gp := range envelope.Resources {
		prevEntry, hadPrior := state.GuardPoints[gp.GuardPath]

		entry := CTEClientGroupGuardPointEntryTFSDK{
			ID: types.StringValue(gp.ID),
			GuardPointParams: CTEClientGuardPointParamsTFSDK{
				GPType:         types.StringValue(gp.GuardPointType),
				IsGuardEnabled: types.BoolValue(gp.GuardEnabled),
				PolicyID:       types.StringValue(gp.PolicyID),
			},
		}

		if hadPrior {
			p := prevEntry.GuardPointParams
			entry.GuardPointParams.IsAutomountEnabled = p.IsAutomountEnabled
			entry.GuardPointParams.IsCIFSEnabled = p.IsCIFSEnabled
			entry.GuardPointParams.IsEarlyAccessEnabled = p.IsEarlyAccessEnabled
			entry.GuardPointParams.IsDeviceIDTCapable = p.IsDeviceIDTCapable
			entry.GuardPointParams.IsMFAEnabled = p.IsMFAEnabled
			entry.GuardPointParams.PreserveSparseRegions = p.PreserveSparseRegions
			entry.GuardPointParams.IsDataClassificationEnabled = p.IsDataClassificationEnabled
			entry.GuardPointParams.IsDataLineageEnabled = p.IsDataLineageEnabled
			entry.GuardPointParams.IsIntelligentProtectionEnabled = p.IsIntelligentProtectionEnabled
			entry.GuardPointParams.NWShareCredentialsID = p.NWShareCredentialsID
			entry.GuardPointParams.DiskName = p.DiskName
			entry.GuardPointParams.DiskgroupName = p.DiskgroupName
		}

		newGuardPoints[gp.GuardPath] = entry
		allIDs = append(allIDs, gp.ID)
	}

	state.GuardPoints = newGuardPoints
	sort.Strings(allIDs)
	state.ID = types.StringValue(strings.Join(allIDs, ","))

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGuardPointTFSDK

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

	//immutable field handling for client id
	if state.CTEClientID.ValueString() != plan.CTEClientID.ValueString() {
		resp.Diagnostics.AddError("Cannot change client_id", "client_id is an immutable field")
		return
	}
	clientID := plan.CTEClientID.ValueString()

	// ---------------------------------------------------------------
	// PHASE 0 — UNGUARD guardpoints whose guard_path was removed from plan.
	// With MapNestedAttribute, a removed key == a removed guardpoint.
	// ---------------------------------------------------------------
	var removedIDs []string
	for guardPath, stateEntry := range state.GuardPoints {
		if _, stillInPlan := plan.GuardPoints[guardPath]; !stillInPlan {
			removedIDs = append(removedIDs, stateEntry.ID.ValueString())
		}
	}

	if len(removedIDs) > 0 {
		unguardPayload := CTEClientGuardPointUnguardJSON{
			GuardPointIdList: removedIDs,
		}
		unguardPayloadJSON, err := json.Marshal(unguardPayload)
		if err != nil {
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Unguard during Update", err.Error())
			return
		}

		_, err = r.client.UpdateData(
			ctx,
			"",
			common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/unguard",
			unguardPayloadJSON,
			"",
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error unguarding removed Guardpoints for client "+clientID,
				err.Error(),
			)
			return
		}

		tflog.Trace(ctx, "[resource_cte_client_guardpoints.go -> Update/Unguard] unguarded IDs: "+strings.Join(removedIDs, ","))
	}

	// ---------------------------------------------------------------
	// PHASE 1 — CREATE guard_paths that are new in the plan (not in state).
	// ---------------------------------------------------------------
	type batchKey struct {
		GPType                string
		PolicyID              string
		IsAutomountEnabled    bool
		IsCIFSEnabled         bool
		IsEarlyAccessEnabled  bool
		IsDeviceIDTCapable    bool
		IsMFAEnabled          bool
		PreserveSparseRegions bool
		NWShareCredentialsID  string
		DiskName              string
		DiskgroupName         string
	}
	type batchEntry struct {
		params     CTEClientGuardPointParamsTFSDK
		guardPaths []string
	}

	batchMap := make(map[batchKey]*batchEntry)
	var batchOrder []batchKey
	newPaths := make(map[string]bool) // track which paths were just created

	for guardPath, planEntry := range plan.GuardPoints {
		if _, existsInState := state.GuardPoints[guardPath]; existsInState {
			continue // already exists — handle in Phase 2
		}

		p := planEntry.GuardPointParams
		key := batchKey{
			GPType:                p.GPType.ValueString(),
			PolicyID:              p.PolicyID.ValueString(),
			IsAutomountEnabled:    p.IsAutomountEnabled.ValueBool(),
			IsCIFSEnabled:         p.IsCIFSEnabled.ValueBool(),
			IsEarlyAccessEnabled:  p.IsEarlyAccessEnabled.ValueBool(),
			IsDeviceIDTCapable:    p.IsDeviceIDTCapable.ValueBool(),
			IsMFAEnabled:          p.IsMFAEnabled.ValueBool(),
			PreserveSparseRegions: p.PreserveSparseRegions.ValueBool(),
			NWShareCredentialsID:  p.NWShareCredentialsID.ValueString(),
			DiskName:              p.DiskName.ValueString(),
			DiskgroupName:         p.DiskgroupName.ValueString(),
		}
		if _, exists := batchMap[key]; !exists {
			batchMap[key] = &batchEntry{params: p}
			batchOrder = append(batchOrder, key)
		}
		batchMap[key].guardPaths = append(batchMap[key].guardPaths, guardPath)
		newPaths[guardPath] = true
	}

	pathToNewID := make(map[string]string)

	for _, key := range batchOrder {
		entry := batchMap[key]
		p := entry.params

		paramsPayload := buildParamsPayload(p)
		payload := CTEClientGuardPointJSON{
			GuardPaths:       entry.guardPaths,
			GuardPointParams: &paramsPayload,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Create-in-Update", err.Error())
			return
		}

		createID := uuid.New().String()
		response, err := r.client.PostDataV2(
			ctx,
			createID,
			common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating new Guardpoint during Update for client "+clientID,
				err.Error(),
			)
			return
		}

		// Parse IDs from the API response JSON by matching guard_path, not position.
		gpSize := int(gjson.Get(response, "guardpoints.#").Int())
		for i := 0; i < gpSize; i++ {
			returnedPath := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.guard_path", i)).String()
			returnedID := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.id", i)).String()
			if returnedPath != "" && returnedID != "" {
				pathToNewID[returnedPath] = returnedID
			}
		}
	}

	// ---------------------------------------------------------------
	// PHASE 2 — UPDATE existing guardpoints
	// ---------------------------------------------------------------
	var allIDs []string

	for guardPath, planEntry := range plan.GuardPoints {
		var gpID string

		if newPaths[guardPath] {
			// Newly created in Phase 1 — params already sent, just record ID.
			gpID = pathToNewID[guardPath]
		} else {
			// Existing — carry state ID forward and send an update.
			stateEntry := state.GuardPoints[guardPath]
			gpID = stateEntry.ID.ValueString()

			// ---------------------------------------------------------------
			// IMMUTABLE FIELD CHECK — policy_id and guard_point_type cannot change
			// ---------------------------------------------------------------

			statePolicyID := stateEntry.GuardPointParams.PolicyID.ValueString()
			planPolicyID := planEntry.GuardPointParams.PolicyID.ValueString()
			if statePolicyID != planPolicyID {
				resp.Diagnostics.AddError(
					"Cannot change policy_id for an existing GuardPoint",
					fmt.Sprintf(
						"guard_path %q has policy_id %q in state but %q in plan. "+
							"policy_id is immutable once a GuardPoint is created. "+
							"To change it, remove this guard_path and re-add it with the new policy_id.",
						guardPath, statePolicyID, planPolicyID,
					),
				)
				return
			}

			stateGPType := stateEntry.GuardPointParams.GPType.ValueString()
			planGPType := planEntry.GuardPointParams.GPType.ValueString()
			if stateGPType != planGPType {
				resp.Diagnostics.AddError(
					"Cannot change guard_point_type for an existing GuardPoint",
					fmt.Sprintf(
						"guard_path %q has guard_point_type %q in state but %q in plan. "+
							"guard_point_type is immutable once a GuardPoint is created. "+
							"To change it, remove this guard_path and re-add it with the new guard_point_type.",
						guardPath, stateGPType, planGPType,
					),
				)
				return
			}

			var payload UpdateCTEGuardPointJSON

			if !planEntry.GuardPointParams.IsGuardEnabled.IsNull() {
				v := planEntry.GuardPointParams.IsGuardEnabled.ValueBool()
				payload.IsGuardEnabled = &v
			}
			if planEntry.GuardPointParams.NWShareCredentialsID.ValueString() != "" {
				payload.NWShareCredentialsID = planEntry.GuardPointParams.NWShareCredentialsID.ValueString()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Update", err.Error())
				return
			}

			_, err = r.client.UpdateData(
				ctx,
				gpID,
				common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints",
				payloadJSON,
				"",
			)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating Guardpoint id "+gpID+" for client id "+clientID,
					err.Error(),
				)
				return
			}

			tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Update]["+gpID+"]")
		}

		// Write the resolved ID back into the plan map entry.
		entry := plan.GuardPoints[guardPath]
		entry.ID = types.StringValue(gpID)
		plan.GuardPoints[guardPath] = entry

		allIDs = append(allIDs, gpID)
	}

	sort.Strings(allIDs)
	plan.ID = types.StringValue(strings.Join(allIDs, ","))
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGuardPointTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var idList []string
	for _, entry := range state.GuardPoints {
		idList = append(idList, entry.ID.ValueString())
	}

	payload := CTEClientGuardPointUnguardJSON{
		GuardPointIdList: idList,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Delete/Unguard]")
		resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Delete/Unguard", err.Error())
		return
	}

	output, err := r.client.UpdateData(
		ctx,
		"",
		common.URL_CTE_CLIENT+"/"+state.CTEClientID.ValueString()+"/guardpoints/unguard",
		payloadJSON,
		"",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Delete/Unguard]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting/Unguarding CipherTrust CTE Client Guardpoint",
			"Could not delete/unguard CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}

	resp.State.RemoveResource(ctx)
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

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

func (r *resourceCTEClientGP) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_client_gp.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_client_gp.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("client_id"), req, resp)
}
