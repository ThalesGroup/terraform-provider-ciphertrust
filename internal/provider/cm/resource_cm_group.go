// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMGroup{}
	_ resource.ResourceWithConfigure = &resourceCMGroup{}
)

func NewResourceCMGroup() resource.Resource {
	return &resourceCMGroup{}
}

type resourceCMGroup struct {
	client *common.Client
}

func (r *resourceCMGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_groups"
}

// Schema defines the schema for the resource.
func (r *resourceCMGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Unique group name.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"app_metadata": schema.StringAttribute{
				Optional:    true,
				Description: "Application-specific metadata associated with the group. Stored as compacted JSON string.",
			},
			"client_metadata": schema.StringAttribute{
				Optional:    true,
				Description: "Client-specific metadata associated with the group. Stored as compacted JSON string to prevent whitespace plan-time drift.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Human-readable description of the group.",
			},
			"user_metadata": schema.StringAttribute{
				Optional:    true,
				Description: "User-specific metadata associated with the group. Stored as compacted JSON string to prevent whitespace plan-time drift.",
			},
			"user_ids": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Set of user IDs that are members of this group. Managed declaratively: users in the set are added to the group; users removed from the set are removed from the group. If omitted, group membership is left as-is.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Create]["+id+"]")

	var plan CMGroupTFSDK
	var payload CMGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if !plan.AppMetadata.IsNull() && !plan.AppMetadata.IsUnknown() && plan.AppMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.AppMetadata.ValueString()), &meta) == nil {
			payload.AppMetadata = meta
		}
	}

	if !plan.ClientMetadata.IsNull() && !plan.ClientMetadata.IsUnknown() && plan.ClientMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.ClientMetadata.ValueString()), &meta) == nil {
			payload.ClientMetadata = meta
		}
	}

	if !plan.UserMetadata.IsNull() && !plan.UserMetadata.IsUnknown() && plan.UserMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.UserMetadata.ValueString()), &meta) == nil {
			payload.UserMetadata = meta
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Creating CipherTrust Group",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = plan.Name

	tflog.Debug(ctx, "[resource_cm_group.go -> Create Output]["+response+"]")

	desiredUsers, diagsUsers := setToStringSlice(ctx, plan.UserIDs)
	resp.Diagnostics.Append(diagsUsers...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, uid := range desiredUsers {
		if err := r.addUserToGroup(ctx, id, plan.Name.ValueString(), uid); err != nil {
			resp.Diagnostics.AddError(
				"Error Adding User to CipherTrust Group",
				fmt.Sprintf("Could not add user %q to group %q: %s", uid, plan.Name.ValueString(), err.Error()),
			)
			return
		}
	}
	plan.UserIDs = stringSliceToSet(desiredUsers)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Read]["+id+"]")

	var state CMGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := state.ID.ValueString()

	response, err := r.client.GetById(ctx, id, resourceID, common.URL_GROUP)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "CipherTrust Group not found, removing from state [resource_cm_group.go -> Read]["+resourceID+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Read]["+resourceID+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group",
			"Could not read group "+resourceID+": "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.ID = state.Name

	if v := gjson.Get(response, "description"); v.Exists() && v.String() != "" {
		state.Description = types.StringValue(v.String())
	} else {
		state.Description = types.StringNull()
	}

	if v := gjson.Get(response, "app_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		// Normalize to compact JSON so whitespace differences between CM and
		// CDSPaaS responses don't surface as phantom drift in subsequent plans.
		compacted := compactJSONString(v.Raw)
		state.AppMetadata = types.StringValue(compacted)
	} else {
		state.AppMetadata = types.StringNull()
	}

	if v := gjson.Get(response, "client_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		state.ClientMetadata = types.StringValue(compactJSONString(v.Raw))
	} else {
		state.ClientMetadata = types.StringNull()
	}

	if v := gjson.Get(response, "user_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		state.UserMetadata = types.StringValue(compactJSONString(v.Raw))
	} else {
		state.UserMetadata = types.StringNull()
	}

	members, err := r.listGroupMembers(ctx, id, state.Name.ValueString())
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Read members]["+resourceID+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group Members",
			"Could not list members of group "+resourceID+": "+err.Error(),
		)
		return
	}
	state.UserIDs = stringSliceToSet(members)

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Update]["+id+"]")
	var plan, state CMGroupTFSDK
	var payload CMGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	// Three-branch pattern for each metadata field:
	//
	//   IsNull()    → per-key null deletion (confirmed live: CM ignores {} and null at the
	//                 field level, but honours {"key":null} to delete individual keys).
	//                 Parse the prior state JSON to extract existing keys, then set each to
	//                 nil so CM's merge-PATCH deletes them. Read()'s guard (v.Raw != "{}")
	//                 maps the resulting {} or absent response back to types.StringNull().
	//
	//   IsUnknown() → skip (deferred reference; CM value preserved).
	//   else        → unmarshal and send the JSON object.
	if plan.AppMetadata.IsNull() {
		if !state.AppMetadata.IsNull() && state.AppMetadata.ValueString() != "" {
			var stateMap map[string]interface{}
			if json.Unmarshal([]byte(state.AppMetadata.ValueString()), &stateMap) == nil {
				nullMap := make(map[string]interface{}, len(stateMap))
				for k := range stateMap {
					nullMap[k] = nil
				}
				payload.AppMetadata = nullMap
			}
		}
	} else if !plan.AppMetadata.IsUnknown() && plan.AppMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.AppMetadata.ValueString()), &meta) == nil {
			payload.AppMetadata = meta
		}
	}

	if plan.ClientMetadata.IsNull() {
		if !state.ClientMetadata.IsNull() && state.ClientMetadata.ValueString() != "" {
			var stateMap map[string]interface{}
			if json.Unmarshal([]byte(state.ClientMetadata.ValueString()), &stateMap) == nil {
				nullMap := make(map[string]interface{}, len(stateMap))
				for k := range stateMap {
					nullMap[k] = nil
				}
				payload.ClientMetadata = nullMap
			}
		}
	} else if !plan.ClientMetadata.IsUnknown() && plan.ClientMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.ClientMetadata.ValueString()), &meta) == nil {
			payload.ClientMetadata = meta
		}
	}

	if plan.UserMetadata.IsNull() {
		if !state.UserMetadata.IsNull() && state.UserMetadata.ValueString() != "" {
			var stateMap map[string]interface{}
			if json.Unmarshal([]byte(state.UserMetadata.ValueString()), &stateMap) == nil {
				nullMap := make(map[string]interface{}, len(stateMap))
				for k := range stateMap {
					nullMap[k] = nil
				}
				payload.UserMetadata = nullMap
			}
		}
	} else if !plan.UserMetadata.IsUnknown() && plan.UserMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.UserMetadata.ValueString()), &meta) == nil {
			payload.UserMetadata = meta
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error Updating CipherTrust Group",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Name = types.StringValue(response)
	plan.ID = plan.Name

	if !plan.UserIDs.IsNull() && !plan.UserIDs.IsUnknown() {
		desired, diagsDes := setToStringSlice(ctx, plan.UserIDs)
		resp.Diagnostics.Append(diagsDes...)
		if resp.Diagnostics.HasError() {
			return
		}
		current, diagsCur := setToStringSlice(ctx, state.UserIDs)
		resp.Diagnostics.Append(diagsCur...)
		if resp.Diagnostics.HasError() {
			return
		}
		toAdd, toRemove := diffStringSlices(current, desired)
		for _, uid := range toRemove {
			if err := r.removeUserFromGroup(ctx, id, plan.Name.ValueString(), uid); err != nil {
				resp.Diagnostics.AddError(
					"Error Removing User from CipherTrust Group",
					fmt.Sprintf("Could not remove user %q from group %q: %s", uid, plan.Name.ValueString(), err.Error()),
				)
				if actualMembers, errRead := r.listGroupMembers(ctx, id, plan.Name.ValueString()); errRead == nil {
					plan.UserIDs = stringSliceToSet(actualMembers)
				}
				_ = resp.State.Set(ctx, plan)
				return
			}
		}
		for _, uid := range toAdd {
			if err := r.addUserToGroup(ctx, id, plan.Name.ValueString(), uid); err != nil {
				resp.Diagnostics.AddError(
					"Error Adding User to CipherTrust Group",
					fmt.Sprintf("Could not add user %q to group %q: %s", uid, plan.Name.ValueString(), err.Error()),
				)
				if actualMembers, errRead := r.listGroupMembers(ctx, id, plan.Name.ValueString()); errRead == nil {
					plan.UserIDs = stringSliceToSet(actualMembers)
				}
				_ = resp.State.Set(ctx, plan)
				return
			}
		}
		plan.UserIDs = stringSliceToSet(desired)
	} else {
		plan.UserIDs = state.UserIDs
	}

	// Seed resp.State with the updated plan so Read() can locate the resource by ID.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delegate final state hydration to Read() so state reflects what CM actually
	// persisted (metadata cleared/updated, compact-normalised values, membership)
	// rather than the raw plan values.
	//
	// RemoveResource guard: the existing Read() calls resp.State.RemoveResource(ctx)
	// on 404. RemoveResource does NOT add an error diagnostic, so HasError() alone
	// cannot detect it. The Plugin Framework's RemoveResource sets the underlying
	// tftypes.Value to a null object (IsNull() → true). A fresh ReadResponse
	// initialised with State: resp.State starts with a non-null, non-undefined
	// tftypes.Value; after r.Read() runs, the combined IsNull()||Type()==nil
	// guard correctly distinguishes a RemoveResource call from a successful hydration.
	readReq := resource.ReadRequest{State: resp.State}
	readResp := &resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, readResp)
	if readResp.Diagnostics.HasError() {
		resp.Diagnostics.Append(readResp.Diagnostics...)
		return
	}
	if readResp.State.Raw.IsNull() || readResp.State.Raw.Type() == nil {
		// Read() called RemoveResource (transient 404 after successful PATCH).
		// Retain the seeded plan state; log a warning for operator visibility.
		tflog.Warn(ctx, "[resource_cm_group.go -> Update] Read() returned empty state after "+
			"successful PATCH (possible transient 404); retaining seeded plan state. "+
			"Resource: "+plan.Name.ValueString()+" ["+id+"]")
		return
	}
	// Read succeeded — use its hydrated state.
	resp.State = readResp.State
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMGroupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_GROUP, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Group",
			"Could not delete group, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// compactJSONString returns s compacted (no extra whitespace). If compaction
// fails it returns s unchanged — keeps JSON round-trips safe when the server
// returns pretty-printed JSON and the config stores compact JSON.
func compactJSONString(s string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return string(b)
}

func (r *resourceCMGroup) addUserToGroup(ctx context.Context, uuid, groupName, userID string) error {
	endpoint := fmt.Sprintf("%s/%s/users/%s", common.URL_GROUP, groupName, userID)
	_, err := r.client.PostNoData(ctx, uuid, endpoint)
	return err
}

// removeUserFromGroup is idempotent: per the swagger, DELETE /usermgmt/groups/{name}/users/{user_id}
// returns 400 when the user is not a member of the group and 404 when the group
// itself doesn't exist. Either condition means there's nothing to remove, so we
// swallow both rather than fail the Update.
func (r *resourceCMGroup) removeUserFromGroup(ctx context.Context, uuid, groupName, userID string) error {
	endpoint := fmt.Sprintf("%s/%s/users/%s", common.URL_GROUP, groupName, userID)
	_, err := r.client.DeleteByURL(ctx, uuid, endpoint)
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, notFoundError) || strings.Contains(msg, notMemberOfGroupErrorFragment) {
		return nil
	}
	return err
}

// listGroupMembers returns the user IDs currently in groupName.
// CipherTrust's user list endpoint (GET /usermgmt/users) supports filtering
// by group via ?groups=<name>. Handles pagination in skip/limit chunks.
func (r *resourceCMGroup) listGroupMembers(ctx context.Context, uuid, groupName string) ([]string, error) {
	ids := []string{}
	skip := 0
	limit := 100
	for {
		filters := url.Values{}
		filters.Set("groups", groupName)
		filters.Set("skip", fmt.Sprintf("%d", skip))
		filters.Set("limit", fmt.Sprintf("%d", limit))

		body, err := r.client.ListWithFilters(ctx, uuid, common.URL_USER_MANAGEMENT, filters)
		if err != nil {
			return nil, err
		}

		resources := gjson.Get(body, "resources").Array()
		if len(resources) == 0 {
			break
		}

		for _, res := range resources {
			if v := res.Get("user_id").String(); v != "" {
				ids = append(ids, v)
			}
		}

		if len(resources) < limit {
			break
		}
		skip += limit
	}
	return ids, nil
}

// setToStringSlice extracts the strings from a types.Set; returns nil if the
// set is null or unknown.
func setToStringSlice(ctx context.Context, s types.Set) ([]string, diag.Diagnostics) {
	if s.IsNull() || s.IsUnknown() {
		return nil, nil
	}
	out := []string{}
	d := s.ElementsAs(ctx, &out, false)
	return out, d
}

// stringSliceToSet builds a types.Set[String] from the given slice. A nil slice
// produces an empty (non-null) set so that Read can distinguish "no members"
// from "unknown".
func stringSliceToSet(in []string) types.Set {
	elems := make([]attr.Value, 0, len(in))
	for _, v := range in {
		elems = append(elems, types.StringValue(v))
	}
	set, _ := types.SetValue(types.StringType, elems)
	return set
}

// diffStringSlices returns (toAdd, toRemove) — the elements present in desired
// but not current, and vice versa.
func diffStringSlices(current, desired []string) (toAdd, toRemove []string) {
	curSet := make(map[string]struct{}, len(current))
	for _, v := range current {
		curSet[v] = struct{}{}
	}
	desSet := make(map[string]struct{}, len(desired))
	for _, v := range desired {
		desSet[v] = struct{}{}
	}
	for _, v := range desired {
		if _, ok := curSet[v]; !ok {
			toAdd = append(toAdd, v)
		}
	}
	for _, v := range current {
		if _, ok := desSet[v]; !ok {
			toRemove = append(toRemove, v)
		}
	}
	return toAdd, toRemove
}
