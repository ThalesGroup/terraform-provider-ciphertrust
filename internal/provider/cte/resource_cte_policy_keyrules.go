package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &resourceCTEPolicyKeyRule{}
	_ resource.ResourceWithConfigure   = &resourceCTEPolicyKeyRule{}
	_ resource.ResourceWithImportState = &resourceCTEPolicyKeyRule{}
	_ resource.ResourceWithModifyPlan  = &resourceCTEPolicyKeyRule{}
)

func NewResourceCTEPolicyKeyRule() resource.Resource {
	return &resourceCTEPolicyKeyRule{}
}

type resourceCTEPolicyKeyRule struct {
	client *common.Client
}

func (r *resourceCTEPolicyKeyRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_key_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicyKeyRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Key Rule need to be added",
			},
			"rule": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Key rule to be updated in the parent policy.",
				Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{
						Computed:    true,
						Description: "Identifier of the key rule.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"order_number": schema.Int64Attribute{
						Optional:    true,
						Computed:    true,
						Description: "Precedence order of the rule in the parent policy.",
						// TFIN-610: adding ModifyPlan (below) to this resource
						// causes the framework to mark computed-and-unset
						// attributes lacking their own plan modifier as
						// unknown ahead of ModifyPlan running, producing a
						// perpetual "known after apply" diff for this field
						// on every plan. UseStateForUnknown restores the
						// original (pre-ModifyPlan) behavior of carrying the
						// prior state value forward when unconfigured.
						PlanModifiers: []planmodifier.Int64{
							int64planmodifier.UseStateForUnknown(),
						},
					},
					"key_id": schema.StringAttribute{
						Optional:    true,
						Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
					},
					"key_type": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
					},
					"resource_set_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Description: "ID of the resource set to link with the rule. Supported for Standard, LDT and IDT policies.",
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicyKeyRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_policy_keyrules.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CTEPolicyAddKeyRuleTFSDK
	var payload KeyRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KeyRule.KeyID.ValueString() != "" && plan.KeyRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.KeyRule.KeyID.ValueString())
	}
	if plan.KeyRule.KeyType.ValueString() != "" && plan.KeyRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.KeyRule.KeyType.ValueString())
	}
	if plan.KeyRule.ResourceSetID.ValueString() != "" && plan.KeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.KeyRule.ResourceSetID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_keyrules.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Key Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/keyrules",
		payloadJSON,
	)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_keyrules.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Key Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Key Rule, unexpected error: "+err.Error(),
		)
		return
	}

	var newRule KeyRuleJSON
	if err := json.Unmarshal([]byte(response), &newRule); err != nil {
		resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
		return
	}

	plan.KeyRule.ID = types.StringValue(newRule.ID)
	plan.KeyRule.OrderNumber = types.Int64Value(*newRule.OrderNumber)

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_keyrules.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicyKeyRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	var state CTEPolicyAddKeyRuleTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(
		ctx,
		id,
		state.KeyRule.ID.ValueString(),
		common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/keyrules",
	)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp KeyRuleJSON
	if err = json.Unmarshal([]byte(response), &apiResp); err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_keyrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error parsing CTE Policy Key Rule response",
			err.Error(),
		)
		return
	}

	// TFIN-472: CM's GET response for this endpoint never includes key_type at
	// all (write-only at the API level), so it always unmarshals as "".
	// Overwriting state from the API response would cause a perpetual plan
	// diff against the user's configured value on every refresh. Preserve the
	// existing (config-sourced) state value for key_type instead of blindly
	// overwriting it from the API response; still refresh the fields CM does
	// return correctly.
	//
	// TFIN-470/TFIN-610: resource_set_id is the opposite case -- CM DOES
	// return it consistently (normalized to the resource set's name), so it
	// must be refreshed from the API response like id/order_number/key_id
	// below. TFIN-470's original fix instead preserved the existing state
	// value here (mirroring the key_type workaround), which stopped the
	// visible perpetual diff but as a side effect made Read() never detect a
	// genuine out-of-band resource_set_id change at all -- a silent-drift
	// regression (TFIN-610). Always refreshing it from apiResp fixes that;
	// ModifyPlan below (TFIN-610) reconciles the resulting name-vs-UUID
	// representation mismatch against config so this doesn't reintroduce the
	// original visible perpetual diff.
	state.KeyRule.ID = types.StringValue(apiResp.ID)
	state.KeyRule.OrderNumber = types.Int64Value(*apiResp.OrderNumber)
	state.KeyRule.KeyID = types.StringValue(apiResp.KeyID)
	state.KeyRule.ResourceSetID = types.StringValue(apiResp.ResourceSetID)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_keyrules.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// ModifyPlan normalizes rule.resource_set_id so state (always the CM-returned
// name form, per Read() above) and config (which may supply either a UUID or
// a name) can be compared consistently (TFIN-610). Without this, refreshing
// state.ResourceSetID from CM's response would show a perpetual diff for any
// config that supplies a UUID -- the exact visible bug TFIN-470 originally
// fixed by a different means. If the planned value resolves to the same
// resource set as the current state, the plan is pinned to the existing
// state value (no diff); a genuine change is left untouched so it surfaces
// normally.
func (r *resourceCTEPolicyKeyRule) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.client == nil || req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var plan, state CTEPolicyAddKeyRuleTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if resolved, ok := modifyPlanCTERuleResourceSetID(
		ctx,
		r.client,
		plan.KeyRule.ResourceSetID.ValueString(),
		state.KeyRule.ResourceSetID.ValueString(),
		!plan.KeyRule.ResourceSetID.IsUnknown(),
	); ok {
		plan.KeyRule.ResourceSetID = types.StringValue(resolved)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicyKeyRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEPolicyAddKeyRuleTFSDK
	var payload KeyRuleJSON

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
	//immutable field handling
	if plan.CTEClientPolicyID.ValueString() != state.CTEClientPolicyID.ValueString() {
		resp.Diagnostics.AddError("Cannot change policy ID associated with policy rule", "Policy ID is an immutable field")
		return
	}

	if plan.KeyRule.KeyID.ValueString() != "" && plan.KeyRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.KeyRule.KeyID.ValueString())
	}
	if plan.KeyRule.KeyType.ValueString() != "" && plan.KeyRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.KeyRule.KeyType.ValueString())
	}
	// TFIN-610: only send order_number when it is actually changing. order_number
	// now carries UseStateForUnknown (added above to counteract ModifyPlan's side
	// effect of marking unconfigured computed attributes unknown), so it is
	// "known" on every Update() call even when unchanged -- previously it would
	// often have been unknown/omitted here. Confirmed via live CM: including an
	// unchanged order_number in the same PATCH as a resource_set_id clear
	// ("resource_set_id":"") causes CM to silently ignore the clear (a CM-side
	// quirk); omitting order_number when it isn't actually changing avoids
	// triggering that.
	if !plan.KeyRule.OrderNumber.IsNull() && !plan.KeyRule.OrderNumber.IsUnknown() &&
		plan.KeyRule.OrderNumber.ValueInt64() != state.KeyRule.OrderNumber.ValueInt64() {
		OrderNumber := plan.KeyRule.OrderNumber.ValueInt64()
		payload.OrderNumber = &OrderNumber
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_keyrules.go -> Update][" + plan.KeyRule.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Key Rule Update",
			err.Error(),
		)
		return
	}

	// TFIN-471: KeyRuleJSON.ResourceSetID carries `omitempty` (needed so
	// Create() can omit it entirely when unset), which also silently drops an
	// explicit empty string -- the exact value CM requires to clear a
	// previously-set resource set. Re-inject resource_set_id directly into the
	// marshaled payload so Update() can always send CM's clear instruction.
	if !plan.KeyRule.ResourceSetID.IsNull() && !plan.KeyRule.ResourceSetID.IsUnknown() {
		var payloadMap map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payloadMap); err != nil {
			resp.Diagnostics.AddError(
				"Invalid data input: CTE Policy Key Rule Update",
				err.Error(),
			)
			return
		}
		payloadMap["resource_set_id"] = plan.KeyRule.ResourceSetID.ValueString()
		payloadJSON, err = json.Marshal(payloadMap)
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid data input: CTE Policy Key Rule Update",
				err.Error(),
			)
			return
		}
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		plan.KeyRule.ID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/keyrules",
		payloadJSON,
	)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_keyrules.go -> Update][" + plan.KeyRule.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Key Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Key Rule, unexpected error: "+err.Error(),
		)
		return
	}
	var updatedRule KeyRuleJSON
	if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
		resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
		return
	}
	plan.KeyRule.ID = types.StringValue(updatedRule.ID)
	plan.KeyRule.OrderNumber = types.Int64Value(*updatedRule.OrderNumber)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicyKeyRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyAddKeyRuleTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	// output, err := r.client.DeleteByID(
	// 	ctx,
	// 	state.KeyRuleID.ValueString(),
	// 	common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/keyrules")
	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEClientPolicyID.ValueString(), "keyrules", state.KeyRule.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEClientPolicyID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_keyrules.go -> Delete][" + state.KeyRule.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if handleDeleteNotFound(err, "CTE Policy Key Rule "+state.KeyRule.ID.ValueString(), &resp.Diagnostics) {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy",
			"Could not delete CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicyKeyRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCTEPolicyKeyRule) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID format: "policy_id:rule_id"
	parts := strings.Split(req.ID, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Expected format: policy_id:rule_id",
		)
		return
	}

	policyID := parts[0]
	ruleID := parts[1]

	state := CTEPolicyAddKeyRuleTFSDK{
		CTEClientPolicyID: types.StringValue(policyID),
		KeyRule: KeyRuleTFSDK{
			ID: types.StringValue(ruleID),
		},
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}
