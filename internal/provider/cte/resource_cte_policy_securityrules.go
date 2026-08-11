package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &resourceCTEPolicySecurityRule{}
	_ resource.ResourceWithConfigure   = &resourceCTEPolicySecurityRule{}
	_ resource.ResourceWithImportState = &resourceCTEPolicySecurityRule{}
	_ resource.ResourceWithModifyPlan  = &resourceCTEPolicySecurityRule{}
)

func NewResourceCTEPolicySecurityRule() resource.Resource {
	return &resourceCTEPolicySecurityRule{}
}

type resourceCTEPolicySecurityRule struct {
	client *common.Client
}

func (r *resourceCTEPolicySecurityRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_security_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicySecurityRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Security Rule need to be added",
			},

			"rule": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Security Rule to be updated in the parent policy.",
				Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{
						Computed:    true,
						Description: "Identifier of the security rule.",
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
					"action": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("all_ops"),
						Description: "Actions applicable to the rule. Examples of actions are read, write, all_ops, and key_op. Separate multiple actions by commas.",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								regexp.MustCompile(`^(read|write|all_ops|key_op)(,(read|write|all_ops|key_op))*$`),
								"must be a comma-separated list of: read, write, all_ops, key_op",
							),
						},
					},
					"effect": schema.StringAttribute{
						Optional:    true,
						Description: "Effects applicable to the rule. Separate multiple effects by commas. The valid values are: permit, deny, audit, applykey",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								regexp.MustCompile(`^(permit|deny|audit|applykey)(,(permit|deny|audit|applykey))*$`),
								"must be a comma-separated list of: permit, deny, audit, applykey",
							),
						},
					},
					"exclude_process_set": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Process set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"exclude_resource_set": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Resource set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"exclude_user_set": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "User set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"partial_match": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Whether to allow partial match operations. By default, it is enabled. Supported for Standard, LDT and IDT policies.",
					},
					"process_set_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Description: "ID of the process set to link to the policy.",
					},
					"resource_set_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Description: "ID of the resource set to link to the policy. Supported for Standard, LDT and IDT policies.",
					},
					"user_set_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Description: "ID of the user set to link to the policy.",
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicySecurityRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_policy_securityrules.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CTEPolicyAddSecurityRuleTFSDK
	var payload SecurityRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.SecurityRule.Action.ValueString() != "" && plan.SecurityRule.Action.ValueString() != types.StringNull().ValueString() {
		payload.Action = string(plan.SecurityRule.Action.ValueString())
	}
	if plan.SecurityRule.Effect.ValueString() != "" && plan.SecurityRule.Effect.ValueString() != types.StringNull().ValueString() {
		payload.Effect = string(plan.SecurityRule.Effect.ValueString())
	}
	if plan.SecurityRule.ExcludeProcessSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeProcessSet = bool(plan.SecurityRule.ExcludeProcessSet.ValueBool())
	}
	if plan.SecurityRule.ExcludeUserSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeUserSet = bool(plan.SecurityRule.ExcludeUserSet.ValueBool())
	}
	if plan.SecurityRule.ExcludeResourceSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeResourceSet = bool(plan.SecurityRule.ExcludeResourceSet.ValueBool())
	}
	if plan.SecurityRule.PartialMatch.ValueBool() != types.BoolNull().ValueBool() {
		payload.PartialMatch = bool(plan.SecurityRule.PartialMatch.ValueBool())
	}
	if plan.SecurityRule.ProcessSetID.ValueString() != "" && plan.SecurityRule.ProcessSetID.ValueString() != types.StringNull().ValueString() {
		payload.ProcessSetID = string(plan.SecurityRule.ProcessSetID.ValueString())
	}
	if plan.SecurityRule.ResourceSetID.ValueString() != "" && plan.SecurityRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.SecurityRule.ResourceSetID.ValueString())
	}
	if plan.SecurityRule.UserSetID.ValueString() != "" && plan.SecurityRule.UserSetID.ValueString() != types.StringNull().ValueString() {
		payload.UserSetID = string(plan.SecurityRule.UserSetID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_securityrules.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Security Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/securityrules",
		payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_securityrules.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Security Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Security Rule, unexpected error: "+err.Error(),
		)
		return
	}
	var newRule SecurityRuleJSON
	if err := json.Unmarshal([]byte(response), &newRule); err != nil {
		resp.Diagnostics.AddError("Error parsing new security rule response", err.Error())
		return
	}
	plan.SecurityRule.ID = types.StringValue(newRule.ID)
	plan.SecurityRule.OrderNumber = types.Int64Value(*newRule.OrderNumber)

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_securityrules.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicySecurityRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEPolicyAddSecurityRuleTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(
		ctx,
		id,
		state.SecurityRule.ID.ValueString(),
		common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/securityrules",
	)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp SecurityRuleJSON
	if err = json.Unmarshal([]byte(response), &apiResp); err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_securityrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error parsing CTE Policy Security Rule response",
			err.Error(),
		)
		return
	}

	// Refresh all mutable rule fields
	state.SecurityRule = SecurityRuleTFSDK{
		OrderNumber:        types.Int64Value(*apiResp.OrderNumber),
		ID:                 types.StringValue(apiResp.ID),
		Action:             types.StringValue(apiResp.Action),
		Effect:             types.StringValue(apiResp.Effect),
		PartialMatch:       types.BoolValue(apiResp.PartialMatch),
		UserSetID:          types.StringValue(apiResp.UserSetID),
		ExcludeUserSet:     types.BoolValue(apiResp.ExcludeUserSet),
		ProcessSetID:       types.StringValue(apiResp.ProcessSetID),
		ExcludeProcessSet:  types.BoolValue(apiResp.ExcludeProcessSet),
		ResourceSetID:      types.StringValue(apiResp.ResourceSetID),
		ExcludeResourceSet: types.BoolValue(apiResp.ExcludeResourceSet),
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_securityrules.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)

}

// ModifyPlan normalizes rule.resource_set_id so state (always the CM-returned
// name form, per Read() above) and config (which may supply either a UUID or
// a name) can be compared consistently (TFIN-610). CM's GET for this
// endpoint always returns the resource set's name, and Read() has always
// unconditionally refreshed state from it, so config supplying a UUID showed
// a permanent, non-converging diff (~ resource_set_id = "<name>" ->
// "<UUID>") on every subsequent plan. If the planned value resolves to the
// same resource set as the current state, the plan is pinned to the
// existing state value (no diff); a genuine change is left untouched so it
// surfaces normally.
func (r *resourceCTEPolicySecurityRule) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.client == nil || req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var plan, state CTEPolicyAddSecurityRuleTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if resolved, ok := modifyPlanCTERuleResourceSetID(
		ctx,
		r.client,
		plan.SecurityRule.ResourceSetID.ValueString(),
		state.SecurityRule.ResourceSetID.ValueString(),
		!plan.SecurityRule.ResourceSetID.IsUnknown(),
	); ok {
		plan.SecurityRule.ResourceSetID = types.StringValue(resolved)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicySecurityRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEPolicyAddSecurityRuleTFSDK
	var payload SecurityRuleJSON

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

	if plan.SecurityRule.Action.ValueString() != "" && plan.SecurityRule.Action.ValueString() != types.StringNull().ValueString() {
		payload.Action = string(plan.SecurityRule.Action.ValueString())
	}
	if plan.SecurityRule.Effect.ValueString() != "" && plan.SecurityRule.Effect.ValueString() != types.StringNull().ValueString() {
		payload.Effect = string(plan.SecurityRule.Effect.ValueString())
	}
	if plan.SecurityRule.ExcludeProcessSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeProcessSet = bool(plan.SecurityRule.ExcludeProcessSet.ValueBool())
	}
	if plan.SecurityRule.ExcludeUserSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeUserSet = bool(plan.SecurityRule.ExcludeUserSet.ValueBool())
	}
	if plan.SecurityRule.ExcludeResourceSet.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExcludeResourceSet = bool(plan.SecurityRule.ExcludeResourceSet.ValueBool())
	}
	if plan.SecurityRule.PartialMatch.ValueBool() != types.BoolNull().ValueBool() {
		payload.PartialMatch = bool(plan.SecurityRule.PartialMatch.ValueBool())
	}
	if plan.SecurityRule.ProcessSetID.ValueString() != "" && plan.SecurityRule.ProcessSetID.ValueString() != types.StringNull().ValueString() {
		payload.ProcessSetID = string(plan.SecurityRule.ProcessSetID.ValueString())
	}
	if plan.SecurityRule.ResourceSetID.ValueString() != "" && plan.SecurityRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.SecurityRule.ResourceSetID.ValueString())
	}
	if plan.SecurityRule.UserSetID.ValueString() != "" && plan.SecurityRule.UserSetID.ValueString() != types.StringNull().ValueString() {
		payload.UserSetID = string(plan.SecurityRule.UserSetID.ValueString())
	}
	// TFIN-610: only send order_number when it is actually changing. order_number
	// now carries UseStateForUnknown (added above to counteract ModifyPlan's side
	// effect of marking unconfigured computed attributes unknown), so it is
	// "known" on every Update() call even when unchanged -- previously it would
	// often have been unknown/omitted here. Confirmed via live CM (on the
	// sibling data_tx_rule/key_rule endpoints): including an unchanged
	// order_number in the same PATCH as a resource_set_id clear
	// ("resource_set_id":"") causes CM to silently ignore the clear (a CM-side
	// quirk); omitting order_number when it isn't actually changing avoids
	// triggering that.
	if !plan.SecurityRule.OrderNumber.IsNull() && !plan.SecurityRule.OrderNumber.IsUnknown() &&
		plan.SecurityRule.OrderNumber.ValueInt64() != state.SecurityRule.OrderNumber.ValueInt64() {
		OrderNumber := plan.SecurityRule.OrderNumber.ValueInt64()
		payload.OrderNumber = &OrderNumber
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_securityrules.go -> Update][" + plan.SecurityRule.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Security Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		plan.SecurityRule.ID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/securityrules",
		payloadJSON,
	)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy_securityrules.go -> Update][" + plan.SecurityRule.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Security Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Security Rule, unexpected error: "+err.Error(),
		)
		return
	}
	var updatedRule SecurityRuleJSON
	if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
		resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
		return
	}
	plan.SecurityRule.ID = types.StringValue(updatedRule.ID)
	plan.SecurityRule.OrderNumber = types.Int64Value(*updatedRule.OrderNumber)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicySecurityRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyAddSecurityRuleTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEClientPolicyID.ValueString(), "securityrules", state.SecurityRule.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEClientPolicyID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy_securityrules.go -> Delete][" + state.SecurityRule.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if handleDeleteNotFound(err, "CTE Policy Security Rule "+state.SecurityRule.ID.ValueString(), &resp.Diagnostics) {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy Security Rule",
			"Could not delete CTE Policy Security Rule, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicySecurityRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCTEPolicySecurityRule) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

	state := CTEPolicyAddSecurityRuleTFSDK{
		CTEClientPolicyID: types.StringValue(policyID),
		SecurityRule: SecurityRuleTFSDK{
			ID: types.StringValue(ruleID),
		},
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}
