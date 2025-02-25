package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEPolicySecurityRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicySecurityRule{}
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
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the Security Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"order_number": schema.Int64Attribute{
				Optional:    true,
				Description: "Precedence order of the rule in the parent policy.",
			},
			"rule": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Security Rule to be updated in the parent policy.",
				Attributes: map[string]schema.Attribute{
					"action": schema.StringAttribute{
						Optional:    true,
						Description: "Actions applicable to the rule. Examples of actions are read, write, all_ops, and key_op.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"read", "write", "all_ops", "key_op"}...),
						},
					},
					"effect": schema.StringAttribute{
						Optional:    true,
						Description: "Effects applicable to the rule. Separate multiple effects by commas. The valid values are: permit, deny, audit, applykey",
					},
					"exclude_process_set": schema.BoolAttribute{
						Optional:    true,
						Description: "Process set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"exclude_resource_set": schema.BoolAttribute{
						Optional:    true,
						Description: "Resource set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"exclude_user_set": schema.BoolAttribute{
						Optional:    true,
						Description: "User set to exclude. Supported for Standard, LDT and IDT policies.",
					},
					"partial_match": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to allow partial match operations. By default, it is enabled. Supported for Standard, LDT and IDT policies.",
					},
					"process_set_id": schema.StringAttribute{
						Optional:    true,
						Description: "ID of the process set to link to the policy.",
					},
					"resource_set_id": schema.StringAttribute{
						Optional:    true,
						Description: "ID of the resource set to link to the policy. Supported for Standard, LDT and IDT policies.",
					},
					"user_set_id": schema.StringAttribute{
						Optional:    true,
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_policy_securityrules.go -> Create]["+id+"]")

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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_securityrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Security Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/securityrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_securityrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Security Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Security Rule, unexpected error: "+err.Error(),
		)
		return
	}

	plan.SecurityRuleID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_securityrules.go -> Create]["+id+"]")
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
	_, err := r.client.GetById(ctx, id, state.SecurityRuleID.ValueString(), common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/securityrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_securityrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Security Key Rule on CipherTrust Manager: ",
			"Could not read Security Key Rule id : ,"+state.SecurityRuleID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_securityrules.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicySecurityRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEPolicyAddSecurityRuleTFSDK
	var payload SecurityRuleUpdateJSON

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
	if plan.OrderNumber.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.OrderNumber = int64(plan.OrderNumber.ValueInt64())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_securityrules.go -> Update]["+plan.SecurityRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Security Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.SecurityRuleID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/securityrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_securityrules.go -> Update]["+plan.SecurityRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Security Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Security Rule, unexpected error: "+err.Error(),
		)
		return
	}
	plan.SecurityRuleID = types.StringValue(response)
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
	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEClientPolicyID.ValueString(), "securityrules", state.SecurityRuleID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEClientPolicyID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_securityrules.go -> Delete]["+state.SecurityRuleID.ValueString()+"]["+output+"]")
	if err != nil {
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
