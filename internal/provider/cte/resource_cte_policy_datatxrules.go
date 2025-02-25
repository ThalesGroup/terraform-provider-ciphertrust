package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEPolicyDataTXRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicyDataTXRule{}
)

func NewResourceCTEPolicyDataTXRule() resource.Resource {
	return &resourceCTEPolicyDataTXRule{}
}

type resourceCTEPolicyDataTXRule struct {
	client *common.Client
}

func (r *resourceCTEPolicyDataTXRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_data_tx_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicyDataTXRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Data TX Rule need to be added",
			},
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the Data TX Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"order_number": schema.Int64Attribute{
				Optional:    true,
				Description: "Precedence order of the rule in the parent policy.",
			},
			"rule": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"key_id": schema.StringAttribute{
						Optional:    true,
						Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
					},
					"key_type": schema.StringAttribute{
						Optional:    true,
						Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
					},
					"resource_set_id": schema.StringAttribute{
						Optional:    true,
						Description: "ID of the resource set linked with the rule.",
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicyDataTXRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_policy_datatxrules.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan AddDataTXRulePolicyTFSDK
	var payload DataTxRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.DataTXRule.KeyID.ValueString() != "" && plan.DataTXRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.DataTXRule.KeyID.ValueString())
	}
	if plan.DataTXRule.KeyType.ValueString() != "" && plan.DataTXRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.DataTXRule.KeyType.ValueString())
	}
	if plan.DataTXRule.ResourceSetID.ValueString() != "" && plan.DataTXRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.DataTXRule.ResourceSetID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_datatxrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Data TX Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/datatxrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_datatxrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Data TX Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Data TX Rule, unexpected error: "+err.Error(),
		)
		return
	}

	plan.DataTXRuleID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_datatxrules.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicyDataTXRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AddDataTXRulePolicyTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.DataTXRuleID.ValueString(), common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/datatxrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_dataxrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Datax Key Rule on CipherTrust Manager: ",
			"Could not read Datax Key Rule id : ,"+state.DataTXRuleID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_dataxrules.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicyDataTXRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AddDataTXRulePolicyTFSDK
	var payload DataTxRuleUpdateJSON

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

	if plan.DataTXRule.KeyID.ValueString() != "" && plan.DataTXRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.DataTXRule.KeyID.ValueString())
	}
	if plan.DataTXRule.KeyType.ValueString() != "" && plan.DataTXRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.DataTXRule.KeyType.ValueString())
	}
	if plan.DataTXRule.ResourceSetID.ValueString() != "" && plan.DataTXRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.DataTXRule.ResourceSetID.ValueString())
	}
	if plan.OrderNumber.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.OrderNumber = int64(plan.OrderNumber.ValueInt64())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_datatxrules.go -> Update]["+plan.DataTXRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Data TX Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		state.DataTXRuleID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/datatxrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_datatxrules.go -> Update]["+plan.DataTXRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Data TX Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Data TX Rule, unexpected error: "+err.Error()+"\n"+string(payloadJSON),
		)
		return
	}
	plan.DataTXRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicyDataTXRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AddDataTXRulePolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEClientPolicyID.ValueString(), "datatxrules", state.DataTXRuleID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEClientPolicyID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_datatxrules.go -> Delete]["+state.DataTXRuleID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy",
			"Could not delete CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicyDataTXRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
