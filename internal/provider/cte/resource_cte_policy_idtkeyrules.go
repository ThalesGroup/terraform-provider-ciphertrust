package cte

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEPolicyIDTKeyRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicyIDTKeyRule{}
)

func NewResourceCTEPolicyIDTKeyRule() resource.Resource {
	return &resourceCTEPolicyIDTKeyRule{}
}

type resourceCTEPolicyIDTKeyRule struct {
	client *common.Client
}

func (r *resourceCTEPolicyIDTKeyRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_idt_key_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicyIDTKeyRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which IDT Key Rule need to be added",
			},
			"rule_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the IDT Key Rule created in the parent policy",
			},
			"rule": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"current_key": schema.StringAttribute{
							Optional:    true,
							Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
						},
						"current_key_type": schema.StringAttribute{
							Optional:    true,
							Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
						},
						"transformation_key": schema.StringAttribute{
							Optional:    true,
							Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id.",
						},
						"transformation_key_type": schema.StringAttribute{
							Optional:    true,
							Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicyIDTKeyRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicyIDTKeyRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicyIDTKeyRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan UpdateIDTKeyRulePolicyTFSDK
	var payload IDTRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.IDTKeyRule.CurrentKey.ValueString() != "" && plan.IDTKeyRule.CurrentKey.ValueString() != types.StringNull().ValueString() {
		payload.CurrentKey = string(plan.IDTKeyRule.CurrentKey.ValueString())
	}
	if plan.IDTKeyRule.CurrentKeyType.ValueString() != "" && plan.IDTKeyRule.CurrentKeyType.ValueString() != types.StringNull().ValueString() {
		payload.CurrentKeyType = string(plan.IDTKeyRule.CurrentKeyType.ValueString())
	}
	if plan.IDTKeyRule.TransformationKey.ValueString() != "" && plan.IDTKeyRule.TransformationKey.ValueString() != types.StringNull().ValueString() {
		payload.TransformationKey = string(plan.IDTKeyRule.TransformationKey.ValueString())
	}
	if plan.IDTKeyRule.TransformationKeyType.ValueString() != "" && plan.IDTKeyRule.TransformationKeyType.ValueString() != types.StringNull().ValueString() {
		payload.TransformationKeyType = string(plan.IDTKeyRule.TransformationKeyType.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_idtkeyrules.go -> Update]["+plan.IDTKeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy IDT Key Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.IDTKeyRuleID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/idtkeyrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_idtkeyrules.go -> Update]["+plan.IDTKeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy IDT Key Rule on CipherTrust Manager: ",
			"Could not update CTE Policy IDT Key Rule, unexpected error: "+err.Error(),
		)
		return
	}
	plan.IDTKeyRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicyIDTKeyRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *resourceCTEPolicyIDTKeyRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
