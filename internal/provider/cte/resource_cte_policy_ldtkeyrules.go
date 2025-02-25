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
	_ resource.Resource              = &resourceCTEPolicyLDTKeyRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicyLDTKeyRule{}
)

func NewResourceCTEPolicyLDTKeyRule() resource.Resource {
	return &resourceCTEPolicyLDTKeyRule{}
}

type resourceCTEPolicyLDTKeyRule struct {
	client *common.Client
}

func (r *resourceCTEPolicyLDTKeyRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_ldtkey_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicyLDTKeyRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which LDT Key Rule need to be added",
			},
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the LDT Key Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"order_number": schema.Int64Attribute{
				Optional:    true,
				Description: "Precedence order of the rule in the parent policy.",
			},
			"rule": schema.ListNestedAttribute{
				Optional:    true,
				Description: "LDT Key rule to be updated in the parent policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"is_exclusion_rule": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether this is an exclusion rule. If enabled, no need to specify the transformation rule.",
						},
						"resource_set_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of the resource set to link with the rule.",
						},
						"current_key": schema.SingleNestedAttribute{
							Optional:    true,
							Description: "Properties of the current key.",
							Attributes: map[string]schema.Attribute{
								"key_id": schema.StringAttribute{
									Optional:    true,
									Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
								},
								"key_type": schema.StringAttribute{
									Optional:    true,
									Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
								},
							},
						},
						"transformation_key": schema.SingleNestedAttribute{
							Optional:    true,
							Description: "Properties of the transformation key.",
							Attributes: map[string]schema.Attribute{
								"key_id": schema.StringAttribute{
									Optional:    true,
									Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
								},
								"key_type": schema.StringAttribute{
									Optional:    true,
									Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicyLDTKeyRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_policy_ldtkeyrules.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEPolicyAddLDTKeyRuleTFSDK

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ldtKeyRules []LDTRuleJSON
	for _, ldtKeyRule := range plan.LDTKeyRules {
		var ldtKeyRuleJSON LDTRuleJSON
		var ldtKeyRuleCurrentKey CurrentKeyJSON
		var ldtKeyRuleTransformationKey TransformationKeyJSON
		if ldtKeyRule.ResourceSetID.ValueString() != "" && ldtKeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleJSON.ResourceSetID = string(ldtKeyRule.ResourceSetID.ValueString())
		}
		if ldtKeyRule.IsExclusionRule.ValueBool() != types.BoolNull().ValueBool() {
			ldtKeyRuleJSON.IsExclusionRule = bool(ldtKeyRule.IsExclusionRule.ValueBool())
		}
		if ldtKeyRule.CurrentKey.KeyID.ValueString() != "" && ldtKeyRule.CurrentKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyID = string(ldtKeyRule.CurrentKey.KeyID.ValueString())
		}
		if ldtKeyRule.CurrentKey.KeyType.ValueString() != "" && ldtKeyRule.CurrentKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyType = string(ldtKeyRule.CurrentKey.KeyType.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyID.ValueString() != "" && ldtKeyRule.TransformationKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyID = string(ldtKeyRule.TransformationKey.KeyID.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyType.ValueString() != "" && ldtKeyRule.TransformationKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyType = string(ldtKeyRule.TransformationKey.KeyType.ValueString())
		}
		ldtKeyRuleJSON.CurrentKey = ldtKeyRuleCurrentKey
		ldtKeyRuleJSON.TransformationKey = ldtKeyRuleTransformationKey
		ldtKeyRules = append(ldtKeyRules, ldtKeyRuleJSON)
	}

	payloadJSON, err := json.Marshal(ldtKeyRules[0])
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_ldtkeyrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy LDT Key Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/ldtkeyrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_ldtkeyrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy LDT Key Rule on CipherTrust Manager: ",
			"Could not create CTE Policy LDT Key Rule, unexpected error: "+err.Error(),
		)
		return
	}

	plan.LDTKeyRuleID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_ldtkeyrules.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicyLDTKeyRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEPolicyAddLDTKeyRuleTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.LDTKeyRuleID.ValueString(), common.URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/ldtkeyrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_ldtkeyyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading LDT Key Rule on CipherTrust Manager: ",
			"Could not read LDT Key Rule id : ,"+state.LDTKeyRuleID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_ldtkeyrules.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicyLDTKeyRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEPolicyAddLDTKeyRuleTFSDK

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

	var ldtKeyRules []LDTRuleUpdateJSON
	for _, ldtKeyRule := range plan.LDTKeyRules {
		var ldtKeyRuleJSON LDTRuleUpdateJSON
		var ldtKeyRuleCurrentKey CurrentKeyJSON
		var ldtKeyRuleTransformationKey TransformationKeyJSON
		if ldtKeyRule.ResourceSetID.ValueString() != state.LDTKeyRules[0].ResourceSetID.ValueString() && ldtKeyRule.ResourceSetID.ValueString() != "" && ldtKeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleJSON.ResourceSetID = string(ldtKeyRule.ResourceSetID.ValueString())
		}
		if ldtKeyRule.IsExclusionRule.ValueBool() != types.BoolNull().ValueBool() {
			ldtKeyRuleJSON.IsExclusionRule = bool(ldtKeyRule.IsExclusionRule.ValueBool())
		}
		if ldtKeyRule.CurrentKey.KeyID.ValueString() != "" && ldtKeyRule.CurrentKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyID = string(ldtKeyRule.CurrentKey.KeyID.ValueString())
		}
		if ldtKeyRule.CurrentKey.KeyType.ValueString() != "" && ldtKeyRule.CurrentKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyType = string(ldtKeyRule.CurrentKey.KeyType.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyID.ValueString() != "" && ldtKeyRule.TransformationKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyID = string(ldtKeyRule.TransformationKey.KeyID.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyType.ValueString() != "" && ldtKeyRule.TransformationKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyType = string(ldtKeyRule.TransformationKey.KeyType.ValueString())
		}
		ldtKeyRuleJSON.CurrentKey = ldtKeyRuleCurrentKey
		ldtKeyRuleJSON.TransformationKey = ldtKeyRuleTransformationKey
		ldtKeyRules = append(ldtKeyRules, ldtKeyRuleJSON)
	}

	payloadJSON, err := json.Marshal(ldtKeyRules[0])
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_ldtkeyrules.go -> Update]["+plan.LDTKeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy LDT Key Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.LDTKeyRuleID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/ldtkeyrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_ldtkeyrules.go -> Update]["+plan.LDTKeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy LDT Key Rule on CipherTrust Manager: ",
			"Could not update CTE Policy LDT Key Rule, unexpected error: "+err.Error()+string(payloadJSON),
		)
		return
	}
	plan.LDTKeyRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicyLDTKeyRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyAddLDTKeyRuleTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEClientPolicyID.ValueString(), "ldtkeyrules", state.LDTKeyRuleID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEClientPolicyID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_ldtkeyrules.go -> Delete]["+state.LDTKeyRuleID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy LDT Key Rule",
			"Could not delete CTE Policy LDT Key Rule, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicyLDTKeyRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
