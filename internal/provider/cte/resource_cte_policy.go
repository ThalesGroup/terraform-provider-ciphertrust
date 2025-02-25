package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

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
	_ resource.Resource              = &resourceCTEPolicy{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicy{}
)

func NewResourceCTEPolicy() resource.Resource {
	return &resourceCTEPolicy{}
}

type resourceCTEPolicy struct {
	client *common.Client
}

func (r *resourceCTEPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the policy.",
			},
			"policy_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Standard", "LDT", "IDT", "Cloud_Object_Storage", "CSI"}...),
				},
				Description: "Type of the policy. Valid values are - Standard, LDT, IDT, Cloud_Object_Storage, CSI",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"data_transform_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Data transformation rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
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
			"idt_key_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "IDT rules to link with the policy.",
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
			"key_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Key rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
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
							Description: "ID of the resource set to link with the rule. Supported for Standard, LDT and IDT policies.",
						},
					},
				},
			},
			"ldt_key_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "LDT rules to link with the policy. Supported for LDT policies.",
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
			"metadata": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Restrict policy for modification",
				Attributes: map[string]schema.Attribute{
					"restrict_update": schema.BoolAttribute{
						Optional:    true,
						Description: "To restrict the policy for modification. If its value enabled means user not able to modify the guarded policy.",
					},
				},
			},
			"never_deny": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to always allow operations in the policy. By default, it is disabled, that is, operations are not allowed. Supported for Standard, LDT, and Cloud_Object_Storage policies. For Learn Mode activations, never_deny is set to true, by default.",
			},
			"security_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Security rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
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
			"signature_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Security rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"signature_set_id": schema.StringAttribute{
							Optional:    true,
							Description: "List of identifiers of signature sets. This identifier can be the Name, ID (a UUIDv4), URI, or slug of the signature set.",
						},
					},
				},
			},
			"force_restrict_update": schema.BoolAttribute{
				Optional:    true,
				Description: "To remove restriction of policy for modification.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEPolicyTFSDK
	var payload CTEPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Add Name to the payload
	payload.Name = common.TrimString(plan.Name.String())

	// Add Policy Type to the payload
	payload.PolicyType = common.TrimString(plan.PolicyType.String())

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}

	// Add never_deny to the payload if set
	if plan.NeverDeny.ValueBool() != types.BoolNull().ValueBool() {
		payload.NeverDeny = bool(plan.NeverDeny.ValueBool())
	}

	// Add Data Transformation Rules to the payload if set
	var txRules []DataTxRuleJSON
	for _, txRule := range plan.DataTransformRules {
		var txRuleJSON DataTxRuleJSON
		if txRule.KeyID.ValueString() != "" && txRule.KeyID.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.KeyID = string(txRule.KeyID.ValueString())
		}
		if txRule.KeyType.ValueString() != "" && txRule.KeyType.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.KeyType = string(txRule.KeyType.ValueString())
		}
		if txRule.ResourceSetID.ValueString() != "" && txRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.ResourceSetID = string(txRule.ResourceSetID.ValueString())
		}
		txRules = append(txRules, txRuleJSON)
	}
	payload.DataTransformRules = txRules

	// Add Data Transformation Rules to the payload if set
	var IDTKeyRules []IDTRuleJSON
	for _, IDTKeyRule := range plan.IDTKeyRules {
		var IDTKeyRuleJSON IDTRuleJSON
		if IDTKeyRule.CurrentKey.ValueString() != "" && IDTKeyRule.CurrentKey.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.CurrentKey = string(IDTKeyRule.CurrentKey.ValueString())
		}
		if IDTKeyRule.CurrentKeyType.ValueString() != "" && IDTKeyRule.CurrentKeyType.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.CurrentKeyType = string(IDTKeyRule.CurrentKeyType.ValueString())
		}
		if IDTKeyRule.TransformationKey.ValueString() != "" && IDTKeyRule.TransformationKey.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.TransformationKey = string(IDTKeyRule.TransformationKey.ValueString())
		}
		if IDTKeyRule.TransformationKeyType.ValueString() != "" && IDTKeyRule.TransformationKeyType.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.TransformationKeyType = string(IDTKeyRule.TransformationKeyType.ValueString())
		}
		IDTKeyRules = append(IDTKeyRules, IDTKeyRuleJSON)
	}
	payload.IDTKeyRules = IDTKeyRules

	// Add Key Rules to the payload if set
	var keyRules []KeyRuleJSON
	for _, keyRule := range plan.KeyRules {
		var keyRuleJSON KeyRuleJSON
		if keyRule.KeyID.ValueString() != "" && keyRule.KeyID.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.KeyID = string(keyRule.KeyID.ValueString())
		}
		if keyRule.KeyType.ValueString() != "" && keyRule.KeyType.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.KeyType = string(keyRule.KeyType.ValueString())
		}
		if keyRule.ResourceSetID.ValueString() != "" && keyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.ResourceSetID = string(keyRule.ResourceSetID.ValueString())
		}
		keyRules = append(keyRules, keyRuleJSON)
	}
	payload.KeyRules = keyRules

	var metadata CTEPolicyMetadataJSON
	if !reflect.DeepEqual((*CTEPolicyMetadataTFSDK)(nil), plan.Metadata) {
		tflog.Debug(ctx, "Metadata should not be empty at this point")
		if plan.Metadata.RestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
			metadata.RestrictUpdate = bool(plan.Metadata.RestrictUpdate.ValueBool())
		}
		payload.Metadata = metadata
	}

	// Add Key Rules to the payload if set
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
	payload.LDTKeyRules = ldtKeyRules

	// Add Security Rules to the payload if set
	var securityRules []SecurityRuleJSON
	for _, securityRule := range plan.SecurityRules {
		var securityRuleJSON SecurityRuleJSON
		if securityRule.Action.ValueString() != "" && securityRule.Action.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.Action = string(securityRule.Action.ValueString())
		}
		if securityRule.Effect.ValueString() != "" && securityRule.Effect.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.Effect = string(securityRule.Effect.ValueString())
		}
		if securityRule.ExcludeProcessSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeProcessSet = bool(securityRule.ExcludeProcessSet.ValueBool())
		}
		if securityRule.ExcludeUserSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeUserSet = bool(securityRule.ExcludeUserSet.ValueBool())
		}
		if securityRule.ExcludeResourceSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeResourceSet = bool(securityRule.ExcludeResourceSet.ValueBool())
		}
		if securityRule.PartialMatch.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.PartialMatch = bool(securityRule.PartialMatch.ValueBool())
		}
		if securityRule.ProcessSetID.ValueString() != "" && securityRule.ProcessSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.ProcessSetID = string(securityRule.ProcessSetID.ValueString())
		}
		if securityRule.ResourceSetID.ValueString() != "" && securityRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.ResourceSetID = string(securityRule.ResourceSetID.ValueString())
		}
		if securityRule.UserSetID.ValueString() != "" && securityRule.UserSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.UserSetID = string(securityRule.UserSetID.ValueString())
		}
		securityRules = append(securityRules, securityRuleJSON)
	}
	payload.SecurityRules = securityRules

	// Add Signature Rules to the payload if set
	var signatureRules []SignatureRuleJSON
	for _, signatureRule := range plan.SignatureRules {
		var signatureRuleJSON SignatureRuleJSON
		if signatureRule.SignatureSetID.ValueString() != "" && signatureRule.SignatureSetID.ValueString() != types.StringNull().ValueString() {
			signatureRuleJSON.SignatureSetID = string(signatureRule.SignatureSetID.ValueString())
		}
		signatureRules = append(signatureRules, signatureRuleJSON)
	}
	payload.SignatureRules = signatureRules

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CTE_POLICY, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEPolicyTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_POLICY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Policy on CipherTrust Manager: ",
			"Could not Policy id : ,"+state.ID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEPolicyTFSDK
	var payload CTEPolicyJSON

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

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}

	// Add never_deny to the payload if set
	if plan.NeverDeny.ValueBool() != types.BoolNull().ValueBool() {
		payload.NeverDeny = bool(plan.NeverDeny.ValueBool())
	}

	// Add never_deny to the payload if set
	if plan.ForceRestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
		payload.ForceRestrictUpdate = bool(plan.ForceRestrictUpdate.ValueBool())
	}

	var metadata CTEPolicyMetadataJSON
	if !reflect.DeepEqual((*CTEPolicyMetadataTFSDK)(nil), plan.Metadata) {
		tflog.Debug(ctx, "Metadata should not be empty at this point")
		if plan.Metadata.RestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
			metadata.RestrictUpdate = bool(plan.Metadata.RestrictUpdate.ValueBool())
		}
		payload.Metadata = metadata
	}
	payload.Metadata = metadata

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_CTE_POLICY, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy",
			"Could not delete CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
