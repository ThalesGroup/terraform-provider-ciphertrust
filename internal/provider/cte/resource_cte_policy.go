package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCTEPolicy{}
	_ resource.ResourceWithConfigure      = &resourceCTEPolicy{}
	_ resource.ResourceWithImportState    = &resourceCTEPolicy{}
	_ resource.ResourceWithValidateConfig = &resourceCTEPolicy{}
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
				Description: "(Immutable) Name of the policy.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the policy.",
				Computed:    true,
				// TFIN-583: no Default here -- the framework never marks a
				// Default-bearing attribute unknown (see
				// MarkComputedNilsAsUnknown), which made UseStateForUnknown()
				// a no-op and let every unrelated update silently reset an
				// omitted description back to "". UseStateForUnknown() keeps
				// the last known value stable instead; Create() below
				// resolves the initial unknown to the real API value.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"policy_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Standard", "LDT", "IDT", "Cloud_Object_Storage", "CSI"}...),
				},
				Description: "(Immutable) Type of the policy. Valid values are - Standard, LDT, IDT, Cloud_Object_Storage, CSI.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"data_transform_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Data transformation rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the data transform rule.",
							PlanModifiers: []planmodifier.String{
								// TFIN-641: UseStateForUnknown() unconditionally
								// copies the prior state value once triggered.
								// For a newly-added list entry with no prior
								// state, that value is concrete null (not
								// absent), which forces the planned value to
								// null instead of leaving it unknown --
								// Terraform then rejects the apply once the
								// real id comes back from CM ("provider
								// produced inconsistent result after apply").
								// UseNonNullStateForUnknown() only copies the
								// prior value when it is non-null, so a
								// brand-new entry correctly stays unknown.
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"order_number": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Description: "Precedence order of the rule in the policy.",
							// TFIN-583: without this, order_number is
							// marked (known after apply) on every plan that
							// touches the resource, even when it hasn't
							// changed.
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
							// TFIN-583: no Default -- see the top-level
							// description attribute for why Default and
							// UseStateForUnknown() don't mix (Default
							// pre-empts the unknown-marking the plan
							// modifier relies on). Create() below resolves
							// the initial unknown to the real API value.
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
							Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
						},
						"resource_set_id": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
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
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for key rule",
							PlanModifiers: []planmodifier.String{
								// TFIN-641: see data_transform_rules.id above --
								// same UseNonNullStateForUnknown() fix so a
								// newly-added idt_key_rules entry's id stays
								// unknown instead of being forced to null.
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
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
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the key rule.",
							PlanModifiers: []planmodifier.String{
								// TFIN-641: see data_transform_rules.id above --
								// same UseNonNullStateForUnknown() fix so a
								// newly-added key_rules entry's id stays
								// unknown instead of being forced to null.
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"order_number": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Description: "Precedence order of the rule in the policy.",
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
			"ldt_key_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "LDT rules to link with the policy. Supported for LDT policies.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the LDT key rule.",
							PlanModifiers: []planmodifier.String{
								// TFIN-641: see data_transform_rules.id above --
								// same UseNonNullStateForUnknown() fix so a
								// newly-added ldt_key_rules entry's id stays
								// unknown instead of being forced to null.
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"order_number": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Description: "Precedence order of the rule in the policy.",
						},
						"is_exclusion_rule": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(false),
							Description: "Whether this is an exclusion rule. If enabled, no need to specify the transformation rule.",
						},
						"resource_set_id": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
							Description: "ID of the resource set to link with the rule.",
						},
						"current_key": schema.SingleNestedAttribute{
							Required:    true,
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
				Computed:    true,
				Description: "Restrict policy for modification",
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"restrict_update": types.BoolType,
						},
						map[string]attr.Value{
							"restrict_update": types.BoolValue(false),
						},
					),
				),
				Attributes: map[string]schema.Attribute{
					"restrict_update": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "To restrict the policy for modification.",
					},
				},
			},
			"never_deny": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether to always allow operations in the policy. By default, it is disabled, that is, operations are not allowed. Supported for Standard, LDT, and Cloud_Object_Storage policies. For Learn Mode activations, never_deny is set to true, by default.",
			},
			"security_rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Security rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the security rule.",
							PlanModifiers: []planmodifier.String{
								// TFIN-641: UseStateForUnknown() unconditionally
								// copies the prior state value once triggered.
								// For a newly-added security_rules entry with no
								// prior state, that value is concrete null (not
								// absent), which forces the planned value to
								// null instead of leaving it unknown --
								// Terraform then rejects the apply once the
								// real id comes back from CM ("provider
								// produced inconsistent result after apply").
								// UseNonNullStateForUnknown() only copies the
								// prior value when it is non-null, so a
								// brand-new entry correctly stays unknown.
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"order_number": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Description: "Precedence order of the rule in the policy.",
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
			"signature_rules": schema.ListNestedAttribute{
				Optional: true,

				Description: "Security rules to link with the policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the signature rule.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"signature_set_id": schema.StringAttribute{
							Required:    true,
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

// ValidateConfig rejects config combinations that CipherTrust Manager would
// silently mutate server-side, which would otherwise cause a permanent
// terraform plan/apply loop (TFIN-496).
func (r *resourceCTEPolicy) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config CTEPolicyTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// never_deny defaults to false when omitted from config, and CM strips
	// "applykey" from every security_rules.effect in that case.
	if config.NeverDeny.ValueBool() || config.NeverDeny.IsUnknown() {
		return
	}

	for i, rule := range config.SecurityRules {
		if rule.Effect.IsNull() || rule.Effect.IsUnknown() {
			continue
		}
		for _, effect := range strings.Split(rule.Effect.ValueString(), ",") {
			if strings.TrimSpace(effect) == "applykey" {
				resp.Diagnostics.AddAttributeError(
					path.Root("security_rules").AtListIndex(i).AtName("effect"),
					"Invalid security_rules.effect with never_deny = false",
					fmt.Sprintf(
						"CipherTrust Manager strips \"applykey\" from a security rule's effect when the policy's never_deny is false (the default), which causes terraform to perpetually plan and revert this change. Either set never_deny = true or remove \"applykey\" from effect (%q) for this rule.",
						rule.Effect.ValueString(),
					),
				)
				break
			}
		}
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_policy.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CTEPolicyTFSDK
	var payload CTEPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Add Name to the payload
	payload.Name = common.TrimString(plan.Name.ValueString())

	// Add Policy Type to the payload
	payload.PolicyType = common.TrimString(plan.PolicyType.ValueString())

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
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
		r.client.Log.Debug("Metadata should not be empty at this point")
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
		if ldtKeyRule.CurrentKey != nil {
			if ldtKeyRule.CurrentKey.KeyID.ValueString() != "" && ldtKeyRule.CurrentKey.KeyID.ValueString() != types.StringNull().ValueString() {
				ldtKeyRuleCurrentKey.KeyID = string(ldtKeyRule.CurrentKey.KeyID.ValueString())
			}
			if ldtKeyRule.CurrentKey.KeyType.ValueString() != "" && ldtKeyRule.CurrentKey.KeyType.ValueString() != types.StringNull().ValueString() {
				ldtKeyRuleCurrentKey.KeyType = string(ldtKeyRule.CurrentKey.KeyType.ValueString())
			}
			ldtKeyRuleJSON.CurrentKey = ldtKeyRuleCurrentKey
		}
		if ldtKeyRule.TransformationKey != nil {
			if ldtKeyRule.TransformationKey.KeyID.ValueString() != "" && ldtKeyRule.TransformationKey.KeyID.ValueString() != types.StringNull().ValueString() {
				ldtKeyRuleTransformationKey.KeyID = string(ldtKeyRule.TransformationKey.KeyID.ValueString())
			}
			if ldtKeyRule.TransformationKey.KeyType.ValueString() != "" && ldtKeyRule.TransformationKey.KeyType.ValueString() != types.StringNull().ValueString() {
				ldtKeyRuleTransformationKey.KeyType = string(ldtKeyRule.TransformationKey.KeyType.ValueString())
			}
			ldtKeyRuleJSON.TransformationKey = &ldtKeyRuleTransformationKey
		}
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_POLICY, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}

	var apiResp CTEPolicyJSON
	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing API response", err.Error())
		return
	}

	// Policy ID from top level
	plan.ID = types.StringValue(apiResp.ID)

	// TFIN-583: description no longer has a schema Default, so when config
	// omits it, plan.Description is unknown at this point -- resolve it to
	// the real API value before State.Set (mirrors the order_number/ID
	// handling for the rule blocks below).
	plan.Description = types.StringValue(apiResp.Description)

	//Security Rule ID fetched from response
	if len(apiResp.SecurityRules) > 0 {
		// For LDT policy, first security rule is always a default rule — skip it
		securityRules := apiResp.SecurityRules
		if plan.PolicyType.ValueString() == "LDT" {
			securityRules = apiResp.SecurityRules[1:]
		}
		for i, rule := range securityRules {
			plan.SecurityRules[i].ID = types.StringValue(rule.ID)
			plan.SecurityRules[i].OrderNumber = types.Int64Value(*rule.OrderNumber)
		}
	}

	//Key Rule ID fetched from response
	if len(apiResp.KeyRules) > 0 {
		for i, rule := range apiResp.KeyRules {
			plan.KeyRules[i].ID = types.StringValue(rule.ID)
			plan.KeyRules[i].OrderNumber = types.Int64Value(*rule.OrderNumber)
		}
	}

	//Data transformation key rule ID fetched form response
	if len(apiResp.DataTransformRules) > 0 {
		for i, rule := range apiResp.DataTransformRules {
			plan.DataTransformRules[i].ID = types.StringValue(rule.ID)
			plan.DataTransformRules[i].OrderNumber = types.Int64Value(*rule.OrderNumber)
			// TFIN-583: key_type no longer has a schema Default, so resolve
			// the initial unknown to the real API value here too.
			plan.DataTransformRules[i].KeyType = types.StringValue(rule.KeyType)
		}
	}

	// IDT Key Rule ID fetched from response
	if len(apiResp.IDTKeyRules) > 0 {
		rule := apiResp.IDTKeyRules[0]
		plan.IDTKeyRules[0].ID = types.StringValue(rule.ID)
	}

	//LDT Key rule ID fetched from response
	if len(apiResp.LDTKeyRules) > 0 {
		for i, rule := range apiResp.LDTKeyRules {
			plan.LDTKeyRules[i].ID = types.StringValue(rule.ID)
			plan.LDTKeyRules[i].OrderNumber = types.Int64Value(*rule.OrderNumber)
		}
	}

	//Signature rule id fetched from response
	if len(apiResp.SignatureRules) > 0 {
		for i, rule := range apiResp.SignatureRules {
			plan.SignatureRules[i].ID = types.StringValue(rule.ID)
		}
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy.go -> Create][" + id + "]")
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

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_POLICY)
	if handleReadNotFound(ctx, err, "CTE Policy ("+state.ID.ValueString()+")", &resp.Diagnostics) {
		return
	}

	var apiResp CTEPolicyListJSON
	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error parsing CTE Policy response",
			err.Error(),
		)
		return
	}

	// Mutable fields — these can drift and need to be refreshed
	state.Description = types.StringValue(apiResp.Description)
	state.NeverDeny = types.BoolValue(apiResp.NeverDeny)
	state.Name = types.StringValue(apiResp.Name)
	policyTypeMap := map[string]string{
		"STANDARD":             "Standard",
		"LDT":                  "LDT",
		"IDT":                  "IDT",
		"CLOUD_OBJECT_STORAGE": "Cloud_Object_Storage",
		"CSI":                  "CSI",
	}
	if normalized, ok := policyTypeMap[strings.ToUpper(apiResp.PolicyType)]; ok {
		state.PolicyType = types.StringValue(normalized)
	} else {
		state.PolicyType = types.StringValue(apiResp.PolicyType)
	}

	// Metadata is a pointer in TFSDK; only set if the API returned it populated
	state.Metadata = &CTEPolicyMetadataTFSDK{
		RestrictUpdate: types.BoolValue(apiResp.Metadata.RestrictUpdate),
	}
	//updating Security rules
	var refreshedRules []SecurityRuleTFSDK
	for _, rule := range state.SecurityRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/securityrules", common.URL_CTE_POLICY, state.ID.ValueString())

		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy Security Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			// TFIN-623: this previously silently dropped the missing nested
			// rule (`continue`, debug log only). Aborting the whole Read()
			// here instead -- state has not yet been persisted via
			// resp.State.Set, so returning immediately leaves the resource's
			// prior state untouched (kept) rather than partially refreshed.
			return
		}

		var apiRule SecurityRuleJSON
		err = json.Unmarshal([]byte(response), &apiRule)
		if err != nil {
			resp.Diagnostics.AddError("Error parsing security rule response", err.Error())
			return
		}

		refreshedRules = append(refreshedRules, SecurityRuleTFSDK{
			ID:                 types.StringValue(apiRule.ID),
			OrderNumber:        types.Int64Value(*apiRule.OrderNumber),
			Action:             types.StringValue(apiRule.Action),
			Effect:             types.StringValue(apiRule.Effect),
			ExcludeProcessSet:  types.BoolValue(apiRule.ExcludeProcessSet),
			ExcludeResourceSet: types.BoolValue(apiRule.ExcludeResourceSet),
			ExcludeUserSet:     types.BoolValue(apiRule.ExcludeUserSet),
			PartialMatch:       types.BoolValue(apiRule.PartialMatch),
			ProcessSetID:       types.StringValue(apiRule.ProcessSetID),
			ResourceSetID:      types.StringValue(apiRule.ResourceSetID),
			UserSetID:          types.StringValue(apiRule.UserSetID),
		})
	}
	state.SecurityRules = refreshedRules

	//updating key rules
	var refreshedKeyRules []KeyRuleTFSDK
	for _, rule := range state.KeyRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/keyrules", common.URL_CTE_POLICY, state.ID.ValueString())
		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy Key Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			return
		}
		var apiRule KeyRuleJSON
		if err := json.Unmarshal([]byte(response), &apiRule); err != nil {
			resp.Diagnostics.AddError("Error parsing key rule response", err.Error())
			return
		}
		refreshedKeyRules = append(refreshedKeyRules, KeyRuleTFSDK{
			OrderNumber:   types.Int64Value(*apiRule.OrderNumber),
			ID:            types.StringValue(apiRule.ID),
			KeyID:         types.StringValue(apiRule.KeyID),
			KeyType:       types.StringValue(apiRule.KeyType),
			ResourceSetID: types.StringValue(apiRule.ResourceSetID),
		})
	}
	state.KeyRules = refreshedKeyRules

	//updating data transformation key rules
	var refreshedDataTxRules []DataTransformationRuleTFSDK
	for _, rule := range state.DataTransformRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/datatxrules", common.URL_CTE_POLICY, state.ID.ValueString())
		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy Data Transformation Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			return
		}
		var apiRule DataTxRuleJSON
		if err := json.Unmarshal([]byte(response), &apiRule); err != nil {
			resp.Diagnostics.AddError("Error parsing data transform rule response", err.Error())
			return
		}
		refreshedDataTxRules = append(refreshedDataTxRules, DataTransformationRuleTFSDK{
			OrderNumber:   types.Int64Value(*apiRule.OrderNumber),
			ID:            types.StringValue(apiRule.ID),
			KeyID:         types.StringValue(apiRule.KeyID),
			KeyType:       types.StringValue(apiRule.KeyType),
			ResourceSetID: types.StringValue(apiRule.ResourceSetID),
		})
	}
	state.DataTransformRules = refreshedDataTxRules

	//updating idt_key rule
	var refreshedIDTKeyRules []IDTKeyRuleTFSDK
	for _, rule := range state.IDTKeyRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/idtkeyrules", common.URL_CTE_POLICY, state.ID.ValueString())
		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy IDT Key Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			return
		}
		var apiRule IDTRuleJSON
		if err := json.Unmarshal([]byte(response), &apiRule); err != nil {
			resp.Diagnostics.AddError("Error parsing IDT key rule response", err.Error())
			return
		}
		// TFIN-604: CM's GET .../idtkeyrules/{id} never returns
		// current_key_type/transformation_key_type today, so these were
		// unconditionally hard-coded from prior state, making any
		// out-of-band change to them permanently undetectable. Prefer the
		// API response's value when CM actually supplies one (future-proofs
		// against CM eventually returning it), falling back to the prior
		// state value only when the API response genuinely omits/empties
		// the field -- a no-op today since CM never returns these fields.
		currentKeyType := rule.CurrentKeyType
		if apiRule.CurrentKeyType != "" {
			currentKeyType = types.StringValue(apiRule.CurrentKeyType)
		}
		transformationKeyType := rule.TransformationKeyType
		if apiRule.TransformationKeyType != "" {
			transformationKeyType = types.StringValue(apiRule.TransformationKeyType)
		}
		refreshedIDTKeyRules = append(refreshedIDTKeyRules, IDTKeyRuleTFSDK{
			ID:                    types.StringValue(apiRule.ID),
			CurrentKey:            types.StringValue(apiRule.CurrentKey),
			CurrentKeyType:        currentKeyType,
			TransformationKey:     types.StringValue(apiRule.TransformationKey),
			TransformationKeyType: transformationKeyType,
		})
	}
	state.IDTKeyRules = refreshedIDTKeyRules

	// updating ldt key rules
	var refreshedLDTKeyRules []LDTKeyRuleTFSDK
	for _, rule := range state.LDTKeyRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/ldtkeyrules", common.URL_CTE_POLICY, state.ID.ValueString())
		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy LDT Key Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			return
		}
		var apiRule LDTRuleJSON
		if err := json.Unmarshal([]byte(response), &apiRule); err != nil {
			resp.Diagnostics.AddError("Error parsing LDT key rule response", err.Error())
			return
		}

		// Build current key — key_type not returned by API, keep from state
		var currentKey *CurrentKeyTFSDK
		if rule.CurrentKey != nil {
			currentKey = &CurrentKeyTFSDK{
				KeyID:   types.StringValue(apiRule.CurrentKey.KeyID),
				KeyType: rule.CurrentKey.KeyType, // keep from state
			}
		}

		// Build transformation key — key_type not returned by API, keep from state
		var transformationKey *TransformationKeyTFSDK
		transformationKey = &TransformationKeyTFSDK{
			KeyID: types.StringValue(apiRule.TransformationKey.KeyID),
			KeyType: func() types.String {
				if rule.TransformationKey != nil {
					return rule.TransformationKey.KeyType // keep from state if exists
				}
				return types.StringValue("") // default to empty if not in state
			}(),
		}

		refreshedLDTKeyRules = append(refreshedLDTKeyRules, LDTKeyRuleTFSDK{
			ID:                types.StringValue(apiRule.ID),
			OrderNumber:       types.Int64Value(*apiRule.OrderNumber),
			IsExclusionRule:   types.BoolValue(apiRule.IsExclusionRule),
			ResourceSetID:     types.StringValue(apiRule.ResourceSetID),
			CurrentKey:        currentKey,
			TransformationKey: transformationKey,
		})
	}
	state.LDTKeyRules = refreshedLDTKeyRules

	//updating signature rules
	var refreshedSignatureRules []SignatureRuleTFSDK
	for _, rule := range state.SignatureRules {
		ruleEndpoint := fmt.Sprintf("%s/%s/signaturerules", common.URL_CTE_POLICY, state.ID.ValueString())
		response, err := r.client.GetById(ctx, id, rule.ID.ValueString(), ruleEndpoint)
		if handleRuleReadNotFound(ctx, err, response, "CTE Policy Signature Rule ("+rule.ID.ValueString()+")", &resp.Diagnostics) {
			return
		}
		var apiRule SignatureRuleJSON
		if err := json.Unmarshal([]byte(response), &apiRule); err != nil {
			resp.Diagnostics.AddError("Error parsing signature rule response", err.Error())
			return
		}
		refreshedSignatureRules = append(refreshedSignatureRules, SignatureRuleTFSDK{
			ID:             types.StringValue(apiRule.ID),
			SignatureSetID: types.StringValue(apiRule.SignatureSetName), // use name not id!
		})
	}
	state.SignatureRules = refreshedSignatureRules

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
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

	//immutable field handling
	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannot change name of the policy once it is created", "Name is an immutable field")
		return
	}
	if plan.PolicyType.ValueString() != state.PolicyType.ValueString() {
		resp.Diagnostics.AddError("Cannot change type of the policy once it is created", "Policy Type is an immutable field")
		return
	}

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
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
		r.client.Log.Debug("Metadata should not be empty at this point")
		if plan.Metadata.RestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
			metadata.RestrictUpdate = bool(plan.Metadata.RestrictUpdate.ValueBool())
		}
		payload.Metadata = metadata
	}
	payload.Metadata = metadata

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_CTE_POLICY, payloadJSON, "id")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_policy.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
	if err := updateSecurityRules(ctx, r, plan, state, resp); err != nil {
		return
	}
	if err := updateKeyRules(ctx, r, plan, state, resp); err != nil {
		return
	}
	if err := updateDataTxRules(ctx, r, plan, state, resp); err != nil {
		return
	}
	if err := updateIDTKeyRules(ctx, r, plan, state, resp); err != nil {
		return
	}
	if err := updateLDTKeyRules(ctx, r, plan, state, resp); err != nil {
		return
	}
	if err := updateSignatureRules(ctx, r, plan, state, resp); err != nil {
		return
	}

	plan.ID = types.StringValue(response)

	// Read back the policy from CM after the update completes to refresh any
	// server-computed/normalized fields before writing plan to state
	// (TFIN-547), following the same GetById-then-merge-into-plan pattern
	// used in resource_cm_user.go's Update().
	readBackID := uuid.New().String()
	getResp, getErr := r.client.GetById(ctx, readBackID, plan.ID.ValueString(), common.URL_CTE_POLICY)
	if getErr == nil && getResp != "" {
		var apiResp CTEPolicyListJSON
		if err := json.Unmarshal([]byte(getResp), &apiResp); err == nil {
			plan.Description = types.StringValue(apiResp.Description)
			plan.NeverDeny = types.BoolValue(apiResp.NeverDeny)
			plan.Metadata = &CTEPolicyMetadataTFSDK{
				RestrictUpdate: types.BoolValue(apiResp.Metadata.RestrictUpdate),
			}
		}
	}

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
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_policy.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if handleDeleteNotFound(err, "CTE Policy "+state.ID.ValueString(), &resp.Diagnostics) {
			return
		}
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

func updateSecurityRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	id := uuid.New().String()
	ruleEndpoint := fmt.Sprintf("%s/%s/securityrules", common.URL_CTE_POLICY, state.ID.ValueString())

	// Build map of plan rule IDs for quick lookup (only rules with IDs i.e existing rules)
	planRuleMap := make(map[string]SecurityRuleTFSDK)
	for _, planRule := range plan.SecurityRules {
		if planRule.ID.ValueString() != "" {
			planRuleMap[planRule.ID.ValueString()] = planRule
		}
	}

	// Build map of state rule IDs for quick lookup
	stateRuleMap := make(map[string]SecurityRuleTFSDK)
	for _, stateRule := range state.SecurityRules {
		stateRuleMap[stateRule.ID.ValueString()] = stateRule
	}

	// Case 1: DELETE rules that are in state but not in plan
	for _, stateRule := range state.SecurityRules {
		if _, exists := planRuleMap[stateRule.ID.ValueString()]; !exists {
			deleteURL := fmt.Sprintf("%s/%s/%s/securityrules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.ID.ValueString(),
				stateRule.ID.ValueString(),
			)
			_, err := r.client.DeleteByID(ctx, "DELETE", stateRule.ID.ValueString(), deleteURL, nil)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting security rule",
					"Could not delete security rule "+stateRule.ID.ValueString()+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Deleted security rule: " + stateRule.ID.ValueString())
		}
	}

	// Case 2: PATCH rules that are in both plan and state but fields changed
	// Case 3: POST new rules that are in plan but not in state (no ID)
	for i, planRule := range plan.SecurityRules {
		ruleID := planRule.ID.ValueString()

		if ruleID == "" {
			// Case 3: New rule — POST
			rulePayload := SecurityRuleJSON{
				Action:             planRule.Action.ValueString(),
				Effect:             planRule.Effect.ValueString(),
				ExcludeProcessSet:  planRule.ExcludeProcessSet.ValueBool(),
				ExcludeResourceSet: planRule.ExcludeResourceSet.ValueBool(),
				ExcludeUserSet:     planRule.ExcludeUserSet.ValueBool(),
				PartialMatch:       planRule.PartialMatch.ValueBool(),
				ProcessSetID:       planRule.ProcessSetID.ValueString(),
				ResourceSetID:      planRule.ResourceSetID.ValueString(),
				UserSetID:          planRule.UserSetID.ValueString(),
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling new security rule", err.Error())
				return err
			}

			response, err := r.client.PostDataV2(ctx, id, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating new security rule",
					"Could not create security rule: "+err.Error(),
				)
				return err
			}

			// Capture new rule ID from response
			var newRule SecurityRuleJSON
			if err := json.Unmarshal([]byte(response), &newRule); err != nil {
				resp.Diagnostics.AddError("Error parsing new security rule response", err.Error())
				return err
			}
			plan.SecurityRules[i].ID = types.StringValue(newRule.ID)
			plan.SecurityRules[i].OrderNumber = types.Int64Value(*newRule.OrderNumber)
			r.client.Log.Debug("Created new security rule: " + newRule.ID)

		} else {
			// Case 2: Existing rule — compare fields and PATCH if changed
			stateRule, exists := stateRuleMap[ruleID]
			if !exists {
				continue
			}
			// Compare fields — only PATCH if something changed
			orderNumberChanged := false

			if !planRule.OrderNumber.IsNull() && !planRule.OrderNumber.IsUnknown() {
				orderNumberChanged =
					planRule.OrderNumber.ValueInt64() != stateRule.OrderNumber.ValueInt64()
			}

			if planRule.Action.ValueString() == stateRule.Action.ValueString() &&
				!orderNumberChanged &&
				planRule.Effect.ValueString() == stateRule.Effect.ValueString() &&
				planRule.ExcludeProcessSet.ValueBool() == stateRule.ExcludeProcessSet.ValueBool() &&
				planRule.ExcludeResourceSet.ValueBool() == stateRule.ExcludeResourceSet.ValueBool() &&
				planRule.ExcludeUserSet.ValueBool() == stateRule.ExcludeUserSet.ValueBool() &&
				planRule.PartialMatch.ValueBool() == stateRule.PartialMatch.ValueBool() &&
				planRule.ProcessSetID.ValueString() == stateRule.ProcessSetID.ValueString() &&
				planRule.ResourceSetID.ValueString() == stateRule.ResourceSetID.ValueString() &&
				planRule.UserSetID.ValueString() == stateRule.UserSetID.ValueString() {
				// Nothing changed — skip
				plan.SecurityRules[i].OrderNumber = stateRule.OrderNumber
				r.client.Log.Debug("Security rule unchanged, skipping PATCH: " + ruleID)
				continue
			}

			rulePayload := SecurityRuleJSON{
				Action:             planRule.Action.ValueString(),
				Effect:             planRule.Effect.ValueString(),
				ExcludeProcessSet:  planRule.ExcludeProcessSet.ValueBool(),
				ExcludeResourceSet: planRule.ExcludeResourceSet.ValueBool(),
				ExcludeUserSet:     planRule.ExcludeUserSet.ValueBool(),
				PartialMatch:       planRule.PartialMatch.ValueBool(),
				ProcessSetID:       planRule.ProcessSetID.ValueString(),
				ResourceSetID:      planRule.ResourceSetID.ValueString(),
				UserSetID:          planRule.UserSetID.ValueString(),
			}
			if orderNumberChanged {
				orderNumber := planRule.OrderNumber.ValueInt64()
				rulePayload.OrderNumber = &orderNumber
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)

			if err != nil {
				resp.Diagnostics.AddError("Error marshalling security rule", err.Error())
				return err
			}

			response, err := r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating security rule",
					"Could not update security rule "+ruleID+": "+err.Error(),
				)
				return err
			}
			var updatedRule SecurityRuleJSON
			if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
				resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
				return err
			}
			plan.SecurityRules[i].OrderNumber = types.Int64Value(*updatedRule.OrderNumber)
			r.client.Log.Debug("Updated security rule: " + ruleID)
		}
	}

	return nil
}

func updateKeyRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	id := uuid.New().String()
	ruleEndpoint := fmt.Sprintf("%s/%s/keyrules", common.URL_CTE_POLICY, state.ID.ValueString())

	// Build map of plan rule IDs for quick lookup (only existing rules with IDs)
	planRuleMap := make(map[string]KeyRuleTFSDK)
	for _, planRule := range plan.KeyRules {
		if planRule.ID.ValueString() != "" {
			planRuleMap[planRule.ID.ValueString()] = planRule
		}
	}

	// Build map of state rule IDs for quick lookup
	stateRuleMap := make(map[string]KeyRuleTFSDK)
	for _, stateRule := range state.KeyRules {
		stateRuleMap[stateRule.ID.ValueString()] = stateRule
	}

	// Case 1: DELETE rules in state but not in plan
	for _, stateRule := range state.KeyRules {
		if _, exists := planRuleMap[stateRule.ID.ValueString()]; !exists {
			deleteURL := fmt.Sprintf("%s/%s/%s/keyrules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.ID.ValueString(),
				stateRule.ID.ValueString(),
			)
			_, err := r.client.DeleteByID(ctx, "DELETE", stateRule.ID.ValueString(), deleteURL, nil)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting key rule",
					"Could not delete key rule "+stateRule.ID.ValueString()+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Deleted key rule: " + stateRule.ID.ValueString())
		}
	}

	// Case 2 and 3: PATCH existing or POST new rules
	for i, planRule := range plan.KeyRules {
		ruleID := planRule.ID.ValueString()

		if ruleID == "" {
			// Case 3: New rule — POST
			rulePayload := KeyRuleJSON{
				KeyID:         planRule.KeyID.ValueString(),
				KeyType:       planRule.KeyType.ValueString(),
				ResourceSetID: planRule.ResourceSetID.ValueString(),
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling new key rule", err.Error())
				return err
			}

			response, err := r.client.PostDataV2(ctx, id, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating new key rule",
					"Could not create key rule: "+err.Error(),
				)
				return err
			}

			// Capture new rule ID from response
			var newRule KeyRuleJSON
			if err := json.Unmarshal([]byte(response), &newRule); err != nil {
				resp.Diagnostics.AddError("Error parsing new key rule response", err.Error())
				return err
			}
			plan.KeyRules[i].ID = types.StringValue(newRule.ID)
			plan.KeyRules[i].OrderNumber = types.Int64Value(*newRule.OrderNumber)
			r.client.Log.Debug("Created new key rule: " + newRule.ID)

		} else {
			// Case 2: Existing rule — compare and PATCH if changed
			stateRule, exists := stateRuleMap[ruleID]
			if !exists {
				continue
			}
			// Only PATCH if something changed
			orderNumberChanged := false
			if !planRule.OrderNumber.IsNull() && !planRule.OrderNumber.IsUnknown() {
				orderNumberChanged =
					planRule.OrderNumber.ValueInt64() != stateRule.OrderNumber.ValueInt64()
			}
			if planRule.KeyID.ValueString() == stateRule.KeyID.ValueString() &&
				!orderNumberChanged &&
				planRule.KeyType.ValueString() == stateRule.KeyType.ValueString() &&
				planRule.ResourceSetID.ValueString() == stateRule.ResourceSetID.ValueString() {
				r.client.Log.Debug("Key rule unchanged, skipping PATCH: " + ruleID)
				plan.KeyRules[i].OrderNumber = stateRule.OrderNumber
				continue
			}

			// Fields changed — PATCH
			rulePayload := KeyRuleJSON{
				KeyID:         planRule.KeyID.ValueString(),
				KeyType:       planRule.KeyType.ValueString(),
				ResourceSetID: planRule.ResourceSetID.ValueString(),
			}
			if orderNumberChanged {
				orderNumber := planRule.OrderNumber.ValueInt64()
				rulePayload.OrderNumber = &orderNumber
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling key rule", err.Error())
				return err
			}

			response, err := r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating key rule",
					"Could not update key rule "+ruleID+": "+err.Error(),
				)
				return err
			}
			var updatedRule KeyRuleJSON
			if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
				resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
				return err
			}
			plan.KeyRules[i].OrderNumber = types.Int64Value(*updatedRule.OrderNumber)

			r.client.Log.Debug("Updated key rule: " + ruleID)
		}
	}

	return nil
}

func updateDataTxRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	id := uuid.New().String()
	ruleEndpoint := fmt.Sprintf("%s/%s/datatxrules", common.URL_CTE_POLICY, state.ID.ValueString())

	// Build map of plan rule IDs for quick lookup
	planRuleMap := make(map[string]DataTransformationRuleTFSDK)
	for _, planRule := range plan.DataTransformRules {
		if planRule.ID.ValueString() != "" {
			planRuleMap[planRule.ID.ValueString()] = planRule
		}
	}

	// Build map of state rule IDs for quick lookup
	stateRuleMap := make(map[string]DataTransformationRuleTFSDK)
	for _, stateRule := range state.DataTransformRules {
		stateRuleMap[stateRule.ID.ValueString()] = stateRule
	}

	// Case 1: DELETE rules in state but not in plan
	for _, stateRule := range state.DataTransformRules {
		if _, exists := planRuleMap[stateRule.ID.ValueString()]; !exists {
			deleteURL := fmt.Sprintf("%s/%s/%s/datatxrules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.ID.ValueString(),
				stateRule.ID.ValueString(),
			)
			_, err := r.client.DeleteByID(ctx, "DELETE", stateRule.ID.ValueString(), deleteURL, nil)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting data transform rule",
					"Could not delete data transform rule "+stateRule.ID.ValueString()+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Deleted data transform rule: " + stateRule.ID.ValueString())
		}
	}

	// Case 2 and 3: PATCH existing or POST new rules
	for i, planRule := range plan.DataTransformRules {
		ruleID := planRule.ID.ValueString()

		if ruleID == "" {
			// Case 3: New rule — POST

			rulePayload := DataTxRuleJSON{
				KeyID:         planRule.KeyID.ValueString(),
				KeyType:       planRule.KeyType.ValueString(),
				ResourceSetID: planRule.ResourceSetID.ValueString(),
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling new data transform rule", err.Error())
				return err
			}

			response, err := r.client.PostDataV2(ctx, id, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating new data transform rule",
					"Could not create data transform rule: "+err.Error(),
				)
				return err
			}

			var newRule DataTxRuleJSON
			if err := json.Unmarshal([]byte(response), &newRule); err != nil {
				resp.Diagnostics.AddError("Error parsing new data transform rule response", err.Error())
				return err
			}
			plan.DataTransformRules[i].ID = types.StringValue(newRule.ID)
			plan.DataTransformRules[i].OrderNumber = types.Int64Value(*newRule.OrderNumber)
			r.client.Log.Debug("Created new data transform rule: " + newRule.ID)

		} else {
			// Case 2: Existing rule — compare and PATCH if changed
			stateRule, exists := stateRuleMap[ruleID]
			if !exists {
				continue
			}
			orderNumberChanged := false
			if !planRule.OrderNumber.IsNull() && !planRule.OrderNumber.IsUnknown() {
				orderNumberChanged =
					planRule.OrderNumber.ValueInt64() != stateRule.OrderNumber.ValueInt64()
			}
			// Only PATCH if something changed
			if planRule.KeyID.ValueString() == stateRule.KeyID.ValueString() &&
				!orderNumberChanged &&
				planRule.KeyType.ValueString() == stateRule.KeyType.ValueString() &&
				planRule.ResourceSetID.ValueString() == stateRule.ResourceSetID.ValueString() {
				r.client.Log.Debug("Data transform rule unchanged, skipping PATCH: " + ruleID)
				plan.DataTransformRules[i].OrderNumber = stateRule.OrderNumber
				continue
			}

			// Fields changed — PATCH
			rulePayload := DataTxRuleJSON{
				KeyID:         planRule.KeyID.ValueString(),
				KeyType:       planRule.KeyType.ValueString(),
				ResourceSetID: planRule.ResourceSetID.ValueString(),
			}
			if orderNumberChanged {
				orderNumber := planRule.OrderNumber.ValueInt64()
				rulePayload.OrderNumber = &orderNumber
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling data transform rule", err.Error())
				return err
			}

			response, err := r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating data transform rule",
					"Could not update data transform rule "+ruleID+": "+err.Error(),
				)
				return err
			}
			var updatedRule DataTxRuleJSON
			if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
				resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
				return err
			}
			plan.DataTransformRules[i].OrderNumber = types.Int64Value(*updatedRule.OrderNumber)
			r.client.Log.Debug("Updated data transform rule: " + ruleID)
		}
	}

	return nil
}

func updateIDTKeyRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	// TFIN-603: CipherTrust Manager has no route to delete an individual IDT
	// key rule (DELETE .../idtkeyrules/{id} returns 405 Method Not Allowed).
	// Previously this case only logged a warning and tried to restore
	// plan.IDTKeyRules from state, but since plan is passed by value here
	// that reassignment never propagated back to the caller's plan variable
	// in Update() — the caller's resp.State.Set(ctx, plan) still wrote
	// idt_key_rules = [], permanently orphaning the live CM rule with no
	// Terraform-native way to reconcile it again. Refuse the apply instead
	// so state can never reach that terminal condition.
	if len(state.IDTKeyRules) > 0 && len(plan.IDTKeyRules) == 0 {
		resp.Diagnostics.AddError(
			"IDT Key Rule Removal Not Supported",
			"IDT key rules cannot be removed once created; CipherTrust Manager has no API route to delete an "+
				"individual IDT key rule. Restore the idt_key_rules block in your configuration to keep managing "+
				"this policy, or destroy and recreate the entire policy if removal is truly required.",
		)
		return fmt.Errorf("IDT key rule removal is not supported by CipherTrust Manager")
	}

	// Nothing in state and nothing planned — nothing to do.
	if len(state.IDTKeyRules) == 0 && len(plan.IDTKeyRules) == 0 {
		return nil
	}

	// TFIN-603: adding an idt_key_rules entry to a policy that currently has
	// none in state is not handled through this path — CipherTrust Manager
	// only accepts idt_key_rules embedded in the policy creation payload,
	// and there is no confirmed API route to add one to an existing policy
	// afterward (nor, as above, to remove one). Previously this silently
	// no-op'd (returning nil without any API call) and let the plan's
	// unvalidated values — including a fabricated id: null — get written
	// straight to state. Fail clearly instead.
	if len(state.IDTKeyRules) == 0 && len(plan.IDTKeyRules) > 0 {
		resp.Diagnostics.AddError(
			"IDT Key Rule Addition Not Supported",
			"Adding idt_key_rules to a policy that does not already have one is not supported via update; "+
				"CipherTrust Manager does not expose an API route to add an IDT key rule to an existing policy. "+
				"Set idt_key_rules at policy creation time instead.",
		)
		return fmt.Errorf("adding an IDT key rule via update is not supported by CipherTrust Manager")
	}

	if len(plan.IDTKeyRules) > 1 {
		resp.Diagnostics.AddError(
			"Invalid IDT Key Rule Configuration",
			"Only one IDT key rule is allowed per policy. Please remove the extra IDT key rules.",
		)
		return fmt.Errorf("only one IDT key rule is allowed per policy")
	}

	// TFIN-603: state rule has no ID. In practice this only happens to state
	// that was already corrupted by the bug above prior to this fix
	// (removal silently emptied idt_key_rules while the rule stayed live on
	// CM, then re-adding the block wrote id: null with no API call).
	// Reconcile by listing the policy's IDT key rules directly from CM
	// (GET .../idtkeyrules) so the real ID can be recovered without already
	// knowing it, rather than silently continuing with an invalid ID.
	if state.IDTKeyRules[0].ID.ValueString() == "" {
		ruleEndpoint := fmt.Sprintf("%s/%s/idtkeyrules", common.URL_CTE_POLICY, state.ID.ValueString())
		jsonStr, _, err := r.client.GetAllPagedWithLimit(ctx, uuid.New().String(), ruleEndpoint, 0, 10)
		if err != nil {
			resp.Diagnostics.AddError(
				"IDT Key Rule State Inconsistent",
				"IDT key rule in state has no ID and the existing IDT key rules could not be listed from "+
					"CipherTrust Manager to reconcile it: "+err.Error(),
			)
			return err
		}
		var existingRules []CTEPolicyIDTKeyRulesJSON
		if err := json.Unmarshal([]byte(jsonStr), &existingRules); err != nil {
			resp.Diagnostics.AddError("Error parsing IDT key rules list response while reconciling", err.Error())
			return err
		}
		if len(existingRules) == 0 {
			resp.Diagnostics.AddError(
				"IDT Key Rule State Inconsistent",
				"IDT key rule in state has no ID and CipherTrust Manager reports no IDT key rule exists for this "+
					"policy. State cannot be automatically reconciled; correct idt_key_rules in state manually with "+
					"the correct id from CipherTrust Manager before applying again.",
			)
			return fmt.Errorf("IDT key rule state is inconsistent: no ID in state and none found on CM")
		}
		state.IDTKeyRules[0].ID = types.StringValue(existingRules[0].ID)
		plan.IDTKeyRules[0].ID = state.IDTKeyRules[0].ID
		r.client.Log.Debug("Reconciled IDT key rule ID from CM: " + state.IDTKeyRules[0].ID.ValueString())
	}

	planRule := plan.IDTKeyRules[0]
	stateRule := state.IDTKeyRules[0]
	ruleID := stateRule.ID.ValueString()

	// Compare fields — only PATCH if changed
	if planRule.CurrentKey.ValueString() == stateRule.CurrentKey.ValueString() &&
		planRule.CurrentKeyType.ValueString() == stateRule.CurrentKeyType.ValueString() &&
		planRule.TransformationKey.ValueString() == stateRule.TransformationKey.ValueString() &&
		planRule.TransformationKeyType.ValueString() == stateRule.TransformationKeyType.ValueString() {
		r.client.Log.Debug("IDT key rule unchanged, skipping PATCH: " + ruleID)
		return nil
	}

	ruleEndpoint := fmt.Sprintf("%s/%s/idtkeyrules", common.URL_CTE_POLICY, state.ID.ValueString())

	rulePayload := IDTRuleJSON{
		CurrentKey:            planRule.CurrentKey.ValueString(),
		CurrentKeyType:        planRule.CurrentKeyType.ValueString(),
		TransformationKey:     planRule.TransformationKey.ValueString(),
		TransformationKeyType: planRule.TransformationKeyType.ValueString(),
	}

	rulePayloadJSON, err := json.Marshal(rulePayload)
	if err != nil {
		resp.Diagnostics.AddError("Error marshalling IDT key rule", err.Error())
		return err
	}

	_, err = r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating IDT key rule",
			"Could not update IDT key rule "+ruleID+": "+err.Error(),
		)
		return err
	}

	plan.IDTKeyRules[0].ID = stateRule.ID
	r.client.Log.Debug("Updated IDT key rule: " + ruleID)
	return nil
}

func updateLDTKeyRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	id := uuid.New().String()
	ruleEndpoint := fmt.Sprintf("%s/%s/ldtkeyrules", common.URL_CTE_POLICY, state.ID.ValueString())

	// Build map of plan rule IDs
	planRuleMap := make(map[string]LDTKeyRuleTFSDK)
	for _, planRule := range plan.LDTKeyRules {
		if planRule.ID.ValueString() != "" {
			planRuleMap[planRule.ID.ValueString()] = planRule
		}
	}

	// Build map of state rule IDs
	stateRuleMap := make(map[string]LDTKeyRuleTFSDK)
	for _, stateRule := range state.LDTKeyRules {
		stateRuleMap[stateRule.ID.ValueString()] = stateRule
	}

	// Case 1: DELETE rules in state but not in plan
	for _, stateRule := range state.LDTKeyRules {
		if _, exists := planRuleMap[stateRule.ID.ValueString()]; !exists {
			deleteURL := fmt.Sprintf("%s/%s/%s/ldtkeyrules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.ID.ValueString(),
				stateRule.ID.ValueString(),
			)
			_, err := r.client.DeleteByID(ctx, "DELETE", stateRule.ID.ValueString(), deleteURL, nil)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting LDT key rule",
					"Could not delete LDT key rule "+stateRule.ID.ValueString()+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Deleted LDT key rule: " + stateRule.ID.ValueString())
		}
	}

	// Case 2 and 3: PATCH existing or POST new rules
	for i, planRule := range plan.LDTKeyRules {
		ruleID := planRule.ID.ValueString()

		if ruleID == "" {
			// Case 3: New rule — POST
			rulePayload := LDTRuleJSON{
				IsExclusionRule: planRule.IsExclusionRule.ValueBool(),
				ResourceSetID:   planRule.ResourceSetID.ValueString(),
			}
			if planRule.CurrentKey != nil {
				rulePayload.CurrentKey = CurrentKeyJSON{
					KeyID:   planRule.CurrentKey.KeyID.ValueString(),
					KeyType: planRule.CurrentKey.KeyType.ValueString(),
				}
			}
			if planRule.TransformationKey != nil {
				rulePayload.TransformationKey = &TransformationKeyJSON{
					KeyID:   planRule.TransformationKey.KeyID.ValueString(),
					KeyType: planRule.TransformationKey.KeyType.ValueString(),
				}
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling new LDT key rule", err.Error())
				return err
			}

			response, err := r.client.PostDataV2(ctx, id, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating new LDT key rule",
					"Could not create LDT key rule: "+err.Error(),
				)
				return err
			}

			var newRule LDTRuleJSON
			if err := json.Unmarshal([]byte(response), &newRule); err != nil {
				resp.Diagnostics.AddError("Error parsing new LDT key rule response", err.Error())
				return err
			}
			plan.LDTKeyRules[i].ID = types.StringValue(newRule.ID)
			plan.LDTKeyRules[i].OrderNumber = types.Int64Value(*newRule.OrderNumber)
			r.client.Log.Debug("Created new LDT key rule: " + newRule.ID)

		} else {
			// Case 2: Existing rule — compare and PATCH if changed
			stateRule, exists := stateRuleMap[ruleID]
			if !exists {
				continue
			}

			// Compare fields
			currentKeyChanged := planRule.CurrentKey != nil && stateRule.CurrentKey != nil &&
				planRule.CurrentKey.KeyID.ValueString() != stateRule.CurrentKey.KeyID.ValueString()

			transformationKeyChanged := planRule.TransformationKey != nil && stateRule.TransformationKey != nil &&
				planRule.TransformationKey.KeyID.ValueString() != stateRule.TransformationKey.KeyID.ValueString()

			orderNumberChanged := false
			if !planRule.OrderNumber.IsNull() && !planRule.OrderNumber.IsUnknown() {
				orderNumberChanged =
					planRule.OrderNumber.ValueInt64() != stateRule.OrderNumber.ValueInt64()
			}

			if !currentKeyChanged && !transformationKeyChanged && !orderNumberChanged &&
				planRule.IsExclusionRule.ValueBool() == stateRule.IsExclusionRule.ValueBool() &&
				planRule.ResourceSetID.ValueString() == stateRule.ResourceSetID.ValueString() {
				r.client.Log.Debug("LDT key rule unchanged, skipping PATCH: " + ruleID)
				plan.LDTKeyRules[i].OrderNumber = stateRule.OrderNumber
				continue
			}

			// Fields changed — PATCH
			rulePayload := LDTRuleJSON{
				IsExclusionRule: planRule.IsExclusionRule.ValueBool(),
				ResourceSetID: func() string {
					if planRule.ResourceSetID.ValueString() == stateRule.ResourceSetID.ValueString() {
						return ""
					}
					return planRule.ResourceSetID.ValueString()
				}(),
			}
			if planRule.CurrentKey != nil {
				rulePayload.CurrentKey = CurrentKeyJSON{
					KeyID:   planRule.CurrentKey.KeyID.ValueString(),
					KeyType: planRule.CurrentKey.KeyType.ValueString(),
				}
			}
			if planRule.TransformationKey != nil {
				rulePayload.TransformationKey = &TransformationKeyJSON{
					KeyID:   planRule.TransformationKey.KeyID.ValueString(),
					KeyType: planRule.TransformationKey.KeyType.ValueString(),
				}
			}
			if orderNumberChanged {
				orderNumber := planRule.OrderNumber.ValueInt64()
				rulePayload.OrderNumber = &orderNumber
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling LDT key rule", err.Error())
				return err
			}

			response, err := r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating LDT key rule",
					"Could not update LDT key rule "+ruleID+": "+err.Error(),
				)
				return err
			}
			var updatedRule LDTRuleJSON
			if err := json.Unmarshal([]byte(response), &updatedRule); err != nil {
				resp.Diagnostics.AddError("Error parsing updated security rule response", err.Error())
				return err
			}
			plan.LDTKeyRules[i].OrderNumber = types.Int64Value(*updatedRule.OrderNumber)
			r.client.Log.Debug("Updated LDT key rule: " + ruleID)
		}
	}

	return nil
}

func updateSignatureRules(ctx context.Context, r *resourceCTEPolicy, plan CTEPolicyTFSDK, state CTEPolicyTFSDK, resp *resource.UpdateResponse) error {
	id := uuid.New().String()
	ruleEndpoint := fmt.Sprintf("%s/%s/signaturerules", common.URL_CTE_POLICY, state.ID.ValueString())

	// Build map of plan rule IDs
	planRuleMap := make(map[string]SignatureRuleTFSDK)
	for _, planRule := range plan.SignatureRules {
		if planRule.ID.ValueString() != "" {
			planRuleMap[planRule.ID.ValueString()] = planRule
		}
	}

	// Build map of state rule IDs
	stateRuleMap := make(map[string]SignatureRuleTFSDK)
	for _, stateRule := range state.SignatureRules {
		stateRuleMap[stateRule.ID.ValueString()] = stateRule
	}

	// Case 1: DELETE rules in state but not in plan
	for _, stateRule := range state.SignatureRules {
		if _, exists := planRuleMap[stateRule.ID.ValueString()]; !exists {
			deleteURL := fmt.Sprintf("%s/%s/%s/signaturerules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.ID.ValueString(),
				stateRule.ID.ValueString(),
			)
			_, err := r.client.DeleteByID(ctx, "DELETE", stateRule.ID.ValueString(), deleteURL, nil)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting signature rule",
					"Could not delete signature rule "+stateRule.ID.ValueString()+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Deleted signature rule: " + stateRule.ID.ValueString())
		}
	}

	// Case 2 and 3: PATCH existing or POST new rules
	for i, planRule := range plan.SignatureRules {
		ruleID := planRule.ID.ValueString()

		if ruleID == "" {
			// Case 3: New rule — POST with signature_set_id_list
			rulePayload := AddSignaturesToRuleJSON{
				SignatureSets: []string{planRule.SignatureSetID.ValueString()},
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling new signature rule", err.Error())
				return err
			}

			response, err := r.client.PostDataV2(ctx, id, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating new signature rule",
					"Could not create signature rule: "+err.Error(),
				)
				return err
			}

			var newRule SignatureRuleJSON
			if err := json.Unmarshal([]byte(response), &newRule); err != nil {
				resp.Diagnostics.AddError("Error parsing new signature rule response", err.Error())
				return err
			}
			plan.SignatureRules[i].ID = types.StringValue(parseconfig(response)[0])

		} else {
			// Case 2: Existing rule — compare and PATCH if changed
			stateRule, exists := stateRuleMap[ruleID]
			if !exists {
				continue
			}

			if planRule.SignatureSetID.ValueString() == stateRule.SignatureSetID.ValueString() {
				r.client.Log.Debug("Signature rule unchanged, skipping PATCH: " + ruleID)
				continue
			}

			// Fields changed — PATCH with signature_set_id
			rulePayload := SignatureRuleJSON{
				SignatureSetID: planRule.SignatureSetID.ValueString(),
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling signature rule", err.Error())
				return err
			}

			_, err = r.client.UpdateDataV2(ctx, ruleID, ruleEndpoint, rulePayloadJSON)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating signature rule",
					"Could not update signature rule "+ruleID+": "+err.Error(),
				)
				return err
			}
			r.client.Log.Debug("Updated signature rule: " + ruleID)
		}
	}

	return nil
}

func (r *resourceCTEPolicy) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_cte_client.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_cte_client.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
