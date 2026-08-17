package cte

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceCTEPolicySecurityRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicySecurityRule{}
)

func NewDataSourceCTEPolicySecurityRule() datasource.DataSource {
	return &dataSourceCTEPolicySecurityRule{}
}

type dataSourceCTEPolicySecurityRule struct {
	client *common.Client
}

type CTEPolicySecurityRuleDataSourceModel struct {
	PolicyID types.String                      `tfsdk:"policy"`
	Limit    types.Int64                       `tfsdk:"limit"`
	Skip     types.Int64                       `tfsdk:"skip"`
	Rules    []CTEPolicySecurityRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicySecurityRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_security_rules"
}

func (d *dataSourceCTEPolicySecurityRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy": schema.StringAttribute{
				Description: "ID of the parent CTE Client Policy whose security rules are to be listed.",
				Required:    true,
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of security rules to return. If unset, all rules are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of security rules to skip before returning results, for pagination. Defaults to 0.",
			},
			"rules": schema.ListNestedAttribute{
				Description: "List of security rules configured on the policy.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the Security Rule within the parent CTE Client Policy",
						},
						"uri": schema.StringAttribute{
							Description: "URI of the security rule.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the security rule.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application associated with the security rule.",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the security rule.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the security rule was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the security rule was last updated.",
							Computed:    true,
						},
						"effect": schema.StringAttribute{
							Description: "Effect(s) of the security rule, comma-separated combination of permit, deny, audit and applykey.",
							Computed:    true,
						},
						"action": schema.StringAttribute{
							Description: "Actions to apply the effect to, comma-separated combination of read, write, all_ops, key_op, sec_erase, mkdir, rmdir, rename and unlink.",
							Computed:    true,
						},
						"policy_id": schema.StringAttribute{
							Description: "ID of the parent CTE Client Policy.",
							Computed:    true,
						},
						"order_number": schema.Int64Attribute{
							Description: "Precedence order of the rule in the parent policy.",
							Computed:    true,
						},
						"process_signed": schema.StringAttribute{
							Description: "Whether the process is signed.",
							Computed:    true,
						},
						"exclude_process_set": schema.BoolAttribute{
							Computed:    true,
							Description: "Process set to exclude. Supported for Standard, LDT and IDT policies.",
						},
						"exclude_resource_set": schema.BoolAttribute{
							Computed:    true,
							Description: "Resource set to exclude. Supported for Standard, LDT and IDT policies.",
						},
						"exclude_user_set": schema.BoolAttribute{
							Computed:    true,
							Description: "User set to exclude. Supported for Standard, LDT and IDT policies.",
						},
						"partial_match": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether to allow partial match operations. By default, it is enabled. Supported for Standard, LDT and IDT policies.",
						},
						"process_set_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the process set to link to the policy.",
						},
						"resource_set_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the resource set to link to the policy. Supported for Standard, LDT and IDT policies.",
						},
						"user_set_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the user set to link to the policy.",
						},
						"generation": schema.StringAttribute{
							Description: "Generation of the security rule.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicySecurityRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_policy_securityrules.go -> Read][" + id + "]")
	var state CTEPolicySecurityRuleDataSourceModel
	req.Config.Get(ctx, &state)

	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/securityrules",
		skipVal,
		limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy_securityrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Security Rules from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE policy security rules", total, limitVal)

	rules := []CTEPolicySecurityRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy_securityrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Security Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		securityRule := CTEPolicySecurityRulesListTFSDK{}
		securityRule.ID = types.StringValue(rule.ID)
		securityRule.URI = types.StringValue(rule.URI)
		securityRule.Account = types.StringValue(rule.Account)
		securityRule.Application = types.StringValue(rule.Application)
		securityRule.DevAccount = types.StringValue(rule.DevAccount)
		securityRule.CreatedAt = types.StringValue(rule.CreatedAt)
		securityRule.UpdatedAt = types.StringValue(rule.UpdatedAt)
		securityRule.PolicyID = types.StringValue(rule.PolicyID)
		securityRule.OrderNumber = types.Int64Value(rule.OrderNumber)
		securityRule.UserSetID = types.StringValue(rule.UserSetID)
		securityRule.ProcessSetID = types.StringValue(rule.ProcessSetID)
		securityRule.ResourceSetID = types.StringValue(rule.ResourceSetID)
		securityRule.ExcludeProcessSet = types.BoolValue(rule.ExcludeProcessSet)
		securityRule.ExcludeResourceSet = types.BoolValue(rule.ExcludeResourceSet)
		securityRule.ExcludeUserSet = types.BoolValue(rule.ExcludeUserSet)
		securityRule.Effect = types.StringValue(rule.Effect)
		securityRule.Action = types.StringValue(rule.Action)
		securityRule.PartialMatch = types.BoolValue(rule.PartialMatch)
		securityRule.ProcessSigned = types.StringValue(rule.ProcessSigned)
		securityRule.Generation = types.StringValue(rule.Generation)

		state.Rules = append(state.Rules, securityRule)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_policy_securityrules.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicySecurityRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
