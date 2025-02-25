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
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	Rules    []CTEPolicySecurityRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicySecurityRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_security_rules"
}

func (d *dataSourceCTEPolicySecurityRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy": schema.StringAttribute{
				Optional: true,
			},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the Security Rule within the parent CTE Client Policy",
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
							Computed: true,
						},
						"application": schema.StringAttribute{
							Computed: true,
						},
						"dev_account": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"effect": schema.StringAttribute{
							Computed: true,
						},
						"action": schema.StringAttribute{
							Computed: true,
						},
						"policy_id": schema.StringAttribute{
							Computed: true,
						},
						"order_number": schema.Int64Attribute{
							Computed: true,
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
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicySecurityRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_policy_securityrules.go -> Read]["+id+"]")
	var state CTEPolicySecurityRuleDataSourceModel
	req.Config.Get(ctx, &state)

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/securityrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_securityrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Security Rules from CM",
			err.Error(),
		)
		return
	}

	rules := []CTEPolicySecurityRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_securityrules.go -> Read]["+id+"]")
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

		state.Rules = append(state.Rules, securityRule)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_policy_securityrules.go -> Read]["+id+"]")
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
