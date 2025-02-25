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
	_ datasource.DataSource              = &dataSourceCTEPolicyLDTKeyRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicyLDTKeyRule{}
)

func NewDataSourceCTEPolicyLDTKeyRule() datasource.DataSource {
	return &dataSourceCTEPolicyLDTKeyRule{}
}

type dataSourceCTEPolicyLDTKeyRule struct {
	client *common.Client
}

type CTEPolicyLDTKeyRuleDataSourceModel struct {
	PolicyID types.String                    `tfsdk:"policy"`
	Rules    []CTEPolicyLDTKeyRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicyLDTKeyRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_ldt_key_rules"
}

func (d *dataSourceCTEPolicyLDTKeyRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
							Description: "ID of the LDT Key Rule within the parent CTE Client Policy",
						},
						"policy_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the parent CTE Client Policy",
						},
						"order_number": schema.Int64Attribute{
							Computed:    true,
							Description: "Precedence order of the rule in the parent policy.",
						},
						"is_exclusion_rule": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether this is an exclusion rule. If enabled, no need to specify the transformation rule.",
						},
						"resource_set_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the resource set to link with the rule.",
						},
						"current_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the current key linked with the rule.",
						},
						"current_key_type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of the current key linked with the rule.",
						},
						"transformation_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier of the transformation key linked with the rule.",
						},
						"transformation_key_type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of the transformation key linked with the rule.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicyLDTKeyRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_policy_ldtkeyrules.go -> Read]["+id+"]")
	var state CTEPolicyLDTKeyRuleDataSourceModel
	req.Config.Get(ctx, &state)

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/ldtkeyrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_ldtkeyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy LDT Key Rules from CM",
			err.Error(),
		)
		return
	}

	rules := []CTEPolicyLDTKeyRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_ldtkeyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy LDT Key Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		ldtKeyRule := CTEPolicyLDTKeyRulesListTFSDK{}
		ldtKeyRule.ID = types.StringValue(rule.ID)
		ldtKeyRule.PolicyID = types.StringValue(rule.PolicyID)
		ldtKeyRule.OrderNumber = types.Int64Value(rule.OrderNumber)
		ldtKeyRule.ResourceSetID = types.StringValue(rule.ResourceSetID)
		ldtKeyRule.ISExclusionRule = types.BoolValue(rule.ISExclusionRule)
		ldtKeyRule.CurrentKeyID = types.StringValue(rule.CurrentKey.KeyID)
		ldtKeyRule.CurrentKeyType = types.StringValue(rule.CurrentKey.KeyType)
		ldtKeyRule.TransformationKeyID = types.StringValue(rule.TransformationKey.KeyID)
		ldtKeyRule.TransformationKeyType = types.StringValue(rule.TransformationKey.KeyType)

		state.Rules = append(state.Rules, ldtKeyRule)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_policy_ldtkeyrules.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicyLDTKeyRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
