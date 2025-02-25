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
	_ datasource.DataSource              = &dataSourceCTEPolicyIDTKeyRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicyIDTKeyRule{}
)

func NewDataSourceCTEPolicyIDTKeyRule() datasource.DataSource {
	return &dataSourceCTEPolicyIDTKeyRule{}
}

type dataSourceCTEPolicyIDTKeyRule struct {
	client *common.Client
}

type CTEPolicyIDTKeyRuleDataSourceModel struct {
	PolicyID types.String                    `tfsdk:"policy"`
	Rules    []CTEPolicyIDTKeyRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicyIDTKeyRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_idt_key_rules"
}

func (d *dataSourceCTEPolicyIDTKeyRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
							Computed: true,
						},
						"policy_id": schema.StringAttribute{
							Computed: true,
						},
						"current_key": schema.StringAttribute{
							Computed: true,
						},
						"transformation_key": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicyIDTKeyRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_policy_idtkeyrules.go -> Read]["+id+"]")
	var state CTEPolicyIDTKeyRuleDataSourceModel
	req.Config.Get(ctx, &state)
	tflog.Info(ctx, "AnuragJain =====> "+state.PolicyID.ValueString())

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/idtkeyrules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_idtkeyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy IDT Key Rules from CM",
			err.Error(),
		)
		return
	}

	rules := []CTEPolicyIDTKeyRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_idtkeyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy IDT Key Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		idtKeyRule := CTEPolicyIDTKeyRulesListTFSDK{}
		idtKeyRule.ID = types.StringValue(rule.ID)
		idtKeyRule.PolicyID = types.StringValue(rule.PolicyID)
		idtKeyRule.CurrentKey = types.StringValue(rule.CurrentKey)
		idtKeyRule.TransformationKey = types.StringValue(rule.TransformationKey)

		state.Rules = append(state.Rules, idtKeyRule)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_policy_idtkeyrules.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicyIDTKeyRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
