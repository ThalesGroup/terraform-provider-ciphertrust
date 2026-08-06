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
	_ datasource.DataSource              = &dataSourceCTEPolicyDataTXRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicyDataTXRule{}
)

func NewDataSourceCTEPolicyDataTXRule() datasource.DataSource {
	return &dataSourceCTEPolicyDataTXRule{}
}

type dataSourceCTEPolicyDataTXRule struct {
	client *common.Client
}

type CTEPolicyDataTXRuleDataSourceModel struct {
	PolicyID types.String                    `tfsdk:"policy"`
	Limit    types.Int64                     `tfsdk:"limit"`
	Skip     types.Int64                     `tfsdk:"skip"`
	Rules    []CTEPolicyDataTxRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicyDataTXRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_data_tx_rules"
}

func (d *dataSourceCTEPolicyDataTXRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy": schema.StringAttribute{
				Required: true,
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of data transformation rules to return. If unset, all rules are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of data transformation rules to skip before returning results, for pagination. Defaults to 0.",
			},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
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
						"policy_id": schema.StringAttribute{
							Computed: true,
						},
						"order_number": schema.Int64Attribute{
							Computed: true,
						},
						"key_id": schema.StringAttribute{
							Computed: true,
						},
						"new_key_rule": schema.BoolAttribute{
							Computed: true,
						},
						"resource_set_id": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicyDataTXRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_policy_datatxrules.go -> Read][" + id + "]")
	var state CTEPolicyDataTXRuleDataSourceModel
	req.Config.Get(ctx, &state)
	d.client.Log.Info("AnuragJain =====> " + state.PolicyID.ValueString())

	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/datatxrules",
		skipVal,
		limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy_datatxrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Data TX Rules from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE policy data transformation rules", total, limitVal)

	rules := []CTEPolicyDataTxRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy_datatxrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Data TX Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		dataTxRule := CTEPolicyDataTxRulesListTFSDK{}
		dataTxRule.ID = types.StringValue(rule.ID)
		dataTxRule.URI = types.StringValue(rule.URI)
		dataTxRule.Account = types.StringValue(rule.Account)
		dataTxRule.Application = types.StringValue(rule.Application)
		dataTxRule.DevAccount = types.StringValue(rule.DevAccount)
		dataTxRule.CreateAt = types.StringValue(rule.CreatedAt)
		dataTxRule.UpdatedAt = types.StringValue(rule.UpdatedAt)
		dataTxRule.PolicyID = types.StringValue(rule.PolicyID)
		dataTxRule.OrderNumber = types.Int64Value(rule.OrderNumber)
		dataTxRule.KeyID = types.StringValue(rule.KeyID)
		dataTxRule.NewKeyRule = types.BoolValue(rule.NewKeyRule)
		dataTxRule.ResourceSetID = types.StringValue(rule.ResourceSetID)

		state.Rules = append(state.Rules, dataTxRule)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_policy_datatxrules.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicyDataTXRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
