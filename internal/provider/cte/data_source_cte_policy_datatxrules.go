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
	Rules    []CTEPolicyDataTxRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicyDataTXRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_data_tx_rules"
}

func (d *dataSourceCTEPolicyDataTXRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy": schema.StringAttribute{
				Description: "ID of the parent CTE Client Policy whose data transformation rules are to be listed.",
				Required:    true,
			},
			"rules": schema.ListNestedAttribute{
				Description: "List of data transformation rules configured on the policy.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "ID of the data transformation rule within the parent CTE Client Policy.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the data transformation rule.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the data transformation rule.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application associated with the data transformation rule.",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the data transformation rule.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the data transformation rule was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the data transformation rule was last updated.",
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
						"key_id": schema.StringAttribute{
							Description: "Identifier of the key to link with the rule.",
							Computed:    true,
						},
						"new_key_rule": schema.BoolAttribute{
							Description: "Whether this is a new key rule.",
							Computed:    true,
						},
						"resource_set_id": schema.StringAttribute{
							Description: "ID of the resource set to link with the rule.",
							Computed:    true,
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

	jsonStr, err := d.client.GetAllPaged(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/datatxrules")
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy_datatxrules.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Data TX Rules from CM",
			err.Error(),
		)
		return
	}

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
