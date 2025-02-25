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
	_ datasource.DataSource              = &dataSourceCTEPolicySignatureRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicySignatureRule{}
)

func NewDataSourceCTEPolicySignatureRule() datasource.DataSource {
	return &dataSourceCTEPolicySignatureRule{}
}

type dataSourceCTEPolicySignatureRule struct {
	client *common.Client
}

type CTEPolicySignatureRuleDataSourceModel struct {
	PolicyID types.String                       `tfsdk:"policy"`
	Rules    []CTEPolicySignatureRulesListTFSDK `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicySignatureRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_signature_rules"
}

func (d *dataSourceCTEPolicySignatureRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
							Description: "ID of the Signature Rule within the parent CTE Client Policy",
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
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
						"signature_set_id": schema.Int64Attribute{
							Computed: true,
						},
						"signature_set_name": schema.BoolAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicySignatureRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_policy_signaturerules.go -> Read]["+id+"]")
	var state CTEPolicySignatureRuleDataSourceModel
	req.Config.Get(ctx, &state)

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/signaturerules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_signaturerules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Signature Rules from CM",
			err.Error(),
		)
		return
	}

	rules := []CTEPolicySignatureRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_policy_signaturerules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Signature Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		signatureRule := CTEPolicySignatureRulesListTFSDK{}
		signatureRule.ID = types.StringValue(rule.ID)
		signatureRule.URI = types.StringValue(rule.URI)
		signatureRule.Account = types.StringValue(rule.Account)
		signatureRule.CreatedAt = types.StringValue(rule.CreatedAt)
		signatureRule.UpdatedAt = types.StringValue(rule.UpdatedAt)
		signatureRule.PolicyID = types.StringValue(rule.PolicyID)
		signatureRule.SignatureSetID = types.StringValue(rule.SignatureSetID)
		signatureRule.SignatureSetName = types.StringValue(rule.SignatureSetName)

		state.Rules = append(state.Rules, signatureRule)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_policy_signaturerules.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicySignatureRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
