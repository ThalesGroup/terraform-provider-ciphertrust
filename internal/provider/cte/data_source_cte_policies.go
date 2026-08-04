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
	_ datasource.DataSource              = &dataSourceCTEPolicy{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicy{}
)

func NewDataSourceCTEPolicy() datasource.DataSource {
	return &dataSourceCTEPolicy{}
}

type dataSourceCTEPolicy struct {
	client *common.Client
}

type CTEPolicyDataSourceModel struct {
	PolicyName types.String         `tfsdk:"policy_name"`
	Policies   []CTEPolicyListTFSDK `tfsdk:"cte_policies"`
}

func (d *dataSourceCTEPolicy) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policies_list"
}

func (d *dataSourceCTEPolicy) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_name": schema.StringAttribute{
				Optional: true,
			},
			"cte_policies": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"policy_type": schema.StringAttribute{
							Computed: true,
						},
						"metadata": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"restrict_update": schema.BoolAttribute{
									Computed: true,
								},
							},
						},
						"never_deny": schema.BoolAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"policy_version": schema.Int64Attribute{
							Computed: true,
						},
						"policy_key_version": schema.Int64Attribute{
							Computed: true,
						},
						"migrated_policy_id": schema.StringAttribute{
							Computed: true,
						},
						"updated_by": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicy) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_policy.go -> Read][" + id + "]")
	var state CTEPolicyDataSourceModel
	req.Config.Get(ctx, &state)
	d.client.Log.Info("PrathamMaini =====> " + state.PolicyName.ValueString())

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_CTE_POLICY+"?name="+state.PolicyName.ValueString())
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	policies := []CTEPolicyListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &policies)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_policy.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	for _, policy := range policies {
		ctePolicy := CTEPolicyListTFSDK{}
		ctePolicy.ID = types.StringValue(policy.ID)
		ctePolicy.Name = types.StringValue(policy.Name)
		ctePolicy.Description = types.StringValue(policy.Description)
		ctePolicy.PolicyType = types.StringValue(policy.PolicyType)
		ctePolicy.NeverDeny = types.BoolValue(policy.NeverDeny)
		ctePolicy.URI = types.StringValue(policy.URI)
		ctePolicy.CreatedAt = types.StringValue(policy.CreatedAt)
		ctePolicy.UpdatedAt = types.StringValue(policy.UpdatedAt)
		ctePolicy.PolicyVersion = types.Int64Value(policy.PolicyVersion)
		ctePolicy.PolicyKeyVersion = types.Int64Value(policy.PolicyKeyVersion)
		ctePolicy.MigratedPolicyId = types.StringValue(policy.MigratedPolicyId)
		ctePolicy.UpdatedBy = types.StringValue(policy.UpdatedBy)
		ctePolicy.Metadata = &CTEPolicyMetadataTFSDK{
			RestrictUpdate: types.BoolValue(policy.Metadata.RestrictUpdate),
		}

		state.Policies = append(state.Policies, ctePolicy)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_policy.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicy) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
