package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceRegTokens{}
	_ datasource.DataSourceWithConfigure = &dataSourceRegTokens{}
)

func NewDataSourceRegTokens() datasource.DataSource {
	return &dataSourceRegTokens{}
}

type dataSourceRegTokens struct {
	client *common.Client
}

type RegTokensDataSourceModel struct {
	Filters types.Map              `tfsdk:"filters"`
	Tokens  []CMRegTokensListTFSDK `tfsdk:"tokens"`
}

func (d *dataSourceRegTokens) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_tokens_list"
}

func (d *dataSourceRegTokens) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"tokens": schema.ListNestedAttribute{
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
						"token": schema.StringAttribute{
							Computed: true,
						},
						"valid_until": schema.StringAttribute{
							Computed: true,
						},
						"max_clients": schema.Int64Attribute{
							Computed: true,
						},
						"clients_registered": schema.Int64Attribute{
							Computed: true,
						},
						"ca_id": schema.StringAttribute{
							Computed: true,
						},
						"name_prefix": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
		},
	}
}

func (d *dataSourceRegTokens) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_reg_tokens.go -> Read]["+id+"]")
	var state RegTokensDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_REG_TOKEN+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")

	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read reg tokens from CM",
			err.Error(),
		)
		return
	}

	tokens := []CMRegTokensListTFSDK{}

	err = json.Unmarshal([]byte(jsonStr), &tokens)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read reg tokens from CM",
			err.Error(),
		)
		return
	}

	for _, token := range tokens {
		tokenState := CMRegTokensListTFSDK{
			ID:                types.StringValue(token.ID.ValueString()),
			URI:               types.StringValue(token.URI.ValueString()),
			Account:           types.StringValue(token.Account.ValueString()),
			Application:       types.StringValue(token.Application.ValueString()),
			DevAccount:        types.StringValue(token.DevAccount.ValueString()),
			CreatedAt:         types.StringValue(token.CreatedAt.ValueString()),
			UpdatedAt:         types.StringValue(token.UpdatedAt.ValueString()),
			Token:             types.StringValue(token.Token.ValueString()),
			ValidUntil:        types.StringValue(token.ValidUntil.ValueString()),
			MaxClients:        types.Int64Value(token.MaxClients.ValueInt64()),
			ClientsRegistered: types.Int64Value(token.ClientsRegistered.ValueInt64()),
			CAID:              types.StringValue(token.CAID.ValueString()),
			NamePrefix:        types.StringValue(token.NamePrefix.ValueString()),
		}

		state.Tokens = append(state.Tokens, tokenState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_reg_tokens.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceRegTokens) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
