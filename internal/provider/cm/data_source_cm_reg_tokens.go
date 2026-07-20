// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	"github.com/hashicorp/terraform-plugin-framework/attr"
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
							Computed:  true,
							Sensitive: true,
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
						"cert_duration": schema.Int64Attribute{
							Computed: true,
						},
						"client_management_profile_id": schema.StringAttribute{
							Computed: true,
						},
						"lifetime": schema.StringAttribute{
							Computed: true,
						},
						"label": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
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
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_reg_tokens.go -> Read]["+id+"]")

	var state RegTokensDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	var allRawTokens []gjson.Result
	limit := 100
	skip := 0
	for {
		url := fmt.Sprintf("%s/?%sskip=%d&limit=%d", common.URL_REG_TOKEN, strings.Join(kvs, ""), skip, limit)
		jsonStr, err := d.client.GetAll(ctx, id, url)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
			resp.Diagnostics.AddError(
				"Unable to read reg tokens from CM",
				err.Error(),
			)
			return
		}

		rawTokens := gjson.Parse(jsonStr)
		if !rawTokens.IsArray() {
			tflog.Debug(ctx, common.ERR_METHOD_END+"response is not a JSON array [data_source_cm_reg_tokens.go -> Read]["+id+"]")
			resp.Diagnostics.AddError(
				"Unable to read reg tokens from CM",
				"CM returned an unexpected non-array response: "+jsonStr,
			)
			return
		}

		results := rawTokens.Array()
		if len(results) == 0 {
			break
		}

		allRawTokens = append(allRawTokens, results...)
		if len(results) < limit {
			break
		}
		skip += limit
	}

	for _, rawToken := range allRawTokens {
		raw := rawToken.Raw

		tokenState := CMRegTokensListTFSDK{
			ID:                        types.StringValue(gjson.Get(raw, "id").String()),
			URI:                       types.StringValue(gjson.Get(raw, "uri").String()),
			Account:                   types.StringValue(gjson.Get(raw, "account").String()),
			Application:               types.StringValue(gjson.Get(raw, "application").String()),
			DevAccount:                types.StringValue(gjson.Get(raw, "devAccount").String()),
			CreatedAt:                 types.StringValue(gjson.Get(raw, "createdAt").String()),
			UpdatedAt:                 types.StringValue(gjson.Get(raw, "updatedAt").String()),
			Token:                     types.StringValue(gjson.Get(raw, "token").String()),
			ValidUntil:                types.StringValue(gjson.Get(raw, "valid_until").String()),
			MaxClients:                types.Int64Value(gjson.Get(raw, "max_clients").Int()),
			ClientsRegistered:         types.Int64Value(gjson.Get(raw, "clients_registered").Int()),
			CAID:                      types.StringValue(gjson.Get(raw, "ca_id").String()),
			NamePrefix:                types.StringValue(gjson.Get(raw, "name_prefix").String()),
			CertDuration:              types.Int64Value(gjson.Get(raw, "cert_duration").Int()),
			ClientManagementProfileID: types.StringValue(gjson.Get(raw, "client_management_profile_id").String()),
			Lifetime:                  types.StringValue(gjson.Get(raw, "lifetime").String()),
		}

		// label — three-branch: absent/null → MapNull, empty → MapValueMust({}), present → MapValueFrom
		labelResult := gjson.Get(raw, "label")
		if !labelResult.Exists() || labelResult.Type == gjson.Null {
			tokenState.Label = types.MapNull(types.StringType)
		} else if len(labelResult.Map()) == 0 {
			tokenState.Label = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			labelMap := make(map[string]string)
			labelResult.ForEach(func(k, v gjson.Result) bool {
				labelMap[k.String()] = v.String()
				return true
			})
			lv, diag := types.MapValueFrom(ctx, types.StringType, labelMap)
			resp.Diagnostics.Append(diag...)
			if resp.Diagnostics.HasError() {
				return
			}
			tokenState.Label = lv
		}

		// labels — same three-branch pattern
		labelsResult := gjson.Get(raw, "labels")
		if !labelsResult.Exists() || labelsResult.Type == gjson.Null {
			tokenState.Labels = types.MapNull(types.StringType)
		} else if len(labelsResult.Map()) == 0 {
			tokenState.Labels = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			labelsMap := make(map[string]string)
			labelsResult.ForEach(func(k, v gjson.Result) bool {
				labelsMap[k.String()] = v.String()
				return true
			})
			lv, diag := types.MapValueFrom(ctx, types.StringType, labelsMap)
			resp.Diagnostics.Append(diag...)
			if resp.Diagnostics.HasError() {
				return
			}
			tokenState.Labels = lv
		}

		state.Tokens = append(state.Tokens, tokenState)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
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
