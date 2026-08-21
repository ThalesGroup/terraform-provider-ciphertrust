package cm

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		Description: "Lists CipherTrust Manager client registration tokens via the /v1/client-management/regtokens API.",
		Attributes: map[string]schema.Attribute{
			"tokens": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of registration tokens matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the registration token.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "A human readable unique identifier of the registration token.",
						},
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account which owns this registration token.",
						},
						"application": schema.StringAttribute{
							Computed:    true,
							Description: "The application this registration token belongs to.",
						},
						"dev_account": schema.StringAttribute{
							Computed:    true,
							Description: "The developer account which owns this registration token's application.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the registration token was created.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the registration token was last updated.",
						},
						"token": schema.StringAttribute{
							Computed:    true,
							Sensitive:   true,
							Description: "Registration token secret returned by the API. Marked sensitive — value is redacted in plan/apply output.",
						},
						"valid_until": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time until which the registration token remains valid, derived from `lifetime` at creation time.",
						},
						"max_clients": schema.Int64Attribute{
							Computed:    true,
							Description: "Maximum number of clients that can be registered using this token. No limit by default.",
						},
						"clients_registered": schema.Int64Attribute{
							Computed:    true,
							Description: "Number of clients registered using this token so far.",
						},
						"ca_id": schema.StringAttribute{
							Computed:    true,
							Description: "DEPRECATED: the field is deprecated. Use the ca_id in the client profile instead. ca_id is the ID of the trusted Certificate Authority that was used to sign client certificates during the registration process.",
						},
						"name_prefix": schema.StringAttribute{
							Computed:    true,
							Description: "Prefix for the client name. For a client registered using this registration token, name_prefix, if specified, client name is constructed as 'name_prefix{nth client registered using this registration token}'. If name_prefix is not specified, CipherTrust Manager server generates a random name for the client.",
						},
						"cert_duration": schema.Int64Attribute{
							Computed:    true,
							Description: "Duration in days for which the CipherTrust Manager client certificate is valid. It is not recommended to use this parameter; use the one supported in client profile.",
						},
						"client_management_profile_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the client management profile.",
						},
						"lifetime": schema.StringAttribute{
							Computed:    true,
							Description: "Duration the token is valid. A positive integer followed by a unit: s (seconds), m (minutes), h (hours), or d (days). Example: '30d', '24h', '3600s'. Empty string means no expiry.",
						},
						"label": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Map of key/value pairs sent verbatim to CipherTrust Manager as the token's label metadata. CM expects a single fixed key here depending on the client type registered with this token: key \"KmipClientProfile\" for KMIP client registration, or \"ClientProfile\" for ProtectApp (PA) client registration; the corresponding value is the name of the KMIP/ProtectApp client profile associated with the token. This is distinct from `labels` below, which holds free-form user-defined metadata rather than a client-profile association.",
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Labels are free-form key/value pairs used to group and tag resources, based on Kubernetes labels. This is distinct from `label` above, which holds a single CM-convention key naming the KMIP/ProtectApp client profile associated with the token.",
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM registration tokens list API. Supported keys: \"id\" (filter by token ID), \"token\" (filter by token value), \"label\" (filter by the token's label metadata, as a JSON value), and \"labels\" (filter by label selector expression, e.g. \"key1=value1,key2=value2\").",
			},
		},
	}
}

func (d *dataSourceRegTokens) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cm_reg_tokens.go -> Read][" + id + "]")
	defer d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cm_reg_tokens.go -> Read][" + id + "]")

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
			d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cm_reg_tokens.go -> Read][" + id + "]")
			resp.Diagnostics.AddError(
				"Unable to read reg tokens from CM",
				err.Error(),
			)
			return
		}

		rawTokens := gjson.Parse(jsonStr)
		if !rawTokens.IsArray() {
			d.client.Log.Debug(common.ERR_METHOD_END + "response is not a JSON array [data_source_cm_reg_tokens.go -> Read][" + id + "]")
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
