package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceCertificateAuthorities{}
	_ datasource.DataSourceWithConfigure = &dataSourceCertificateAuthorities{}
)

func NewDataSourceCertificateAuthorities() datasource.DataSource {
	return &dataSourceCertificateAuthorities{}
}

type dataSourceCertificateAuthorities struct {
	client *common.Client
}

type certificateAuthoritiesDataSourceModel struct {
	ID      types.String                             `tfsdk:"id"`
	Filters types.Map                                `tfsdk:"filters"`
	Limit   types.Int64                              `tfsdk:"limit"`
	Skip    types.Int64                              `tfsdk:"skip"`
	CAs     []CMCertificateAuthoritiesListModelTFSDK `tfsdk:"cas"`
}

func (d *dataSourceCertificateAuthorities) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_local_ca_list"
}

func (d *dataSourceCertificateAuthorities) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists local certificate authorities (CAs) on CipherTrust Manager via the /v1/ca/local-cas API.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Static identifier for this data source instance (always \"local-ca-list\").",
			},
			"cas": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of local CAs matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the local CA.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "A human readable unique identifier of the local CA.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the local CA.",
						},
						"state": schema.StringAttribute{
							Computed:    true,
							Description: "State of the local CA. One of \"pending\" or \"active\".",
						},
						"cert": schema.StringAttribute{
							Computed:    true,
							Description: "PEM-encoded certificate of the local CA. This is public certificate material.",
						},
						"serial_number": schema.StringAttribute{
							Computed:    true,
							Description: "Serial number of the local CA certificate.",
						},
						"subject": schema.StringAttribute{
							Computed:    true,
							Description: "Subject distinguished name of the local CA certificate.",
						},
						"issuer": schema.StringAttribute{
							Computed:    true,
							Description: "Issuer distinguished name of the local CA certificate.",
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM local CAs list API. Supported keys: \"id\" (filter by ID), \"subject\" (filter by subject), \"issuer\" (filter by issuer), \"state\" (filter by state; active or pending), and \"cert\" (filter by cert).",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of local CAs to return. Defaults to 1000.",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of local CAs to skip before returning results, for pagination. Defaults to 0.",
			},
		},
	}
}

func (d *dataSourceCertificateAuthorities) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cm_certificate_authorities.go -> Read][" + id + "]")
	var state certificateAuthoritiesDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string

	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			strVal, ok := v.(types.String)
			if !ok || strVal.IsNull() || strVal.IsUnknown() {
				resp.Diagnostics.AddError(
					"Invalid filters input",
					fmt.Sprintf("Key %q in filters has an invalid or unconfigured string value", k),
				)
				return
			}
			kv := fmt.Sprintf("%s=%s&", k, url.QueryEscape(strVal.ValueString()))
			kvs = append(kvs, kv)
		}
	}

	limitVal := int64(1000)
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		limitVal = state.Limit.ValueInt64()
	}
	skipVal := int64(0)
	if !state.Skip.IsNull() && !state.Skip.IsUnknown() {
		skipVal = state.Skip.ValueInt64()
	}

	jsonStr, total, err := d.client.GetAllWithTotal(ctx, id, fmt.Sprintf("%s/?%sskip=%d&limit=%d", common.URL_LOCAL_CA, strings.Join(kvs, ""), skipVal, limitVal))
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cm_certificate_authorities.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CAs from CM",
			err.Error(),
		)
		return
	}

	if total > limitVal {
		resp.Diagnostics.AddWarning(
			"Result Set Truncated",
			fmt.Sprintf("The server returned %d total local CAs, but only %d were retrieved due to the configured limit parameter. To retrieve more items, please increase the 'limit' attribute in your data source configuration.", total, limitVal),
		)
	}

	cas := []LocalCAsListModelJSON{}

	err = json.Unmarshal([]byte(jsonStr), &cas)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cm_certificate_authorities.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CAs from CM",
			err.Error(),
		)
		return
	}

	state.CAs = []CMCertificateAuthoritiesListModelTFSDK{}
	for _, ca := range cas {
		caState := CMCertificateAuthoritiesListModelTFSDK{
			ID:           types.StringValue(ca.ID),
			URI:          types.StringValue(ca.URI),
			Issuer:       types.StringValue(ca.Issuer),
			Cert:         types.StringValue(ca.Cert),
			SerialNumber: types.StringValue(ca.SerialNumber),
			State:        types.StringValue(ca.State),
			Subject:      types.StringValue(ca.Subject),
			Name:         types.StringValue(ca.Name),
		}

		state.CAs = append(state.CAs, caState)
	}

	state.ID = types.StringValue("local-ca-list")

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cm_certificate_authorities.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCertificateAuthorities) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
