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
	Filters types.Map                                `tfsdk:"filters"`
	CAs     []CMCertificateAuthoritiesListModelTFSDK `tfsdk:"cas"`
}

func (d *dataSourceCertificateAuthorities) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_local_ca_list"
}

func (d *dataSourceCertificateAuthorities) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"cas": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"state": schema.StringAttribute{
							Computed: true,
						},
						"cert": schema.StringAttribute{
							Computed: true,
						},
						"serial_number": schema.StringAttribute{
							Computed: true,
						},
						"subject": schema.StringAttribute{
							Computed: true,
						},
						"issuer": schema.StringAttribute{
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

func (d *dataSourceCertificateAuthorities) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_certificate_authorities.go -> Read]["+id+"]")
	var state certificateAuthoritiesDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_LOCAL_CA+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_certificate_authorities.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CAs from CM",
			err.Error(),
		)
		return
	}

	cas := []LocalCAsListModelJSON{}

	err = json.Unmarshal([]byte(jsonStr), &cas)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_certificate_authorities.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CAs from CM",
			err.Error(),
		)
		return
	}

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

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_certificate_authorities.go -> Read]["+id+"]")
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
