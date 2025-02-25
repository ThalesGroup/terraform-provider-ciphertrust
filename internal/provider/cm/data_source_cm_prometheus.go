package cm

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourcePrometheus{}
	_ datasource.DataSourceWithConfigure = &dataSourcePrometheus{}
)

func NewDataSourcePrometheus() datasource.DataSource {
	return &dataSourcePrometheus{}
}

type dataSourcePrometheus struct {
	client *common.Client
}

func (d *dataSourcePrometheus) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_prometheus_status"
}

func (d *dataSourcePrometheus) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"token": schema.StringAttribute{
				Computed: true,
			},
			"enabled": schema.BoolAttribute{
				Computed: true,
			},
		},
	}
}

func (d *dataSourcePrometheus) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_prometheus.go -> Read]["+id+"]")

	response, err := d.client.ReadDataByParam(ctx, id, "all", common.URL_PROMETHEUS_STATUS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_prometheus.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Read Error", "Error fetching Prometheus status: "+err.Error())
		return
	}

	state := &CMPrometheusMetricsConfigTFSDK{
		Enabled: types.BoolValue(gjson.Get(response, "enabled").Bool()),
		Token:   types.StringValue(gjson.Get(response, "token").String()),
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_prometheus.go -> Read]["+id+"]")

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourcePrometheus) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
