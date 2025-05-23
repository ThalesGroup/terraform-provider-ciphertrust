package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceGetOCIRegions{}
	_ datasource.DataSourceWithConfigure = &dataSourceGetOCIRegions{}
)

func NewDataSourceGetOCIRegions() datasource.DataSource {
	return &dataSourceGetOCIRegions{}
}

func (d *dataSourceGetOCIRegions) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceGetOCIRegions struct {
	client *common.Client
}

func (d *dataSourceGetOCIRegions) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_get_oci_regions"
}

func (d *dataSourceGetOCIRegions) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI regions available to the connection.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection name or ID.",
			},
			"regions": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "A list of regions available to the connection.",
			},
		},
	}
}

func (d *dataSourceGetOCIRegions) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_regions.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_regions.go -> Read]")

	id := uuid.New().String()
	var state GetOCIRegionsDataSourceTFSDK
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	connection := state.Connection.ValueString()
	payload := GetOCIRegionsPayloadJSON{
		Connection: connection,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI regions, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": connection})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/get-subscribed-regions", payloadJSON)
	if err != nil {
		msg := "Error reading OCI regions."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": connection})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	state.Regions = utils.StringSliceJSONToListValue(gjson.Get(response, "regions").Array(), &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}
