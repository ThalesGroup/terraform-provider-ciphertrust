package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type OCIConnectionDataSourceJSON struct {
	CMCreateConnectionResponseCommon
	OCIConnectionCommonJSON
	Name     string   `json:"name"`
	Products []string `json:"products"`
	ID       string   `json:"id"`
}

var (
	_ datasource.DataSource                     = &dataSourceOCIConnection{}
	_ datasource.DataSourceWithConfigure        = &dataSourceOCIConnection{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceOCIConnection{}

	ociConnectionValidFilterKeys = map[string]struct{}{
		"id": {}, "name": {}, "products": {}, "meta_contains": {},
		"createdBefore": {}, "createdAfter": {}, "last_connection_ok": {},
		"last_connection_before": {}, "last_connection_after": {},
	}
)

func NewDataSourceOCIConnection() datasource.DataSource {
	return &dataSourceOCIConnection{}
}

type dataSourceOCIConnection struct {
	client *common.Client
}

type OCIConnectionDataSourceModel struct {
	Filters types.Map                  `tfsdk:"filters"`
	Oci     []OCIConnectionCommonTFSDK `tfsdk:"oci"`
}

func (d *dataSourceOCIConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_connection_list"
}

// ConfigValidators rejects unrecognized filter keys at plan time (TFIN-570).
func (d *dataSourceOCIConnection) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{ociConnectionFilterValidator{}}
}

type ociConnectionFilterValidator struct{}

func (v ociConnectionFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are recognized CM API parameters."
}
func (v ociConnectionFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v ociConnectionFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config OCIConnectionDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	for k := range config.Filters.Elements() {
		if _, ok := ociConnectionValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key for ciphertrust_oci_connection_list. "+
					"CM silently ignores unknown keys and returns the full unfiltered list.", k),
			)
		}
	}
}

func (d *dataSourceOCIConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM OCI connections list API. Supported keys: \"id\", \"name\", \"products\", \"meta_contains\", \"createdBefore\", \"createdAfter\", \"last_connection_ok\", \"last_connection_before\", and \"last_connection_after\".",
			},
			"oci": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the connection was created.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description about the connection.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the connection.",
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Optional end-user or service data stored with the connection.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Connection name.",
						},
						"pub_key_fingerprint": schema.StringAttribute{
							Computed:    true,
							Description: "Fingerprint of the public key added to the OCI user.",
						},
						"products": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Array of the CipherTrust products associated with the connection. Default is 'cckm'.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "OCI region.",
						},
						"tenancy_ocid": schema.StringAttribute{
							Computed:    true,
							Description: "Tenancy OCID.",
						},
						"user_ocid": schema.StringAttribute{
							Computed:    true,
							Description: "User OCID.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time of last update.",
						},
						// Common response parameters.
						"uri":                   schema.StringAttribute{Computed: true},
						"account":               schema.StringAttribute{Computed: true},
						"service":               schema.StringAttribute{Computed: true},
						"category":              schema.StringAttribute{Computed: true},
						"resource_url":          schema.StringAttribute{Computed: true},
						"last_connection_ok":    schema.BoolAttribute{Computed: true},
						"last_connection_error": schema.StringAttribute{Computed: true},
						"last_connection_at":    schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *dataSourceOCIConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_oci_connection.go -> Read][" + id + "]")
	var state OCIConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
			kvs = append(kvs, kv)
		}
	}

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_OCI_CONNECTION+"/?"+strings.Join(kvs, ""))
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read oci connection from CM",
			err.Error(),
		)
		return
	}

	if jsonStr == "" {
		jsonStr = "[]"
	}

	var ociConnections []OCIConnectionDataSourceJSON
	err = json.Unmarshal([]byte(jsonStr), &ociConnections)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read oci connection from CM",
			err.Error(),
		)
		return
	}

	// Initialize to non-nil empty slice so zero-match filters return [] not null (TFIN-570).
	state.Oci = []OCIConnectionCommonTFSDK{}
	for _, oci := range ociConnections {
		ociConn := OCIConnectionCommonTFSDK{
			CMCreateConnectionResponseCommonTFSDK: CMCreateConnectionResponseCommonTFSDK{
				URI:                 types.StringValue(oci.URI),
				Account:             types.StringValue(oci.Account),
				CreatedAt:           types.StringValue(oci.CreatedAt),
				UpdatedAt:           types.StringValue(oci.UpdatedAt),
				Service:             types.StringValue(oci.Service),
				Category:            types.StringValue(oci.Category),
				ResourceURL:         types.StringValue(oci.ResourceURL),
				LastConnectionOK:    types.BoolValue(oci.LastConnectionOK),
				LastConnectionError: types.StringValue(oci.LastConnectionError),
				LastConnectionAt:    types.StringValue(oci.LastConnectionAt),
			},
			ID:   types.StringValue(oci.ID),
			Name: types.StringValue(oci.Name),
			Products: func() types.List {
				var productValues []attr.Value
				for _, product := range oci.Products {
					productValues = append(productValues, types.StringValue(product))
				}
				listValue, _ := types.ListValue(types.StringType, productValues)
				return listValue
			}(),
			Description: types.StringValue(oci.Description),
			TenancyOcid: types.StringValue(oci.TenancyOCID),
			UserOcid:    types.StringValue(oci.UserOCID),
			Fingerprint: types.StringValue(oci.Fingerprint),
			Region:      types.StringValue(oci.Region),
		}

		if oci.Meta != nil {
			metaMap := make(map[string]attr.Value)
			if m, ok := oci.Meta.(map[string]interface{}); ok {
				for key, value := range m {
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			mapVal, mapDiags := types.MapValue(types.StringType, metaMap)
			resp.Diagnostics.Append(mapDiags...)
			ociConn.Meta = mapVal
		} else {
			ociConn.Meta = types.MapNull(types.StringType)
		}
		state.Oci = append(state.Oci, ociConn)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_oci_connection.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (d *dataSourceOCIConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
