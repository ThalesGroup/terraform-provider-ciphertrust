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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type OCIConnectionDataSourceJSON struct {
	CMCreateConnectionResponseCommon
	OCIConnectionCommonJSON
	Name     string   `json:"name"`
	Products []string `json:"products"`
	ID       string   `json:"id"`
}

var (
	_ datasource.DataSource              = &dataSourceOCIConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCIConnection{}
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

func (d *dataSourceOCIConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
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
							Optional:    true,
							Description: "Description about the connection",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the connection.",
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Optional:    true,
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
						//common response parameters (optional)
						"uri":                   schema.StringAttribute{Computed: true},
						"account":               schema.StringAttribute{Computed: true},
						"service":               schema.StringAttribute{Computed: true},
						"category":              schema.StringAttribute{Computed: true},
						"resource_url":          schema.StringAttribute{Computed: true},
						"last_connection_ok":    schema.BoolAttribute{Computed: true},
						"last_connection_error": schema.StringAttribute{Computed: true},
						"last_connection_at":    schema.StringAttribute{Computed: true}},
				},
			},
		},
	}
}

func (d *dataSourceOCIConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_connection.go -> Read]["+id+"]")
	var state OCIConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_OCI_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read oci connection from CM",
			err.Error(),
		)
		return
	}

	var ociConnections []OCIConnectionDataSourceJSON
	err = json.Unmarshal([]byte(jsonStr), &ociConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read oci connection from CM",
			err.Error(),
		)
		return
	}

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
			// Create the map to store attr.Value for Meta
			metaMap := make(map[string]attr.Value)
			for key, value := range oci.Meta.(map[string]interface{}) {
				// Convert each value in meta to the corresponding attr.Value
				switch v := value.(type) {
				case string:
					metaMap[key] = types.StringValue(v)
				case int64:
					metaMap[key] = types.Int64Value(v)
				case bool:
					metaMap[key] = types.BoolValue(v)
				default:
					// For unknown types, convert them to a string representation
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", v))
				}
			}
			ociConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		} else {
			// If Meta is missing, assign an empty map
			metaMap := make(map[string]attr.Value)
			ociConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		}
		state.Oci = append(state.Oci, ociConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_connection.go -> Read]["+id+"]")
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
