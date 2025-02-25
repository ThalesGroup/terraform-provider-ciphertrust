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

var (
	_ datasource.DataSource              = &dataSourceGCPConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceGCPConnection{}
)

func NewDataSourceGCPConnection() datasource.DataSource {
	return &dataSourceGCPConnection{}
}

type dataSourceGCPConnection struct {
	client *common.Client
}

type GCPConnectionDataSourceModel struct {
	Filters types.Map            `tfsdk:"filters"`
	Gcp     []GCPConnectionTFSDK `tfsdk:"gcp"`
}

func (d *dataSourceGCPConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcp_connection_list"
}

func (d *dataSourceGCPConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"gcp": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"key_file": schema.StringAttribute{
							Computed: true,
						},
						"cloud_name": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"products": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"client_email": schema.StringAttribute{
							Computed: true,
						},
						"private_key_id": schema.StringAttribute{
							Computed: true,
						},
						//common response parameters (optional)
						"uri":                   schema.StringAttribute{Computed: true},
						"account":               schema.StringAttribute{Computed: true},
						"created_at":            schema.StringAttribute{Computed: true},
						"updated_at":            schema.StringAttribute{Computed: true},
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

func (d *dataSourceGCPConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_gcp_connection.go -> Read]["+id+"]")
	var state GCPConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_GCP_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_gcp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read gcp connection from CM",
			err.Error(),
		)
		return
	}

	gcpConnections := []GCPConnectionJSON{}
	err = json.Unmarshal([]byte(jsonStr), &gcpConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_gcp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read gcp connection from CM",
			err.Error(),
		)
		return
	}

	for _, gcp := range gcpConnections {
		gcpConn := GCPConnectionTFSDK{
			CMCreateConnectionResponseCommonTFSDK: CMCreateConnectionResponseCommonTFSDK{
				URI:                 types.StringValue(gcp.URI),
				Account:             types.StringValue(gcp.Account),
				CreatedAt:           types.StringValue(gcp.CreatedAt),
				UpdatedAt:           types.StringValue(gcp.UpdatedAt),
				Service:             types.StringValue(gcp.Service),
				Category:            types.StringValue(gcp.Category),
				ResourceURL:         types.StringValue(gcp.ResourceURL),
				LastConnectionOK:    types.BoolValue(gcp.LastConnectionOK),
				LastConnectionError: types.StringValue(gcp.LastConnectionError),
				LastConnectionAt:    types.StringValue(gcp.LastConnectionAt),
			},
			ID:   types.StringValue(gcp.ID),
			Name: types.StringValue(gcp.Name),
			Products: func() types.List {
				var productValues []attr.Value
				for _, product := range gcp.Products {
					productValues = append(productValues, types.StringValue(product))
				}
				listValue, _ := types.ListValue(types.StringType, productValues)
				return listValue
			}(),
			Description:  types.StringValue(gcp.Description),
			CloudName:    types.StringValue(gcp.CloudName),
			KeyFile:      types.StringValue(gcp.KeyFile),
			ClientEmail:  types.StringValue(gcp.ClientEmail),
			PrivateKeyID: types.StringValue(gcp.PrivateKeyID),
		}

		if gcp.Labels != nil {
			// Create the map to store attr.Value
			labelsMap := make(map[string]attr.Value)
			for key, value := range gcp.Labels {
				// Ensure value is a string and handle if it's not
				if strVal, ok := value.(string); ok {
					labelsMap[key] = types.StringValue(strVal) // types.String is an attr.Value
				} else {
					// If not a string, set a default or skip the key-value pair
					labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			// Set labels as a MapValue
			gcpConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		} else {
			// If Labels are missing, assign an empty map
			labelsMap := make(map[string]attr.Value)
			gcpConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		}

		if gcp.Meta != nil {
			// Create the map to store attr.Value for Meta
			metaMap := make(map[string]attr.Value)
			for key, value := range gcp.Meta.(map[string]interface{}) {
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
			gcpConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		} else {
			// If Meta is missing, assign an empty map
			metaMap := make(map[string]attr.Value)
			gcpConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		}

		state.Gcp = append(state.Gcp, gcpConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_gcp_connection.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceGCPConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
