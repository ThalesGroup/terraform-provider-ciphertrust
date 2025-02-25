package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceScpConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceScpConnection{}
)

func NewDataSourceScpConnection() datasource.DataSource {
	return &dataSourceScpConnection{}
}

type dataSourceScpConnection struct {
	client *common.Client
}

type ScpConnectionDataSourceModel struct {
	Filters types.Map              `tfsdk:"filters"`
	Scp     []CMScpConnectionTFSDK `tfsdk:"scp"`
}

func (d *dataSourceScpConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scp_connection_list"
}

func (d *dataSourceScpConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"scp": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"auth_method": schema.StringAttribute{
							Computed: true,
						},
						"host": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"path_to": schema.StringAttribute{
							Computed: true,
						},
						"username": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"port": schema.Int64Attribute{
							Computed: true,
						},
						"products": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"protocol": schema.StringAttribute{
							Computed: true,
						},
						"password": schema.StringAttribute{
							Computed: true,
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"public_key": schema.StringAttribute{
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

func (d *dataSourceScpConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_scp_connection.go -> Read]["+id+"]")
	var state ScpConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_SCP_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_scp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scp connection from CM",
			err.Error(),
		)
		return
	}

	scpConnections := []CMScpConnectionJSON{}

	err = json.Unmarshal([]byte(jsonStr), &scpConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_scp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scp connection from CM",
			err.Error(),
		)
		return
	}

	for _, scp := range scpConnections {
		scpConn := CMScpConnectionTFSDK{
			CMCreateConnectionResponseCommonTFSDK: CMCreateConnectionResponseCommonTFSDK{
				URI:                 types.StringValue(scp.URI),
				Account:             types.StringValue(scp.Account),
				CreatedAt:           types.StringValue(scp.CreatedAt),
				UpdatedAt:           types.StringValue(scp.UpdatedAt),
				Service:             types.StringValue(scp.Service),
				Category:            types.StringValue(scp.Category),
				ResourceURL:         types.StringValue(scp.ResourceURL),
				LastConnectionOK:    types.BoolValue(scp.LastConnectionOK),
				LastConnectionError: types.StringValue(scp.LastConnectionError),
				LastConnectionAt:    types.StringValue(scp.LastConnectionAt),
			},
			ID:   types.StringValue(scp.ID),
			Name: types.StringValue(scp.Name),
			Products: func() types.List {
				var productValues []attr.Value
				for _, product := range scp.Products {
					productValues = append(productValues, types.StringValue(product))
				}
				listValue, _ := types.ListValue(types.StringType, productValues) // Create a ListValue
				return listValue
			}(),
			Description: types.StringValue(scp.Description),
			Host:        types.StringValue(scp.Host),
			Port:        types.Int64Value(scp.Port),
			Username:    types.StringValue(scp.Username),
			AuthMethod:  types.StringValue(scp.AuthMethod),
			PathTo:      types.StringValue(scp.PathTo),
			Protocol:    types.StringValue(scp.Protocol),
			PublicKey:   types.StringValue(scp.PublicKey),
		}

		if scp.Labels != nil {
			// Create the map to store attr.Value
			labelsMap := make(map[string]attr.Value)
			for key, value := range scp.Labels {
				// Ensure value is a string and handle if it's not
				if strVal, ok := value.(string); ok {
					labelsMap[key] = types.StringValue(strVal) // types.String is an attr.Value
				} else {
					// If not a string, set a default or skip the key-value pair
					labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			// Set labels as a MapValue
			scpConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		} else {
			// If Labels are missing, assign an empty map
			labelsMap := make(map[string]attr.Value)
			scpConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		}

		if scp.Meta != nil {
			// Create the map to store attr.Value for Meta
			metaMap := make(map[string]attr.Value)
			for key, value := range scp.Meta.(map[string]interface{}) {
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
			scpConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		} else {
			// If Meta is missing, assign an empty map
			metaMap := make(map[string]attr.Value)
			scpConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		}

		state.Scp = append(state.Scp, scpConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_scp_connection.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceScpConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
