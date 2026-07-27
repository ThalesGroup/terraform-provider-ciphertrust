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
				Description: "Optional filters passed as query parameters to the CM GCP connections list API. Supported keys: \"id\", \"name\", \"products\", \"meta_contains\", \"cloud_name\", \"createdBefore\", \"createdAfter\", \"last_connection_ok\", \"last_connection_before\", \"last_connection_after\", and \"labels\".",
			},
			"gcp": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"key_file": schema.StringAttribute{
							Computed:    true,
							Sensitive:   true,
							Description: "The private key JSON file of a Google Cloud Platform (GCP) service account can be provided either as a JSON file or as a string. CM never returns this field on GET, so it is not populated by this data source.",
						},
						"key_file_version": schema.Int64Attribute{
							Computed:    true,
							Description: "Not populated by this data source — key_file is write-only and resource-only.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the cloud. Default value is gcp.\n\nOptions:\n\ngcp",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "(Immutable) Unique connection name.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description about the connection.",
						},
						"products": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: productsDescription,
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: labelsDescription,
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Optional end-user or service data stored with the connection.",
						},
						"client_email": schema.StringAttribute{
							Computed:    true,
							Description: "The GCP service account email address associated with the key file.",
						},
						"private_key_id": schema.StringAttribute{
							Computed:    true,
							Sensitive:   true,
							Description: "Private key ID is a unique ID corresponding to a private key.",
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
	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
			kvs = append(kvs, kv)
		}
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
			Description:    types.StringValue(gcp.Description),
			CloudName:      types.StringValue(gcp.CloudName),
			KeyFile:        types.StringValue(gcp.KeyFile),
			KeyFileVersion: types.Int64Null(),
			ClientEmail:    types.StringValue(gcp.ClientEmail),
			PrivateKeyID:   types.StringValue(gcp.PrivateKeyID),
		}

		if gcp.Labels != nil {
			labelsMap := make(map[string]attr.Value)
			for key, value := range gcp.Labels {
				labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
			}
			mapVal, mapDiags := types.MapValue(types.StringType, labelsMap)
			resp.Diagnostics.Append(mapDiags...)
			gcpConn.Labels = mapVal
		} else {
			gcpConn.Labels = types.MapNull(types.StringType)
		}

		if gcp.Meta != nil {
			metaMap := make(map[string]attr.Value)
			if m, ok := gcp.Meta.(map[string]interface{}); ok {
				for key, value := range m {
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			mapVal, mapDiags := types.MapValue(types.StringType, metaMap)
			resp.Diagnostics.Append(mapDiags...)
			gcpConn.Meta = mapVal
		} else {
			gcpConn.Meta = types.MapNull(types.StringType)
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
