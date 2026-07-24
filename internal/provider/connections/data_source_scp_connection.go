// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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
				Description: "Optional filters passed as query parameters to the CM SCP/SFTP connections list API. Supported keys: \"id\", \"name\", \"products\", \"meta_contains\", \"createdBefore\", \"createdAfter\", \"last_connection_ok\", \"last_connection_before\", \"last_connection_after\", \"protocol\", and \"labels\".",
			},
			"scp": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"auth_method": schema.StringAttribute{
							Computed:    true,
							Description: "Authentication type for SCP/SFTP server. Accepted values are 'key' or 'password'",
						},
						"host": schema.StringAttribute{
							Computed:    true,
							Description: "Hostname or FQDN of SCP/SFTP remote machine.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "(Immutable) Unique connection name.",
						},
						"path_to": schema.StringAttribute{
							Computed:    true,
							Description: "A path where the file to be copied via SCP/SFTP. Example '/home/ubuntu/datafolder/'",
						},
						"username": schema.StringAttribute{
							Computed:    true,
							Description: "Username for accessing SCP/SFTP server.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description about the connection.",
						},
						"port": schema.Int64Attribute{
							Computed:    true,
							Description: "Port where SCP/SFTP service runs on host (usually 22).",
						},
						"products": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: productsDescription,
						},
						"protocol": schema.StringAttribute{
							Computed:    true,
							Description: "Use 'sftp' or 'scp'. 'sftp' is the default value",
						},
						"password": schema.StringAttribute{
							Computed:    true,
							Sensitive:   true,
							Description: "Password for SCP/SFTP server. CM never returns this field on GET, so it is not populated by this data source.",
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
						"public_key": schema.StringAttribute{
							Computed:    true,
							Description: "Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.",
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
	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
			kvs = append(kvs, kv)
		}
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
			labelsMap := make(map[string]attr.Value)
			for key, value := range scp.Labels {
				labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
			}
			mapVal, mapDiags := types.MapValue(types.StringType, labelsMap)
			resp.Diagnostics.Append(mapDiags...)
			scpConn.Labels = mapVal
		} else {
			scpConn.Labels = types.MapNull(types.StringType)
		}

		if scp.Meta != nil {
			metaMap := make(map[string]attr.Value)
			if m, ok := scp.Meta.(map[string]interface{}); ok {
				for key, value := range m {
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			mapVal, mapDiags := types.MapValue(types.StringType, metaMap)
			resp.Diagnostics.Append(mapDiags...)
			scpConn.Meta = mapVal
		} else {
			scpConn.Meta = types.MapNull(types.StringType)
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
