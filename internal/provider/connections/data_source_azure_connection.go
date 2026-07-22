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
	_ datasource.DataSource              = &dataSourceAzureConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceAzureConnection{}
)

func NewDataSourceAzureConnection() datasource.DataSource {
	return &dataSourceAzureConnection{}
}

type dataSourceAzureConnection struct {
	client *common.Client
}

type AzureConnectionDataSourceModel struct {
	Filters types.Map              `tfsdk:"filters"`
	Azure   []AzureConnectionTFSDK `tfsdk:"azure"`
}

func (d *dataSourceAzureConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_connection_list"
}

func (d *dataSourceAzureConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"azure": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"client_id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"tenant_id": schema.StringAttribute{
							Computed: true,
						},
						"active_directory_endpoint": schema.StringAttribute{
							Computed: true,
						},
						"azure_stack_connection_type": schema.StringAttribute{
							Computed: true,
						},
						"azure_stack_server_cert": schema.StringAttribute{
							Computed: true,
						},
						"cert_duration": schema.Int64Attribute{
							Computed: true,
						},
						"certificate": schema.StringAttribute{
							Computed: true,
						},
						"client_secret": schema.StringAttribute{
							Computed: true,
						},
						"cloud_name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"external_certificate_used": schema.BoolAttribute{
							Computed: true,
						},
						"is_certificate_used": schema.BoolAttribute{
							Computed: true,
						},
						"key_vault_dns_suffix": schema.StringAttribute{
							Computed: true,
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"management_url": schema.StringAttribute{
							Computed: true,
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"products": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"resource_manager_url": schema.StringAttribute{
							Computed: true,
						},
						"vault_resource_url": schema.StringAttribute{
							Computed: true,
						},
						"certificate_thumbprint": schema.StringAttribute{
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

func (d *dataSourceAzureConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_azure_connection.go -> Read]["+id+"]")
	var state AzureConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
			kvs = append(kvs, kv)
		}
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_AZURE_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_azure_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read azure connection from CM",
			err.Error(),
		)
		return
	}

	azureConnections := []AzureConnectionJSON{}
	err = json.Unmarshal([]byte(jsonStr), &azureConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_azure_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read azure connection from CM",
			err.Error(),
		)
		return
	}

	for _, azure := range azureConnections {
		azureConn := AzureConnectionTFSDK{
			CMCreateConnectionResponseCommonTFSDK: CMCreateConnectionResponseCommonTFSDK{
				URI:                 types.StringValue(azure.URI),
				Account:             types.StringValue(azure.Account),
				CreatedAt:           types.StringValue(azure.CreatedAt),
				UpdatedAt:           types.StringValue(azure.UpdatedAt),
				Service:             types.StringValue(azure.Service),
				Category:            types.StringValue(azure.Category),
				ResourceURL:         types.StringValue(azure.ResourceURL),
				LastConnectionOK:    types.BoolValue(azure.LastConnectionOK),
				LastConnectionError: types.StringValue(azure.LastConnectionError),
				LastConnectionAt:    types.StringValue(azure.LastConnectionAt),
			},
			ID:                       types.StringValue(azure.ID),
			Name:                     types.StringValue(azure.Name),
			ClientID:                 types.StringValue(azure.ClientID),
			TenantID:                 types.StringValue(azure.TenantID),
			ActiveDirectoryEndpoint:  types.StringValue(azure.ActiveDirectoryEndpoint),
			AzureStackConnectionType: types.StringValue(azure.AzureStackConnectionType),
			AzureStackServerCert:     types.StringValue(azure.AzureStackServerCert),
			Certificate:              types.StringValue(azure.Certificate),
			CertificateThumbprint:    types.StringValue(azure.CertificateThumbprint),
			CloudName:                types.StringValue(azure.CloudName),
			Description:              types.StringValue(azure.Description),
			ExternalCertificateUsed:  types.BoolValue(azure.ExternalCertificateUsed),
			KeyVaultDNSSuffix:        types.StringValue(azure.KeyVaultDNSSuffix),
			ManagementURL:            types.StringValue(azure.ManagementURL),
			CertDuration:             types.Int64Value(azure.CertDuration),
			IsCertificateUsed:        types.BoolValue(azure.IsCertificateUsed),
			Products: func() types.List {
				var productValues []attr.Value
				for _, product := range azure.Products {
					productValues = append(productValues, types.StringValue(product))
				}
				listValue, _ := types.ListValue(types.StringType, productValues)
				return listValue
			}(),
			ResourceManagerURL: types.StringValue(azure.ResourceManagerURL),
			VaultResourceURL:   types.StringValue(azure.VaultResourceURL),
		}

		if azure.Labels != nil {
			labelsMap := make(map[string]attr.Value)
			for key, value := range azure.Labels {
				labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
			}
			mapVal, mapDiags := types.MapValue(types.StringType, labelsMap)
			resp.Diagnostics.Append(mapDiags...)
			azureConn.Labels = mapVal
		} else {
			azureConn.Labels = types.MapNull(types.StringType)
		}

		if azure.Meta != nil {
			metaMap := make(map[string]attr.Value)
			if m, ok := azure.Meta.(map[string]interface{}); ok {
				for key, value := range m {
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			mapVal, mapDiags := types.MapValue(types.StringType, metaMap)
			resp.Diagnostics.Append(mapDiags...)
			azureConn.Meta = mapVal
		} else {
			azureConn.Meta = types.MapNull(types.StringType)
		}

		state.Azure = append(state.Azure, azureConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_azure_connection.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceAzureConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
