package cte

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
	_ datasource.DataSource              = &dataSourceCTEClients{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEClients{}
)

func NewDataSourceCTEClients() datasource.DataSource {
	return &dataSourceCTEClients{}
}

type dataSourceCTEClients struct {
	client *common.Client
}

type CTEClientsDataSourceModel struct {
	Filters types.Map             `tfsdk:"filters"`
	Clients []CTEClientsListTFSDK `tfsdk:"clients"`
}

func (d *dataSourceCTEClients) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_clients_list"
}

func (d *dataSourceCTEClients) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"clients": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
							Computed: true,
						},
						"application": schema.StringAttribute{
							Computed: true,
						},
						"dev_account": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"os_type": schema.StringAttribute{
							Computed: true,
						},
						"os_sub_type": schema.StringAttribute{
							Computed: true,
						},
						"client_reg_id": schema.StringAttribute{
							Computed: true,
						},
						"server_host_name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"client_locked": schema.BoolAttribute{
							Computed: true,
						},
						"system_locked": schema.BoolAttribute{
							Computed: true,
						},
						"password_creation_method": schema.StringAttribute{
							Computed: true,
						},
						"client_version": schema.Int64Attribute{
							Computed: true,
						},
						"registration_allowed": schema.BoolAttribute{
							Computed: true,
						},
						"communication_enabled": schema.BoolAttribute{
							Computed: true,
						},
						"capabilities": schema.StringAttribute{
							Computed: true,
						},
						"enabled_capabilities": schema.StringAttribute{
							Computed: true,
						},
						"protection_mode": schema.StringAttribute{
							Computed: true,
						},
						"client_type": schema.StringAttribute{
							Computed: true,
						},
						"profile_name": schema.StringAttribute{
							Computed: true,
						},
						"profile_id": schema.StringAttribute{
							Computed: true,
						},
						"ldt_enabled": schema.BoolAttribute{
							Computed: true,
						},
						"client_health_status": schema.StringAttribute{
							Computed: true,
						},
						"errors": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"warnings": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"client_errors": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"client_warnings": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
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

func (d *dataSourceCTEClients) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_clients.go -> Read]["+id+"]")
	var state CTEClientsDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_CTE_CLIENT+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")

	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_clients.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Clients from CM",
			err.Error(),
		)
		return
	}

	clients := []CTEClientsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &clients)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_clients.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Clients from CM",
			err.Error(),
		)
		return
	}

	for _, client := range clients {
		var errs []types.String
		var warnings []types.String
		var clientErrs []types.String
		var clientWarnings []types.String

		clientState := CTEClientsListTFSDK{}
		clientState.ID = types.StringValue(client.ID)
		clientState.URI = types.StringValue(client.URI)
		clientState.Account = types.StringValue(client.Account)
		clientState.App = types.StringValue(client.App)
		clientState.DevAccount = types.StringValue(client.DevAccount)
		clientState.CreatedAt = types.StringValue(client.CreatedAt)
		clientState.UpdatedAt = types.StringValue(client.UpdatedAt)
		clientState.Name = types.StringValue(client.Name)
		clientState.OSType = types.StringValue(client.OSType)
		clientState.OSSubType = types.StringValue(client.OSSubType)
		clientState.ClientRegID = types.StringValue(client.ClientRegID)
		clientState.ServerHostname = types.StringValue(client.ServerHostname)
		clientState.Description = types.StringValue(client.Description)
		clientState.ClientLocked = types.BoolValue(client.ClientLocked)
		clientState.SystemLocked = types.BoolValue(client.SystemLocked)
		clientState.PasswordCreationMethod = types.StringValue(client.PasswordCreationMethod)
		clientState.ClientVersion = types.Int64Value(client.ClientVersion)
		clientState.RegistrationAllowed = types.BoolValue(client.RegistrationAllowed)
		clientState.CommunicationEnabled = types.BoolValue(client.CommunicationEnabled)
		clientState.Capabilities = types.StringValue(client.Capabilities)
		clientState.EnabledCapabilities = types.StringValue(client.EnabledCapabilities)
		clientState.ProtectionMode = types.StringValue(client.ProtectionMode)
		clientState.ClientType = types.StringValue(client.ClientType)
		clientState.ProfileName = types.StringValue(client.ProfileName)
		clientState.ProfileID = types.StringValue(client.ProfileID)
		clientState.LDTEnabled = types.BoolValue(client.LDTEnabled)
		clientState.ClientHealthStatus = types.StringValue(client.ClientHealthStatus)

		for _, err := range client.Errors {
			errs = append(errs, types.StringValue(err))
		}
		clientState.Errors = errs
		for _, warning := range client.Warnings {
			warnings = append(warnings, types.StringValue(warning))
		}
		clientState.Warnings = warnings
		for _, clientErr := range client.ClientErrors {
			clientErrs = append(clientErrs, types.StringValue(clientErr))
		}
		clientState.ClientErrors = clientErrs
		for _, clientWarning := range client.ClientWarnings {
			clientWarnings = append(clientWarnings, types.StringValue(clientWarning))
		}
		clientState.ClientWarnings = clientWarnings

		state.Clients = append(state.Clients, clientState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_clients.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEClients) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
