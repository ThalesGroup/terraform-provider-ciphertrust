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
				Description: "List of clients matching the given filters.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the client.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the client.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the client.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application associated with the client.",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the client.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the client was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the client was last updated.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the client.",
							Computed:    true,
						},
						"os_type": schema.StringAttribute{
							Description: "OS type of the client.",
							Computed:    true,
						},
						"os_sub_type": schema.StringAttribute{
							Description: "OS sub-type of the client.",
							Computed:    true,
						},
						"client_reg_id": schema.StringAttribute{
							Description: "Registration ID of the client.",
							Computed:    true,
						},
						"server_host_name": schema.StringAttribute{
							Description: "Hostname of the CipherTrust Manager the client is registered to.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the client.",
							Computed:    true,
						},
						"client_locked": schema.BoolAttribute{
							Description: "Whether the client is locked. If enabled, this client will not be updated by the CipherTrust Manager.",
							Computed:    true,
						},
						"system_locked": schema.BoolAttribute{
							Description: "Whether the system is locked. If enabled, GuardPoints on this client cannot be removed.",
							Computed:    true,
						},
						"password_creation_method": schema.StringAttribute{
							Description: "Password creation method of the client, MANUAL or GENERATE.",
							Computed:    true,
						},
						"client_version": schema.StringAttribute{
							Description: "Version of the CTE agent installed on the client.",
							Computed:    true,
						},
						"registration_allowed": schema.BoolAttribute{
							Description: "Whether client's registration with the CipherTrust Manager is allowed.",
							Computed:    true,
						},
						"communication_enabled": schema.BoolAttribute{
							Description: "Whether communication with the client is enabled.",
							Computed:    true,
						},
						"capabilities": schema.StringAttribute{
							Description: "Capabilities of the client.",
							Computed:    true,
						},
						"enabled_capabilities": schema.StringAttribute{
							Description: "Comma-separated list of enabled capabilities on the client such as ldt, dar (data at rest) and dsm (data security manager).",
							Computed:    true,
						},
						"protection_mode": schema.StringAttribute{
							Description: "Protection mode of the client, online or offline.",
							Computed:    true,
						},
						"client_type": schema.StringAttribute{
							Description: "Type of the client, FS (FileSystem) or CTE-U (CTE for user spaces).",
							Computed:    true,
						},
						"profile_name": schema.StringAttribute{
							Description: "Name of the client profile associated with the client.",
							Computed:    true,
						},
						"profile_id": schema.StringAttribute{
							Description: "ID of the client profile associated with the client.",
							Computed:    true,
						},
						"ldt_enabled": schema.BoolAttribute{
							Description: "Whether LDT (Live Data Transformation) is enabled on the client.",
							Computed:    true,
						},
						"client_health_status": schema.StringAttribute{
							Description: "Health status of the client.",
							Computed:    true,
						},
						"errors": schema.StringAttribute{
							Description: "Errors reported by the client.",
							Computed:    true,
						},
						"warnings": schema.StringAttribute{
							Description: "Warnings reported by the client.",
							Computed:    true,
						},
						"client_errors": schema.StringAttribute{
							Description: "Client-specific errors reported by the client.",
							Computed:    true,
						},
						"client_warnings": schema.StringAttribute{
							Description: "Client-specific warnings reported by the client.",
							Computed:    true,
						},
						"fam_enabled": schema.BoolAttribute{
							Description: "Whether FAM (File Access Manager) is enabled on the client.",
							Computed:    true,
						},
						"fam_state": schema.StringAttribute{
							Description: "State of FAM (File Access Manager) on the client.",
							Computed:    true,
						},
						"dps_enabled": schema.BoolAttribute{
							Description: "Whether designated primary set is enabled on the client.",
							Computed:    true,
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				Description: "A map of key:value pairs matching CipherTrust Manager API query parameters for filtering the clients list, e.g. \"name\". Values containing commas are split and applied as repeated filters.",
				ElementType: types.StringType,
				Optional:    true,
			},
		},
	}
}

func (d *dataSourceCTEClients) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_clients.go -> Read][" + id + "]")
	var state CTEClientsDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		filterVal := v.(types.String).ValueString()
		// Support comma-separated values for multiple filters
		if strings.Contains(filterVal, ",") {
			values := strings.Split(filterVal, ",")
			for _, val := range values {
				kv := fmt.Sprintf("%s=%s&", k, strings.TrimSpace(val))
				kvs = append(kvs, kv)
			}
		} else {
			kv := fmt.Sprintf("%s=%s&", k, filterVal)
			kvs = append(kvs, kv)
		}
	}

	jsonStr, err := d.client.GetAllPaged(
		ctx,
		id,
		common.URL_CTE_CLIENT+"/?"+strings.Join(kvs, ""))

	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_clients.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Clients from CM",
			err.Error(),
		)
		return
	}

	clients := []CTEClientsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &clients)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_clients.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Clients from CM",
			err.Error(),
		)
		return
	}

	for _, client := range clients {

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
		clientState.ClientVersion = types.StringValue(client.ClientVersion)
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
		clientState.Errors = types.StringValue(client.Errors)
		clientState.Warnings = types.StringValue(client.Warnings)
		clientState.ClientErrors = types.StringValue(client.ClientErrors)
		clientState.ClientWarnings = types.StringValue(client.ClientWarnings)
		clientState.FamEnabled = types.BoolValue(client.FamEnabled)
		clientState.FamState = types.StringValue(client.FamState)
		clientState.DPS_Enabled = types.BoolValue(client.DPS_Enabled)
		state.Clients = append(state.Clients, clientState)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_clients.go -> Read][" + id + "]")
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
