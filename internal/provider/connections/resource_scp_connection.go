package connections

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMScpConnection{}
	_ resource.ResourceWithConfigure = &resourceCMScpConnection{}

	labelsDescription = `Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.

To add a label, set the label's value as follows.

    "labels": {
      "key1": "value1",
      "key2": "value2"
    }

To remove a key/value pair, pass value null to the particular key

    "labels": {
      "key1": null
    }
`

	productsDescription = `Array of the CipherTrust products associated with the connection. Valid values are:

    "cckm" for:
        AWS
        Azure
        GCP
        Luna connections
        DSM
        Salesforce
        SAP Data Custodian
    "ddc" for:
        GCP
        Hadoop connections
    "cte" for:
        Hadoop connections
        SMB
        OIDC
        LDAP connections
    "data discovery" for Hadoop connections.
    "backup/restore" for SCP/SFTP connections.
    "logger" for:
        loki connections
        elasticsearch connections
        syslog connections
    "hsm_anchored_domain" for:
        Luna connections
    "csm" for:
        Akeyless connections
`
)

func NewResourceCMScpConnection() resource.Resource {
	return &resourceCMScpConnection{}
}

type resourceCMScpConnection struct {
	client *common.Client
}

func (r *resourceCMScpConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scp_connection"
}

// Schema defines the schema for the resource.
func (r *resourceCMScpConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"auth_method": schema.StringAttribute{
				Required:    true,
				Description: "Authentication type for SCP/SFTP server. Accepted values are 'key' or 'password'",
			},
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Hostname or FQDN of SCP/SFTP remote machine.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique connection name.",
			},
			"path_to": schema.StringAttribute{
				Required:    true,
				Description: "A path where the file to be copied via SCP/SFTP. Example '/home/ubuntu/datafolder/'",
			},
			"public_key": schema.StringAttribute{
				Required:    true,
				Description: "Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.",
			},
			"username": schema.StringAttribute{
				Required:    true,
				Description: "Username for accessing SCP/SFTP server.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: labelsDescription,
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Description: "Password for SCP/SFTP server.",
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Port where SCP/SFTP service runs on host (usually 22).",
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: productsDescription,
			},
			"protocol": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Use 'sftp' or 'scp'. 'sftp' is the default value",
			},
			//common response parameters (optional)
			"uri":                   schema.StringAttribute{Computed: true, Optional: true},
			"account":               schema.StringAttribute{Computed: true, Optional: true},
			"created_at":            schema.StringAttribute{Computed: true, Optional: true},
			"updated_at":            schema.StringAttribute{Computed: true, Optional: true},
			"service":               schema.StringAttribute{Computed: true, Optional: true},
			"category":              schema.StringAttribute{Computed: true, Optional: true},
			"resource_url":          schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_ok":    schema.BoolAttribute{Computed: true, Optional: true},
			"last_connection_error": schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_at":    schema.StringAttribute{Computed: true, Optional: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMScpConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scp_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMScpConnectionTFSDK
	var payload CMScpConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.AuthMethod.ValueString() != "" && plan.AuthMethod.ValueString() != types.StringNull().ValueString() {
		payload.AuthMethod = plan.AuthMethod.ValueString()
	}
	if plan.Host.ValueString() != "" && plan.Host.ValueString() != types.StringNull().ValueString() {
		payload.Host = plan.Host.ValueString()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.PathTo.ValueString() != "" && plan.PathTo.ValueString() != types.StringNull().ValueString() {
		payload.PathTo = plan.PathTo.ValueString()
	}

	if plan.PublicKey.ValueString() != "" && plan.PublicKey.ValueString() != types.StringNull().ValueString() {
		payload.PublicKey = plan.PublicKey.ValueString()
	}

	if plan.Username.ValueString() != "" && plan.Username.ValueString() != types.StringNull().ValueString() {
		payload.Username = plan.Username.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	scpLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		scpLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = scpLabelsPayload

	scpMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		scpMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = scpMetadataPayload

	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = plan.Password.ValueString()
	}

	if plan.Port.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var scpProducts []string
		diags = plan.Products.ElementsAs(ctx, &scpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = scpProducts
	}

	if plan.Protocol.ValueString() != "" && plan.Protocol.ValueString() != types.StringNull().ValueString() {
		payload.Protocol = plan.Protocol.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scp_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: SCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_SCP_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scp_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating SCP Connection on CipherTrust Manager: ",
			"Could not create scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getParamsFromResponse(response, &resp.Diagnostics, &plan)

	tflog.Debug(ctx, "[resource_scp_connection.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scp_connection.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMScpConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMScpConnectionTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scp_connection.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_SCP_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading SCP Connection on CipherTrust Manager: ",
			"Could not read scp connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Debug(ctx, "resource_scp_connection.go: response :"+response)

	getParamsFromResponse(response, &resp.Diagnostics, &state)
	// required parameters are fetched separately
	state.AuthMethod = types.StringValue(gjson.Get(response, "auth_method").String())
	state.Host = types.StringValue(gjson.Get(response, "host").String())
	state.PathTo = types.StringValue(gjson.Get(response, "path_to").String())
	state.PublicKey = types.StringValue(gjson.Get(response, "public_key").String())
	state.Username = types.StringValue(gjson.Get(response, "username").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scp_connection.go -> Read]["+id+"]")
	return
}

func (r *resourceCMScpConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scp_connection.go -> Update]["+id+"]")
	var plan CMScpConnectionTFSDK
	var payload CMScpConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.AuthMethod.ValueString() != "" && plan.AuthMethod.ValueString() != types.StringNull().ValueString() {
		payload.AuthMethod = plan.AuthMethod.ValueString()
	}
	if plan.Host.ValueString() != "" && plan.Host.ValueString() != types.StringNull().ValueString() {
		payload.Host = plan.Host.ValueString()
	}

	if plan.PathTo.ValueString() != "" && plan.PathTo.ValueString() != types.StringNull().ValueString() {
		payload.PathTo = plan.PathTo.ValueString()
	}

	if plan.PublicKey.ValueString() != "" && plan.PublicKey.ValueString() != types.StringNull().ValueString() {
		payload.PublicKey = plan.PublicKey.ValueString()
	}

	if plan.Username.ValueString() != "" && plan.Username.ValueString() != types.StringNull().ValueString() {
		payload.Username = plan.Username.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	scpLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		scpLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = scpLabelsPayload

	scpMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		scpMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = scpMetadataPayload

	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = plan.Password.ValueString()
	}

	if plan.Port.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var scpProducts []string
		diags = plan.Products.ElementsAs(ctx, &scpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = scpProducts
	}

	if plan.Protocol.ValueString() != "" && plan.Protocol.ValueString() != types.StringNull().ValueString() {
		payload.Protocol = plan.Protocol.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scp_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: SCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_SCP_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scp_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating SCP Connection on CipherTrust Manager: ",
			"Could not update scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getParamsFromResponse(response, &resp.Diagnostics, &plan)

	tflog.Debug(ctx, fmt.Sprintf("Response: %s", response))
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMScpConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMScpConnectionTFSDK
	diags := req.State.Get(ctx, &state)
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scp_connection.go -> Delete]["+state.ID.ValueString()+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_SCP_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scp_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust SCP Connection",
			"Could not delete scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scp_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
}

func (d *resourceCMScpConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func getParamsFromResponse(response string, diag *diag.Diagnostics, data *CMScpConnectionTFSDK) {
	data.ID = types.StringValue(gjson.Get(response, "id").String())
	data.URI = types.StringValue(gjson.Get(response, "uri").String())
	data.Account = types.StringValue(gjson.Get(response, "account").String())
	data.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	data.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	data.Category = types.StringValue(gjson.Get(response, "category").String())
	data.Service = types.StringValue(gjson.Get(response, "service").String())
	data.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	data.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	data.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	data.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())
	data.Description = types.StringValue(gjson.Get(response, "description").String())
	data.Protocol = types.StringValue(gjson.Get(response, "protocol").String())
	data.Port = types.Int64Value(gjson.Get(response, "port").Int())
	data.Labels = common.ParseMap(response, diag, "labels")
	data.Meta = common.ParseMap(response, diag, "meta")
	data.Products = common.ParseArray(response, "products")
}
