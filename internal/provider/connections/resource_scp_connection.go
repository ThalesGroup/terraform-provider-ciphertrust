package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                   = &resourceCMScpConnection{}
	_ resource.ResourceWithConfigure      = &resourceCMScpConnection{}
	_ resource.ResourceWithValidateConfig = &resourceCMScpConnection{}

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

func (r *resourceCMScpConnection) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_scp_connection", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMScpConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an SCP/SFTP connection used for backup/restore on the CipherTrust Manager appliance. **Only available on CipherTrust Manager — not supported on CDSPaaS, where backup/restore is managed by the platform.**",
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
				Validators: []validator.String{
					validators.OneOfFold("key", "password"),
				},
			},
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Hostname or FQDN of SCP/SFTP remote machine.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "(Immutable) Unique connection name.",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"path_to": schema.StringAttribute{
				Required:    true,
				Description: "A path where the file to be copied via SCP/SFTP. Example '/home/ubuntu/datafolder/'",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"public_key": schema.StringAttribute{
				Required:    true,
				Description: "Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"username": schema.StringAttribute{
				Required:    true,
				Description: "Username for accessing SCP/SFTP server.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection. Note: once set, this field cannot be cleared back to empty — CM does not honour empty-string PATCH requests for this field.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: labelsDescription,
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection. Note: once set, this field cannot be cleared back to empty — CM does not honour empty-object PATCH requests for this field.",
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Password for SCP/SFTP server. Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). To resend a rotated password, change `password` and bump `password_version` in the same apply.",
			},
			"password_version": schema.Int64Attribute{
				Optional:    true,
				Description: "Arbitrary version number used to trigger re-sending `password` to CipherTrust Manager. Since `password` is write-only, Terraform cannot detect a change in its value on its own; increment this on every apply where you want the current `password` value re-sent.",
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Port where SCP/SFTP service runs on host (usually 22).",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: productsDescription,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("cckm", "ddc", "cte", "data discovery", "backup/restore", "logger", "hsm_anchored_domain", "csm"),
					),
				},
			},
			"protocol": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Use 'sftp' or 'scp'. 'sftp' is the default value",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					validators.OneOfFold("sftp", "scp"),
				},
			},
			//common response parameters (read-only)
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "URI of the SCP connection resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "Account associated with the SCP connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the connection was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// updated_at intentionally has no UseStateForUnknown(): CM sets a fresh
			// timestamp on every successful update, so showing it as "known after
			// apply" is accurate, not spurious drift.
			"updated_at": schema.StringAttribute{Computed: true, Description: "Timestamp when the connection was last updated."},
			// service is derived server-side from protocol (e.g. protocol "scp" is
			// reported back as service "secure-copy"), so it must NOT use
			// UseStateForUnknown() — carrying the prior value forward causes a
			// "Provider produced inconsistent result after apply" error whenever
			// an update triggers CM to return a freshly normalized value.
			"service": schema.StringAttribute{
				Computed:    true,
				Description: "Service type for the connection.",
			},
			"category": schema.StringAttribute{
				Computed:    true,
				Description: "Category of the connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"resource_url": schema.StringAttribute{
				Computed:    true,
				Description: "Resource URL of the connection on CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_connection_ok": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the last connection attempt was successful.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"last_connection_error": schema.StringAttribute{
				Computed:    true,
				Description: "Error message from the last connection attempt, if any.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_connection_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last connection attempt.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMScpConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_scp_connection.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CMScpConnectionTFSDK
	var payload CMScpConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.Password is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config CMScpConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
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

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		scpLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			scpLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = scpLabelsPayload
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		scpMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			scpMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = scpMetadataPayload
	}

	if v := config.Password.ValueString(); v != "" {
		payload.Password = v
	}

	if plan.Port.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var scpProducts []string
		diags = plan.Products.ElementsAs(ctx, &scpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = scpProducts
	}

	if plan.Protocol.ValueString() != "" && plan.Protocol.ValueString() != types.StringNull().ValueString() {
		payload.Protocol = plan.Protocol.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scp_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: SCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_SCP_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scp_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating SCP Connection on CipherTrust Manager: ",
			"Could not create scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getParamsFromResponse(response, &resp.Diagnostics, &plan)

	// password is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.Password = types.StringNull()

	r.client.Log.Debug("[resource_scp_connection.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_scp_connection.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMScpConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMScpConnectionTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_scp_connection.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_SCP_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddWarning(
				"SCP Connection Not Found on CipherTrust Manager — State Preserved",
				fmt.Sprintf("The managed SCP connection %q was not found during refresh.\n\n"+
					"To prevent accidental data loss and key recreation, this connection has been kept in state.\n\n"+
					"Please verify if this is a transient cluster issue. If the connection was permanently deleted, "+
					"manually remove it from state: 'terraform state rm <resource-address>'",
					state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scp_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading SCP Connection on CipherTrust Manager: ",
			"Could not read scp connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Debug("resource_scp_connection.go: response :" + response)

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

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_scp_connection.go -> Read][" + id + "]")
	return
}

func (r *resourceCMScpConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_scp_connection.go -> Update][" + id + "]")
	var plan CMScpConnectionTFSDK
	var state CMScpConnectionTFSDK
	var payload CMScpConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Load prior state to detect a password_version bump (see below).
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Update() ever runs, so plan.Password is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config CMScpConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
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

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		scpLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			scpLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = scpLabelsPayload
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		scpMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			scpMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = scpMetadataPayload
	}

	// password is write-only (never stored in state), so its own value can never be
	// diffed against a prior value — password_version is the explicit, state-tracked
	// signal that the caller wants the current password value re-sent to CM.
	if !plan.PasswordVersion.Equal(state.PasswordVersion) {
		payload.Password = config.Password.ValueString()
	}

	if plan.Port.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var scpProducts []string
		diags = plan.Products.ElementsAs(ctx, &scpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = scpProducts
	}

	if plan.Protocol.ValueString() != "" && plan.Protocol.ValueString() != types.StringNull().ValueString() {
		payload.Protocol = plan.Protocol.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scp_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: SCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_SCP_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scp_connection.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating SCP Connection on CipherTrust Manager: ",
			"Could not update scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getParamsFromResponse(response, &resp.Diagnostics, &plan)

	// password is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.Password = types.StringNull()

	r.client.Log.Debug(fmt.Sprintf("Response: %s", response))
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMScpConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMScpConnectionTFSDK
	diags := req.State.Get(ctx, &state)
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_scp_connection.go -> Delete][" + state.ID.ValueString() + "]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_SCP_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			r.client.Log.Debug("SCP connection already deleted out-of-band on CM")
			return
		}
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_scp_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust SCP Connection",
			"Could not delete scp connection, unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_scp_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
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
