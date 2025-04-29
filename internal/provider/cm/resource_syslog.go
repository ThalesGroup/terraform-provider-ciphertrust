package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMSyslog{}
	_ resource.ResourceWithConfigure = &resourceCMSyslog{}
)

func NewResourceCMSyslog() resource.Resource {
	return &resourceCMSyslog{}
}

type resourceCMSyslog struct {
	client *common.Client
}

func (r *resourceCMSyslog) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_syslog"
}

// Schema defines the schema for the resource.
func (r *resourceCMSyslog) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of this resource.",
			},
			"host": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The hostname or IP address of the syslog connection.",
			},
			"transport": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "udp, tcp or tls",
			},
			"ca_cert": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The trusted CA cert in PEM format. Only used in TLS transport mode",
			},
			"message_format": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The log message format for new log messages: rfc5424 (default) plain_message cef leef.",
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The port to use for the connection. Defaults to 514 for udp, 601 for tcp and 6514 for tls",
			},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMSyslog) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_syslog.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMSyslogTFSDK
	var payload CMSyslogJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Host = plan.Host.ValueString()
	payload.Transport = plan.Transport.ValueString()

	if plan.CACert.ValueString() != "" && plan.CACert.ValueString() != types.StringNull().ValueString() {
		payload.CACert = plan.CACert.ValueString()
	}

	if plan.MessageFormat.ValueString() != "" && plan.MessageFormat.ValueString() != types.StringNull().ValueString() {
		payload.MessageFormat = plan.MessageFormat.ValueString()
	}

	if plan.Port.ValueInt64() != types.Int64Unknown().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_syslog.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Syslog Configuration",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CM_SYSLOG,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_syslog.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error adding Syslog configuration on CipherTrust Manager: ",
			"Could not add Syslog "+plan.Host.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Host = types.StringValue(gjson.Get(response, "host").String())
	plan.Transport = types.StringValue(gjson.Get(response, "transport").String())
	plan.CACert = types.StringValue(gjson.Get(response, "caCert").String())
	plan.MessageFormat = types.StringValue(gjson.Get(response, "messageFormat").String())
	plan.Port = types.Int64Value(gjson.Get(response, "port").Int())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Debug(ctx, "[resource_syslog.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_syslog.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMSyslog) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMSyslogTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_SYSLOG)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_syslog.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Syslog configuration on CipherTrust Manager: ",
			"Could not read Syslog cofiguration : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Host = types.StringValue(gjson.Get(response, "host").String())
	state.Transport = types.StringValue(gjson.Get(response, "transport").String())
	state.CACert = types.StringValue(gjson.Get(response, "caCert").String())
	state.MessageFormat = types.StringValue(gjson.Get(response, "messageFormat").String())
	state.Port = types.Int64Value(gjson.Get(response, "port").Int())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_syslog.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMSyslog) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMSyslogTFSDK
	var payload CMSyslogJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Host = plan.Host.ValueString()
	payload.Transport = plan.Transport.ValueString()

	if plan.CACert.ValueString() != "" && plan.CACert.ValueString() != types.StringNull().ValueString() {
		payload.CACert = plan.CACert.ValueString()
	}

	if plan.MessageFormat.ValueString() != "" && plan.MessageFormat.ValueString() != types.StringNull().ValueString() {
		payload.MessageFormat = plan.MessageFormat.ValueString()
	}

	if plan.Port.ValueInt64() != types.Int64Unknown().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_syslog.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Syslog Updation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		id,
		common.URL_CM_SYSLOG+"/"+plan.ID.ValueString(),
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_syslog.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating Syslog on CipherTrust Manager: ",
			"Could not update Syslog "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Host = types.StringValue(gjson.Get(response, "host").String())
	plan.Transport = types.StringValue(gjson.Get(response, "transport").String())
	plan.CACert = types.StringValue(gjson.Get(response, "caCert").String())
	plan.MessageFormat = types.StringValue(gjson.Get(response, "messageFormat").String())
	plan.Port = types.Int64Value(gjson.Get(response, "port").Int())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMSyslog) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMSyslogTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_SYSLOG, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_syslog.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Syslog",
			"Could not delete Syslog, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMSyslog) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
