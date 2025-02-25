package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMLogForwarders{}
	_ resource.ResourceWithConfigure = &resourceCMLogForwarders{}
)

func NewResourceCMLogForwarders() resource.Resource {
	return &resourceCMLogForwarders{}
}

type resourceCMLogForwarders struct {
	client *common.Client
}

func (r *resourceCMLogForwarders) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_log_forwarder"
}

// Schema defines the schema for the resource.
func (r *resourceCMLogForwarders) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "connection id of log-forwarder connection (elasticsearch, loki, syslog).",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name of the Log Forwarder.",
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Type of the Log Forwarder",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"elasticsearch",
						"loki",
						"syslog"}...),
				},
			},
			"elasticsearch_params": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Optional attributes specifying extra configuration fields specific to Elasticsearch",
				Attributes: map[string]schema.Attribute{
					"indices": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Optional attributes specifying index field for different logs",
						Attributes: map[string]schema.Attribute{
							"activity_kmip": schema.StringAttribute{
								Optional:    true,
								Description: "Index to be used for entries coming from the KMIP activity log. Logs will not be forwarded if index is not provided. Consult Elasticsearch documentation for allowed characters.",
							},
							"activity_nae": schema.StringAttribute{
								Optional:    true,
								Description: "Index to be used for entires coming from the NAE activity log. Logs will not be forwarded if index is not provided. Consult Elasticsearch documentation for allowed characters.",
							},
							"client_audit_records": schema.StringAttribute{
								Optional:    true,
								Description: "Index to be used for entries coming from client audit records. Client audit logs are forwarded only if this index is provided. Consult Elasticsearch documentation for allowed characters.",
							},
							"server_audit_records": schema.StringAttribute{
								Optional:    true,
								Description: "Index to be used for entries coming from server audit records. Logs will not be forwarded if index is not provided. Consult Elasticsearch documentation for allowed characters.",
							},
						},
					},
				},
			},
			"loki_params": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"labels": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Information which is used to create a Key using HKDF.",
						Attributes: map[string]schema.Attribute{
							"activity_kmip": schema.StringAttribute{
								Optional:    true,
								Description: "Labels to be used for entries coming from the KMIP activity log, for example \"jobs=activity_kmip\". Logs will not be forwarded if label is not provided. Consult Loki documentation for allowed characters.",
							},
							"activity_nae": schema.StringAttribute{
								Optional:    true,
								Description: "Labels to be used for entries coming from the NAE activity log, for example \"jobs=activity_nae\". Logs will not be forwarded if label is not provided. Consult Loki documentation for allowed characters.",
							},
							"client_audit_records": schema.StringAttribute{
								Optional:    true,
								Description: "Labels to be used for entries coming from client audit records, for example \"jobs=client_audit_records\". Client audit logs are forwarded only if this label is provided. Consult Loki documentation for allowed characters.",
							},
							"server_audit_records": schema.StringAttribute{
								Optional:    true,
								Description: "Labels to be used for entries coming from server audit records, for example \"jobs=server_audit_records\". Logs will not be forwarded if label is not provided. Consult Loki documentation for allowed characters.",
							},
						},
					},
				},
			},
			"syslog_params": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"forward_logs": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Information which is used to create a Key using HKDF.",
						Attributes: map[string]schema.Attribute{
							"activity_kmip": schema.BoolAttribute{
								Optional:    true,
								Description: "When true, KMIP Activity logs will be forwarded. You need to enable KMIP Acitivity logs before forwarding them.",
							},
							"activity_nae": schema.BoolAttribute{
								Optional:    true,
								Description: "When true, NAE Activity logs will be forwarded. You need to enable NAE Acitivity logs before forwarding them.",
							},
							"client_audit_records": schema.BoolAttribute{
								Optional:    true,
								Description: "When true, Client Audit Records will be forwarded.",
							},
							"server_audit_records": schema.BoolAttribute{
								Optional:    true,
								Description: "When true, Server Audit Records will be forwarded.",
							},
						},
					},
				},
			},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMLogForwarders) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_log_forwarder.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMLogForwardersTFSDK
	var payload CMLogForwardersJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var esParamIndices CMLogForwardersESOrLokiParamsJSON
	var esParams CMLogForwardersESJSON
	if !reflect.DeepEqual((*CMLogForwardersESTFSDK)(nil), plan.ElasticsearchParams) {
		tflog.Debug(ctx, "ElasticsearchParams should not be empty at this point")
		if plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ActivityKMIP = plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ActivityNAE = plan.ElasticsearchParams.Indices.ActivityNAE.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ClientAuditRecords = plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ServerAuditRecords = plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString()
		}
		esParams.Indices = &esParamIndices
		payload.ElasticsearchParams = &esParams
	}

	var lokiParamLabels CMLogForwardersESOrLokiParamsJSON
	var lokiParams CMLogForwardersLokiJSON
	if !reflect.DeepEqual((*CMLogForwardersLokiTFSDK)(nil), plan.LokiParams) {
		tflog.Debug(ctx, "LokiParams should not be empty at this point")
		if plan.LokiParams.Labels.ActivityKMIP.ValueString() != "" && plan.LokiParams.Labels.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ActivityKMIP = plan.LokiParams.Labels.ActivityKMIP.ValueString()
		}
		if plan.LokiParams.Labels.ActivityNAE.ValueString() != "" && plan.LokiParams.Labels.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ActivityNAE = plan.LokiParams.Labels.ActivityNAE.ValueString()
		}
		if plan.LokiParams.Labels.ClientAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ClientAuditRecords = plan.LokiParams.Labels.ClientAuditRecords.ValueString()
		}
		if plan.LokiParams.Labels.ServerAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ServerAuditRecords = plan.LokiParams.Labels.ServerAuditRecords.ValueString()
		}
		lokiParams.Labels = &lokiParamLabels
		payload.LokiParams = &lokiParams
	}

	var syslogParamLabels CMLogForwardersSyslogParamsJSON
	var syslogParams CMLogForwardersSyslogJSON
	if !reflect.DeepEqual((*CMLogForwardersSyslogTFSDK)(nil), plan.SyslogParams) {
		tflog.Debug(ctx, "SyslogParams should not be empty at this point")
		if plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ActivityKMIP = plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ActivityNAE = plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ClientAuditRecords = plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ServerAuditRecords = plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool()
		}
		syslogParams.SyslogParams = &syslogParamLabels
		payload.SyslogParams = &syslogParams
	}

	payload.ConnectionID = plan.ConnectionID.ValueString()
	payload.Name = plan.Name.ValueString()
	payload.Type = plan.Type.ValueString()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_log_forwarder.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Log Forwarder Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CM_LOG_FORWARDS,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_log_forwarder.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Log Forwarder on CipherTrust Manager: ",
			"Could not create Log Forwarder "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Debug(ctx, "[resource_log_forwarder.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_log_forwarder.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMLogForwarders) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMLogForwardersTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_LOG_FORWARDS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_log_forwarder.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Log Forwarder from CipherTrust Manager: ",
			"Could not read Log Forwarder: ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Type = types.StringValue(gjson.Get(response, "type").String())
	state.ConnectionID = types.StringValue(gjson.Get(response, "connection_id").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_log_forwarder.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMLogForwarders) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMLogForwardersTFSDK
	var payload CMLogForwardersJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var esParamIndices CMLogForwardersESOrLokiParamsJSON
	var esParams CMLogForwardersESJSON
	if !reflect.DeepEqual((*CMLogForwardersESTFSDK)(nil), plan.ElasticsearchParams) {
		tflog.Debug(ctx, "ElasticsearchParams should not be empty at this point")
		if plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ActivityKMIP = plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ActivityNAE = plan.ElasticsearchParams.Indices.ActivityNAE.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ClientAuditRecords = plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices.ServerAuditRecords = plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString()
		}
		esParams.Indices = &esParamIndices
		payload.ElasticsearchParams = &esParams
	}

	var lokiParamLabels CMLogForwardersESOrLokiParamsJSON
	var lokiParams CMLogForwardersLokiJSON
	if !reflect.DeepEqual((*CMLogForwardersLokiTFSDK)(nil), plan.LokiParams) {
		tflog.Debug(ctx, "LokiParams should not be empty at this point")
		if plan.LokiParams.Labels.ActivityKMIP.ValueString() != "" && plan.LokiParams.Labels.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ActivityKMIP = plan.LokiParams.Labels.ActivityKMIP.ValueString()
		}
		if plan.LokiParams.Labels.ActivityNAE.ValueString() != "" && plan.LokiParams.Labels.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ActivityNAE = plan.LokiParams.Labels.ActivityNAE.ValueString()
		}
		if plan.LokiParams.Labels.ClientAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ClientAuditRecords = plan.LokiParams.Labels.ClientAuditRecords.ValueString()
		}
		if plan.LokiParams.Labels.ServerAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels.ServerAuditRecords = plan.LokiParams.Labels.ServerAuditRecords.ValueString()
		}
		lokiParams.Labels = &lokiParamLabels
		payload.LokiParams = &lokiParams
	}

	var syslogParamLabels CMLogForwardersSyslogParamsJSON
	var syslogParams CMLogForwardersSyslogJSON
	if !reflect.DeepEqual((*CMLogForwardersSyslogTFSDK)(nil), plan.SyslogParams) {
		tflog.Debug(ctx, "SyslogParams should not be empty at this point")
		if plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ActivityKMIP = plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ActivityNAE = plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ClientAuditRecords = plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels.ServerAuditRecords = plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool()
		}
		syslogParams.SyslogParams = &syslogParamLabels
		payload.SyslogParams = &syslogParams
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.ConnectionID.ValueString() != "" && plan.ConnectionID.ValueString() != types.StringNull().ValueString() {
		payload.ConnectionID = plan.ConnectionID.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Log Forwarder Updation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		id,
		common.URL_CM_LOG_FORWARDS+"/"+plan.ID.ValueString(),
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Log Forwarder on CipherTrust Manager: ",
			"Could not update Log Forwarder, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
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
func (r *resourceCMLogForwarders) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMLogForwardersTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_POLICIES, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_log_forwarder.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CM Log Forwarder",
			"Could not delete Log Forwarder, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMLogForwarders) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
