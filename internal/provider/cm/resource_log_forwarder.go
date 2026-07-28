package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		Description: "Configures a CipherTrust Manager log forwarder that streams logs to an external destination (Elasticsearch, Loki, or Syslog) over a pre-existing connection.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the log forwarder.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "connection id of log-forwarder connection (elasticsearch, loki, syslog).",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name of the Log Forwarder.",
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Type of the log forwarder. Allowed values: elasticsearch, loki, syslog.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"elasticsearch",
						"loki",
						"syslog"}...),
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
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
				Description: "Optional attributes specifying extra configuration fields specific to Loki.",
				Attributes: map[string]schema.Attribute{
					"labels": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Optional attributes specifying labels specific to Loki.",
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
				Description: "Optional attributes specifying log forwarding flags specific to Syslog.",
				Attributes: map[string]schema.Attribute{
					"forward_logs": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Flags specifying which logs should be forwarded to Syslog.",
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
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "Date/time the log forwarder was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Description: "Date/time the log forwarder was last updated.",
				Computed:    true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMLogForwarders) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_log_forwarder.go -> Create][" + id + "]")

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
		r.client.Log.Debug("ElasticsearchParams should not be empty at this point")
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
		r.client.Log.Debug("LokiParams should not be empty at this point")
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
		r.client.Log.Debug("SyslogParams should not be empty at this point")
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Create][" + id + "]")
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Create][" + id + "]")
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

	r.client.Log.Debug("[resource_log_forwarder.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_log_forwarder.go -> Create][" + id + "]")
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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_log_forwarder.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_LOG_FORWARDS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"Log Forwarder Not Found — State Preserved",
				"The Log Forwarder resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Log Forwarder",
			"Could not read Log Forwarder: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Type = types.StringValue(gjson.Get(response, "type").String())
	state.ConnectionID = types.StringValue(gjson.Get(response, "connection_id").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	// Hydrate elasticsearch_params
	if gjson.Get(response, "elasticsearch_params").Exists() {
		var esIndices CMLogForwardersESOrLokiParamsTFSDK
		if r := gjson.Get(response, "elasticsearch_params.indices.activity_kmip"); r.Exists() {
			esIndices.ActivityKMIP = types.StringValue(r.String())
		} else {
			esIndices.ActivityKMIP = types.StringNull()
		}
		if r := gjson.Get(response, "elasticsearch_params.indices.activity_nae"); r.Exists() {
			esIndices.ActivityNAE = types.StringValue(r.String())
		} else {
			esIndices.ActivityNAE = types.StringNull()
		}
		if r := gjson.Get(response, "elasticsearch_params.indices.client_audit_records"); r.Exists() {
			esIndices.ClientAuditRecords = types.StringValue(r.String())
		} else {
			esIndices.ClientAuditRecords = types.StringNull()
		}
		if r := gjson.Get(response, "elasticsearch_params.indices.server_audit_records"); r.Exists() {
			esIndices.ServerAuditRecords = types.StringValue(r.String())
		} else {
			esIndices.ServerAuditRecords = types.StringNull()
		}
		var esParams CMLogForwardersESTFSDK
		esParams.Indices = &esIndices
		state.ElasticsearchParams = &esParams
	} else {
		state.ElasticsearchParams = nil
	}

	// Hydrate loki_params
	if gjson.Get(response, "loki_params").Exists() {
		var lokiLabels CMLogForwardersESOrLokiParamsTFSDK
		if r := gjson.Get(response, "loki_params.labels.activity_kmip"); r.Exists() {
			lokiLabels.ActivityKMIP = types.StringValue(r.String())
		} else {
			lokiLabels.ActivityKMIP = types.StringNull()
		}
		if r := gjson.Get(response, "loki_params.labels.activity_nae"); r.Exists() {
			lokiLabels.ActivityNAE = types.StringValue(r.String())
		} else {
			lokiLabels.ActivityNAE = types.StringNull()
		}
		if r := gjson.Get(response, "loki_params.labels.client_audit_records"); r.Exists() {
			lokiLabels.ClientAuditRecords = types.StringValue(r.String())
		} else {
			lokiLabels.ClientAuditRecords = types.StringNull()
		}
		if r := gjson.Get(response, "loki_params.labels.server_audit_records"); r.Exists() {
			lokiLabels.ServerAuditRecords = types.StringValue(r.String())
		} else {
			lokiLabels.ServerAuditRecords = types.StringNull()
		}
		var lokiParams CMLogForwardersLokiTFSDK
		lokiParams.Labels = &lokiLabels
		state.LokiParams = &lokiParams
	} else {
		state.LokiParams = nil
	}

	// Hydrate syslog_params.
	// CMLogForwardersSyslogTFSDK.SyslogParams has tfsdk tag "forward_logs".
	// gjson path follows json:"syslog_params" on CMLogForwardersSyslogJSON.SyslogParams,
	// so the nested path is "syslog_params.syslog_params.*".
	if gjson.Get(response, "syslog_params").Exists() {
		var syslogInner CMLogForwardersSyslogParamsTFSDK
		if r := gjson.Get(response, "syslog_params.syslog_params.activity_kmip"); r.Exists() {
			syslogInner.ActivityKMIP = types.BoolValue(r.Bool())
		} else {
			syslogInner.ActivityKMIP = types.BoolNull()
		}
		if r := gjson.Get(response, "syslog_params.syslog_params.activity_nae"); r.Exists() {
			syslogInner.ActivityNAE = types.BoolValue(r.Bool())
		} else {
			syslogInner.ActivityNAE = types.BoolNull()
		}
		if r := gjson.Get(response, "syslog_params.syslog_params.client_audit_records"); r.Exists() {
			syslogInner.ClientAuditRecords = types.BoolValue(r.Bool())
		} else {
			syslogInner.ClientAuditRecords = types.BoolNull()
		}
		if r := gjson.Get(response, "syslog_params.syslog_params.server_audit_records"); r.Exists() {
			syslogInner.ServerAuditRecords = types.BoolValue(r.Bool())
		} else {
			syslogInner.ServerAuditRecords = types.BoolNull()
		}
		var syslogOuter CMLogForwardersSyslogTFSDK
		syslogOuter.SyslogParams = &syslogInner
		state.SyslogParams = &syslogOuter
	} else {
		state.SyslogParams = nil
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_log_forwarder.go -> Read][" + id + "]")
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
	payload := make(map[string]interface{})

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !reflect.DeepEqual((*CMLogForwardersESTFSDK)(nil), plan.ElasticsearchParams) {
		r.client.Log.Debug("ElasticsearchParams should not be empty at this point")
		esParams := make(map[string]interface{})
		esParamIndices := make(map[string]interface{})
		if plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			esParamIndices["activity_kmip"] = plan.ElasticsearchParams.Indices.ActivityKMIP.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != "" && plan.ElasticsearchParams.Indices.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			esParamIndices["activity_nae"] = plan.ElasticsearchParams.Indices.ActivityNAE.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices["client_audit_records"] = plan.ElasticsearchParams.Indices.ClientAuditRecords.ValueString()
		}
		if plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != "" && plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			esParamIndices["server_audit_records"] = plan.ElasticsearchParams.Indices.ServerAuditRecords.ValueString()
		}
		if len(esParamIndices) > 0 {
			esParams["indices"] = esParamIndices
			payload["elasticsearch_params"] = esParams
		}
	}

	if !reflect.DeepEqual((*CMLogForwardersLokiTFSDK)(nil), plan.LokiParams) {
		r.client.Log.Debug("LokiParams should not be empty at this point")
		lokiParams := make(map[string]interface{})
		lokiParamLabels := make(map[string]interface{})
		if plan.LokiParams.Labels.ActivityKMIP.ValueString() != "" && plan.LokiParams.Labels.ActivityKMIP.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels["activity_kmip"] = plan.LokiParams.Labels.ActivityKMIP.ValueString()
		}
		if plan.LokiParams.Labels.ActivityNAE.ValueString() != "" && plan.LokiParams.Labels.ActivityNAE.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels["activity_nae"] = plan.LokiParams.Labels.ActivityNAE.ValueString()
		}
		if plan.LokiParams.Labels.ClientAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ClientAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels["client_audit_records"] = plan.LokiParams.Labels.ClientAuditRecords.ValueString()
		}
		if plan.LokiParams.Labels.ServerAuditRecords.ValueString() != "" && plan.LokiParams.Labels.ServerAuditRecords.ValueString() != types.StringNull().ValueString() {
			lokiParamLabels["server_audit_records"] = plan.LokiParams.Labels.ServerAuditRecords.ValueString()
		}
		if len(lokiParamLabels) > 0 {
			lokiParams["labels"] = lokiParamLabels
			payload["loki_params"] = lokiParams
		}
	}

	if !reflect.DeepEqual((*CMLogForwardersSyslogTFSDK)(nil), plan.SyslogParams) {
		r.client.Log.Debug("SyslogParams should not be empty at this point")
		syslogParams := make(map[string]interface{})
		syslogParamLabels := make(map[string]interface{})
		if plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels["activity_kmip"] = plan.SyslogParams.SyslogParams.ActivityKMIP.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels["activity_nae"] = plan.SyslogParams.SyslogParams.ActivityNAE.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels["client_audit_records"] = plan.SyslogParams.SyslogParams.ClientAuditRecords.ValueBool()
		}
		if plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool() != types.BoolNull().ValueBool() {
			syslogParamLabels["server_audit_records"] = plan.SyslogParams.SyslogParams.ServerAuditRecords.ValueBool()
		}
		if len(syslogParamLabels) > 0 {
			syslogParams["syslog_params"] = syslogParamLabels
			payload["syslog_params"] = syslogParams
		}
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload["name"] = plan.Name.ValueString()
	}
	if plan.ConnectionID.ValueString() != "" && plan.ConnectionID.ValueString() != types.StringNull().ValueString() {
		payload["connection_id"] = plan.ConnectionID.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Update][" + id + "]")
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Update][" + id + "]")
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
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_log_forwarder.go -> Delete][" + id + "]")

	var state CMLogForwardersTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_LOG_FORWARDS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_log_forwarder.go -> Delete][" + id + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_log_forwarder.go -> Delete][" + id + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Log Forwarder",
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
