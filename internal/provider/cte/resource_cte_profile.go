package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEProfile{}
	_ resource.ResourceWithConfigure = &resourceCTEProfile{}
)

func NewResourceCTEProfile() resource.Resource {
	return &resourceCTEProfile{}
}

type resourceCTEProfile struct {
	client *common.Client
}

func (r *resourceCTEProfile) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_profile"
}

// Schema defines the schema for the resource.
func (r *resourceCTEProfile) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the CTE profile.",
			},
			"cache_settings": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Cache settings for the server.",
				Attributes: map[string]schema.Attribute{
					"max_files": schema.Int64Attribute{
						Optional:    true,
						Description: "Maximum number of files. Minimum value is 200.",
					},
					"max_space": schema.Int64Attribute{
						Optional:    true,
						Description: "Max Space. Minimum value is 100 MB.",
					},
				},
			},
			"concise_logging": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to allow concise logging.",
			},
			"connect_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Connect timeout in seconds. Valid values are 5 to 150.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the profile resource.",
			},
			"duplicate_settings": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Duplicate setting parameters.",
				Attributes: map[string]schema.Attribute{
					"suppress_interval": schema.Int64Attribute{
						Optional:    true,
						Description: "Suppress interval in seconds. Valid values are 1 to 1000.",
					},
					"suppress_threshold": schema.Int64Attribute{
						Optional:    true,
						Description: "Suppress threshold. Valid values are 1 to 100.",
					},
				},
			},
			"file_settings": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "File settings for the profile.",
				Attributes: map[string]schema.Attribute{
					"allow_purge": schema.BoolAttribute{
						Optional:    true,
						Description: "Allows purge.",
					},
					"file_threshold": schema.StringAttribute{
						Optional:    true,
						Description: "Applicable file threshold. ",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}...),
						},
					},
					"max_file_size": schema.Int64Attribute{
						Optional:    true,
						Description: "Maximum file size(bytes) 1,000 - 1,000,000,000 (1KB to 1GB).",
					},
					"max_old_files": schema.Int64Attribute{
						Optional:    true,
						Description: "Maximum number of old files allowed. Valid values are 1 to 100.",
					},
				},
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
			},
			"ldt_qos_cap_cpu_allocation": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to allow CPU allocation for Quality of Service (QoS) capabilities.",
			},
			"ldt_qos_cpu_percent": schema.Int64Attribute{
				Optional:    true,
				Description: "CPU application percentage if ldt_qos_cap_cpu_allocation is true. Valid values are 0 to 100.",
			},
			"ldt_qos_rekey_option": schema.StringAttribute{
				Optional:    true,
				Description: "Rekey option and applicable options are RekeyRate and CPU.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"RekeyRate", "CPU"}...),
				},
			},
			"ldt_qos_rekey_rate": schema.Int64Attribute{
				Optional:    true,
				Description: "Rekey rate in terms of MB/s. Valid values are 0 to 32767.",
			},
			"ldt_qos_schedule": schema.StringAttribute{
				Optional:    true,
				Description: "Type of QoS schedule.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"CUSTOM", "CUSTOM_WITH_OVERWRITE", "ANY_TIME", "WEEKNIGHTS", "WEEKENDS"}...),
				},
			},
			"ldt_qos_status_check_rate": schema.Int64Attribute{
				Optional:    true,
				Description: "Frequency to check and update the LDT status on the CipherTrust Manager. The valid value ranges from 600 to 86400 seconds. The default value is 3600 seconds.",
			},
			"client_logging_configuration": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Logger configurations for the management service.",
				Attributes: map[string]schema.Attribute{
					"duplicates": schema.StringAttribute{
						Optional:    true,
						Description: "Control duplicate entries, ALLOW or SUPPRESS",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"ALLOW", "SUPPRESS"}...),
						},
					},
					"file_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to enable file upload.",
					},
					"syslog_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to enable support for the Syslog server.",
					},
					"threshold": schema.StringAttribute{
						Optional:    true,
						Description: "Threshold value",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}...),
						},
					},
					"upload_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to enable log upload to the URL.",
					},
				},
			},
			"metadata_scan_interval": schema.Int64Attribute{
				Optional:    true,
				Description: "Time interval in seconds to scan files under the GuardPoint. The default value is 600.",
			},
			"mfa_exempt_user_set_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the user set to be exempted from MFA. MFA will not be enforced on the users of this set.",
			},
			"oidc_connection_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the OIDC connection.",
			},
			"qos_schedules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Schedule of QoS capabilities.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"end_time_hour": schema.Int64Attribute{
							Optional:    true,
							Description: "QoS end hour. Valid values are 1 to 23.",
						},
						"end_time_min": schema.Int64Attribute{
							Optional:    true,
							Description: "QoS end minute. Valid values are 0 to 59.",
						},
						"end_weekday": schema.StringAttribute{
							Optional:    true,
							Description: "QoS end day.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}...),
							},
						},
						"start_time_hour": schema.Int64Attribute{
							Optional:    true,
							Description: "QOS start hour. Valid values are 1 to 23.",
						},
						"start_time_min": schema.Int64Attribute{
							Optional:    true,
							Description: "QOS start minute. Valid values are 0 to 59.",
						},
						"start_weekday": schema.StringAttribute{
							Optional:    true,
							Description: "QoS start day.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}...),
							},
						},
					},
				},
			},
			"rwp_operation": schema.StringAttribute{
				Optional:    true,
				Description: "Applicable to the Ransomware clients only. The valid values are permit(for Audit), deny(for Block), and disable. The default value is deny.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"permit", "deny", "disable"}...),
				},
			},
			"rwp_process_set": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the process set to be whitelisted.",
			},
			"server_response_rate": schema.Int64Attribute{
				Optional:    true,
				Description: "the percentage value of successful API calls to the server, for which the agent will consider the server to be working fine. If the value is set to 75 then, if the server responds to 75 percent of the calls it is considered OK & no update is sent by agent. Valid values are between 0 to 100, both inclusive. Default value is 0.",
			},
			"server_settings": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Server configuration of cluster nodes. These settings are allowed only in cluster environment.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host_name": schema.StringAttribute{
							Optional:    true,
							Description: "Host name of the cluster node.",
						},
						"priority": schema.StringAttribute{
							Optional:    true,
							Description: "Priority of the cluster node. Valid values are 1 to 100.",
						},
					},
				},
			},
			"syslog_settings": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Parameters to configure the Syslog server.",
				Attributes: map[string]schema.Attribute{
					"local": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether the Syslog server is local.",
					},
					"syslog_threshold": schema.StringAttribute{
						Optional:    true,
						Description: "Applicable threshold.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}...),
						},
					},
					"servers": schema.ListNestedAttribute{
						Optional:    true,
						Description: "Configuration of the Syslog server.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"ca_certificate": schema.StringAttribute{
									Optional:    true,
									Description: "CA certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----\n<certificate content>\n-----END CERTIFICATE--------",
								},
								"certificate": schema.StringAttribute{
									Optional:    true,
									Description: "Client certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----\n<certificate content>\n-----END CERTIFICATE--------",
								},
								"message_format": schema.StringAttribute{
									Optional:    true,
									Description: "Format of the message on the Syslog server.",
									Validators: []validator.String{
										stringvalidator.OneOf([]string{"CEF", "LEEF", "RFC5424", "PLAIN"}...),
									},
								},
								"name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the Syslog server.",
								},
								"port": schema.Int64Attribute{
									Optional:    true,
									Description: "Port for syslog server. Valid values are 1 to 65535.",
								},
								"private_key": schema.StringAttribute{
									Optional:    true,
									Description: "Client certificate for syslog application provided by the client. for example: -----BEGIN RSA PRIVATE KEY-----\n<key content>\n-----END RSA PRIVATE KEY-----",
								},
								"protocol": schema.StringAttribute{
									Optional:    true,
									Description: "Protocol of the Syslog server, TCP, UDP and TLS.",
									Validators: []validator.String{
										stringvalidator.OneOf([]string{"TCP", "UDP", "TLS"}...),
									},
								},
							},
						},
					},
				},
			},
			"upload_settings": schema.MapNestedAttribute{
				Optional:    true,
				Description: "Configure log upload to the Syslog server.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"duplicates": schema.StringAttribute{
							Optional:    true,
							Description: "Control duplicate entries, ALLOW or SUPPRESS",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"ALLOW", "SUPPRESS"}...),
							},
						},
						"file_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to enable file upload.",
						},
						"syslog_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to enable support for the Syslog server.",
						},
						"threshold": schema.StringAttribute{
							Optional:    true,
							Description: "Threshold value",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}...),
							},
						},
						"upload_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to enable log upload to the URL.",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEProfile) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_profile.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEProfileTFSDK
	var payload CTEProfileJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Add Name to the payload
	payload.Name = common.TrimString(plan.Name.String())

	// Set cache_settings in the request
	var cacheSettings CTEProfileCacheSettingsJSON
	if !reflect.DeepEqual((*CTEProfileCacheSettingsTFSDK)(nil), plan.CacheSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.CacheSettings.MaxFiles.ValueInt64() != types.Int64Null().ValueInt64() {
			cacheSettings.MaxFiles = plan.CacheSettings.MaxFiles.ValueInt64()
		}
		if plan.CacheSettings.MaxSpace.ValueInt64() != types.Int64Null().ValueInt64() {
			cacheSettings.MaxSpace = plan.CacheSettings.MaxSpace.ValueInt64()
		}
		payload.CacheSettings = &cacheSettings
	}

	if plan.ConciseLogging.ValueBool() != types.BoolNull().ValueBool() {
		payload.ConciseLogging = plan.ConciseLogging.ValueBool()
	}
	if plan.ConnectTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.ConnectTimeout = plan.ConnectTimeout.ValueInt64()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
	}

	// Set duplicate_settings in the request
	var duplicateSettings CTEProfileDuplicateSettingsJSON
	if !reflect.DeepEqual((*CTEProfileDuplicateSettingsTFSDK)(nil), plan.DuplicateSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.DuplicateSettings.SuppressInterval.ValueInt64() != types.Int64Null().ValueInt64() {
			duplicateSettings.SuppressInterval = plan.DuplicateSettings.SuppressInterval.ValueInt64()
		}
		if plan.DuplicateSettings.SuppressThreshold.ValueInt64() != types.Int64Null().ValueInt64() {
			duplicateSettings.SuppressThreshold = plan.DuplicateSettings.SuppressThreshold.ValueInt64()
		}
		payload.DuplicateSettings = &duplicateSettings
	}

	// Set file_settings in the request
	var fileSettings CTEProfileFileSettingsJSON
	if !reflect.DeepEqual((*CTEProfileFileSettingsTFSDK)(nil), plan.FileSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.FileSettings.AllowPurge.ValueBool() != types.BoolNull().ValueBool() {
			fileSettings.AllowPurge = plan.FileSettings.AllowPurge.ValueBool()
		}
		if plan.FileSettings.FileThreshold.ValueString() != "" && plan.FileSettings.FileThreshold.ValueString() != types.StringNull().ValueString() {
			fileSettings.FileThreshold = common.TrimString(plan.FileSettings.FileThreshold.String())
		}
		if plan.FileSettings.MaxFileSize.ValueInt64() != types.Int64Null().ValueInt64() {
			fileSettings.MaxFileSize = plan.FileSettings.MaxFileSize.ValueInt64()
		}
		if plan.FileSettings.MaxOldFiles.ValueInt64() != types.Int64Null().ValueInt64() {
			fileSettings.MaxOldFiles = plan.FileSettings.MaxOldFiles.ValueInt64()
		}
		payload.FileSettings = &fileSettings
	}

	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	if plan.LDTQOSCapCPUAllocation.ValueBool() != types.BoolNull().ValueBool() {
		payload.LDTQOSCapCPUAllocation = bool(plan.LDTQOSCapCPUAllocation.ValueBool())
	}
	if plan.LDTQOSCapCPUPercent.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSCapCPUPercent = plan.LDTQOSCapCPUPercent.ValueInt64()
	}
	if plan.LDTQOSRekeyOption.ValueString() != "" && plan.LDTQOSRekeyOption.ValueString() != types.StringNull().ValueString() {
		payload.LDTQOSRekeyOption = common.TrimString(plan.LDTQOSRekeyOption.ValueString())
	}
	if plan.LDTQOSRekeyRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSRekeyRate = plan.LDTQOSRekeyRate.ValueInt64()
	}
	if plan.LDTQOSSchedule.ValueString() != "" && plan.LDTQOSSchedule.ValueString() != types.StringNull().ValueString() {
		payload.LDTQOSSchedule = common.TrimString(plan.LDTQOSSchedule.ValueString())
	}
	if plan.LDTQOSStatusCheckRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSStatusCheckRate = plan.LDTQOSStatusCheckRate.ValueInt64()
	}

	// Set client_logger_configs in the request
	var managementServiceLogger, policyEvaluationLogger, securityAdminLogger, systemAdminLogger CTEProfileManagementServiceLoggerJSON
	if !reflect.DeepEqual((*CTEProfileManagementServiceLoggerTFSDK)(nil), plan.Client_Logging_Config) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.Client_Logging_Config.Duplicates.ValueString() != "" && plan.Client_Logging_Config.Duplicates.ValueString() != types.StringNull().ValueString() {
			policyEvaluationLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			managementServiceLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			systemAdminLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			securityAdminLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
		}
		if plan.Client_Logging_Config.FileEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			policyEvaluationLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			systemAdminLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			securityAdminLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
		}
		if plan.Client_Logging_Config.SyslogEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			policyEvaluationLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			securityAdminLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			systemAdminLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()

		}
		if plan.Client_Logging_Config.Threshold.ValueString() != "" && plan.Client_Logging_Config.Threshold.ValueString() != types.StringNull().ValueString() {
			managementServiceLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.ValueString())
			policyEvaluationLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.String())
			securityAdminLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.ValueString())
			systemAdminLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.String())

		}
		if plan.Client_Logging_Config.UploadEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			policyEvaluationLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			securityAdminLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			systemAdminLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()

		}
		payload.ManagementServiceLogger = &managementServiceLogger
		payload.SecurityAdminLogger = &securityAdminLogger
		payload.SystemAdminLogger = &systemAdminLogger
		payload.PolicyEvaluationLogger = &policyEvaluationLogger

	}

	if plan.MetadataScanInterval.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MetadataScanInterval = plan.MetadataScanInterval.ValueInt64()
	}
	if plan.MFAExemptUserSetID.ValueString() != "" && plan.MFAExemptUserSetID.ValueString() != types.StringNull().ValueString() {
		payload.MFAExemptUserSetID = common.TrimString(plan.MFAExemptUserSetID.ValueString())
	}
	if plan.OIDCConnectionID.ValueString() != "" && plan.OIDCConnectionID.ValueString() != types.StringNull().ValueString() {
		payload.OIDCConnectionID = common.TrimString(plan.OIDCConnectionID.ValueString())
	}

	// Add qos_schedules to the payload if set
	var qosSchedules []CTEProfileQOSScheduleJSON
	for _, schedule := range plan.QOSSchedules {
		var scheduleJSON CTEProfileQOSScheduleJSON
		if schedule.EndTimeHour.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.EndTimeHour = schedule.EndTimeHour.ValueInt64()
		}
		if schedule.EndTimeMin.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.EndTimeMin = schedule.EndTimeMin.ValueInt64()
		}
		if schedule.EndWeekday.ValueString() != "" && schedule.EndWeekday.ValueString() != types.StringNull().ValueString() {
			scheduleJSON.EndWeekday = string(schedule.EndWeekday.ValueString())
		}
		if schedule.StartTimeHour.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.StartTimeHour = schedule.StartTimeHour.ValueInt64()
		}
		if schedule.StartTimeMin.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.StartTimeMin = schedule.StartTimeMin.ValueInt64()
		}
		if schedule.StartWeekday.ValueString() != "" && schedule.StartWeekday.ValueString() != types.StringNull().ValueString() {
			scheduleJSON.StartWeekday = string(schedule.StartWeekday.ValueString())
		}
		qosSchedules = append(qosSchedules, scheduleJSON)
	}
	payload.QOSSchedules = &qosSchedules

	if plan.RWPOperation.ValueString() != "" && plan.RWPOperation.ValueString() != types.StringNull().ValueString() {
		payload.RWPOperation = common.TrimString(plan.RWPOperation.ValueString())
	}
	if plan.RWPProcessSet.ValueString() != "" && plan.RWPProcessSet.ValueString() != types.StringNull().ValueString() {
		payload.RWPProcessSet = common.TrimString(plan.RWPProcessSet.ValueString())
	}

	if plan.ServerResponseRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.ServerResponseRate = plan.ServerResponseRate.ValueInt64()
	}

	// Add server_settings to the payload if set
	var serverSettings []CTEProfileServiceSettingJSON
	for _, setting := range plan.ServerSettings {
		var serverSetting CTEProfileServiceSettingJSON
		if setting.HostName.ValueString() != "" && setting.HostName.ValueString() != types.StringNull().ValueString() {
			serverSetting.HostName = string(setting.HostName.ValueString())
		}
		if setting.Priority.ValueInt64() != types.Int64Null().ValueInt64() {
			serverSetting.Priority = setting.Priority.ValueInt64()
		}
		serverSettings = append(serverSettings, serverSetting)
	}
	payload.ServerSettings = &serverSettings

	// Set syslog_settings in the request
	var syslogSettings CTEProfileSyslogSettingsJSON
	if !reflect.DeepEqual((*CTEProfileSyslogSettingsTFSDK)(nil), plan.SyslogSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.SyslogSettings.Local.ValueBool() != types.BoolNull().ValueBool() {
			syslogSettings.Local = plan.SyslogSettings.Local.ValueBool()
		}
		if plan.SyslogSettings.Threshold.ValueString() != "" && plan.SyslogSettings.Threshold.ValueString() != types.StringNull().ValueString() {
			syslogSettings.Threshold = common.TrimString(plan.SyslogSettings.Threshold.String())
		}
		var servers []CTEProfileSyslogSettingServerJSON
		for _, item := range plan.SyslogSettings.Servers {
			var server CTEProfileSyslogSettingServerJSON
			if item.CACert.ValueString() != "" && item.CACert.ValueString() != types.StringNull().ValueString() {
				server.CACert = string(item.CACert.ValueString())
			}
			if item.Certificate.ValueString() != "" && item.Certificate.ValueString() != types.StringNull().ValueString() {
				server.Certificate = string(item.Certificate.ValueString())
			}
			if item.MessageFormat.ValueString() != "" && item.MessageFormat.ValueString() != types.StringNull().ValueString() {
				server.MessageFormat = string(item.MessageFormat.ValueString())
			}
			if item.Name.ValueString() != "" && item.Name.ValueString() != types.StringNull().ValueString() {
				server.Name = string(item.Name.ValueString())
			}
			if item.Port.ValueInt64() != types.Int64Null().ValueInt64() {
				server.Port = item.Port.ValueInt64()
			}
			if item.PrivateKey.ValueString() != "" && item.PrivateKey.ValueString() != types.StringNull().ValueString() {
				server.PrivateKey = string(item.PrivateKey.ValueString())
			}
			if item.Protocol.ValueString() != "" && item.Protocol.ValueString() != types.StringNull().ValueString() {
				server.Protocol = string(item.Protocol.ValueString())
			}
			servers = append(servers, server)
		}
		syslogSettings.Servers = servers
		payload.SyslogSettings = &syslogSettings
	}

	// Set upload_settings in the request
	var uploadSettings CTEProfileUploadSettingsJSON
	if !reflect.DeepEqual((*CTEProfileUploadSettingsTFSDK)(nil), plan.UploadSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.UploadSettings.ConnectionTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.ConnectionTimeout = plan.UploadSettings.ConnectionTimeout.ValueInt64()
		}
		if plan.UploadSettings.DropIfBusy.ValueBool() != types.BoolNull().ValueBool() {
			uploadSettings.DropIfBusy = plan.UploadSettings.DropIfBusy.ValueBool()
		}
		if plan.UploadSettings.JobCompletionTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.JobCompletionTimeout = plan.UploadSettings.JobCompletionTimeout.ValueInt64()
		}
		if plan.UploadSettings.MaxInterval.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MaxInterval = plan.UploadSettings.MaxInterval.ValueInt64()
		}
		if plan.UploadSettings.MaxMessages.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MaxMessages = plan.UploadSettings.MaxMessages.ValueInt64()
		}
		if plan.UploadSettings.MinInterval.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MinInterval = plan.UploadSettings.MinInterval.ValueInt64()
		}
		if plan.UploadSettings.Threshold.ValueString() != "" && plan.UploadSettings.Threshold.ValueString() != types.StringNull().ValueString() {
			uploadSettings.Threshold = common.TrimString(plan.UploadSettings.Threshold.String())
		}
		payload.UploadSettings = &uploadSettings
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_profile.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Profile Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CTE_PROFILE, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_profile.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Profile on CipherTrust Manager: ",
			"Could not create CTE Profile, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_profile.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEProfile) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEProfileTFSDK

	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_PROFILE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_profile.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CTE Profile on CipherTrust Manager: ",
			"Could not read CTE Profile id : ,"+state.ID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_profile.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEProfile) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEProfileTFSDK
	var payload CTEProfileJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var cacheSettings CTEProfileCacheSettingsJSON
	if plan.CacheSettings.MaxFiles.ValueInt64() != types.Int64Null().ValueInt64() {
		cacheSettings.MaxFiles = plan.CacheSettings.MaxFiles.ValueInt64()
	}
	if plan.CacheSettings.MaxSpace.ValueInt64() != types.Int64Null().ValueInt64() {
		cacheSettings.MaxSpace = plan.CacheSettings.MaxSpace.ValueInt64()
	}
	payload.CacheSettings = &cacheSettings

	if plan.ConciseLogging.ValueBool() != types.BoolNull().ValueBool() {
		payload.ConciseLogging = plan.ConciseLogging.ValueBool()
	}
	if plan.ConnectTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.ConnectTimeout = plan.ConnectTimeout.ValueInt64()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
	}

	// Set duplicate_settings in the request
	var duplicateSettings CTEProfileDuplicateSettingsJSON
	if plan.DuplicateSettings.SuppressInterval.ValueInt64() != types.Int64Null().ValueInt64() {
		duplicateSettings.SuppressInterval = plan.DuplicateSettings.SuppressInterval.ValueInt64()
	}
	if plan.DuplicateSettings.SuppressThreshold.ValueInt64() != types.Int64Null().ValueInt64() {
		duplicateSettings.SuppressThreshold = plan.DuplicateSettings.SuppressThreshold.ValueInt64()
	}
	payload.DuplicateSettings = &duplicateSettings

	// Set file_settings in the request
	var fileSettings CTEProfileFileSettingsJSON
	if plan.FileSettings.AllowPurge.ValueBool() != types.BoolNull().ValueBool() {
		fileSettings.AllowPurge = plan.FileSettings.AllowPurge.ValueBool()
	}
	if plan.FileSettings.FileThreshold.ValueString() != "" && plan.FileSettings.FileThreshold.ValueString() != types.StringNull().ValueString() {
		fileSettings.FileThreshold = common.TrimString(plan.FileSettings.FileThreshold.String())
	}
	if plan.FileSettings.MaxFileSize.ValueInt64() != types.Int64Null().ValueInt64() {
		fileSettings.MaxFileSize = plan.FileSettings.MaxFileSize.ValueInt64()
	}
	if plan.FileSettings.MaxOldFiles.ValueInt64() != types.Int64Null().ValueInt64() {
		fileSettings.MaxOldFiles = plan.FileSettings.MaxOldFiles.ValueInt64()
	}
	payload.FileSettings = &fileSettings

	if plan.LDTQOSCapCPUAllocation.ValueBool() != types.BoolNull().ValueBool() {
		payload.LDTQOSCapCPUAllocation = bool(plan.LDTQOSCapCPUAllocation.ValueBool())
	}
	if plan.LDTQOSCapCPUPercent.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSCapCPUPercent = plan.LDTQOSCapCPUPercent.ValueInt64()
	}
	if plan.LDTQOSRekeyOption.ValueString() != "" && plan.LDTQOSRekeyOption.ValueString() != types.StringNull().ValueString() {
		payload.LDTQOSRekeyOption = common.TrimString(plan.LDTQOSRekeyOption.ValueString())
	}
	if plan.LDTQOSRekeyRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSRekeyRate = plan.LDTQOSRekeyRate.ValueInt64()
	}
	if plan.LDTQOSSchedule.ValueString() != "" && plan.LDTQOSSchedule.ValueString() != types.StringNull().ValueString() {
		payload.LDTQOSSchedule = common.TrimString(plan.LDTQOSSchedule.ValueString())
	}
	if plan.LDTQOSStatusCheckRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.LDTQOSStatusCheckRate = plan.LDTQOSStatusCheckRate.ValueInt64()
	}
	// Set client_logger_configs in the request
	var managementServiceLogger, policyEvaluationLogger, securityAdminLogger, systemAdminLogger CTEProfileManagementServiceLoggerJSON
	if !reflect.DeepEqual((*CTEProfileManagementServiceLoggerTFSDK)(nil), plan.Client_Logging_Config) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.Client_Logging_Config.Duplicates.ValueString() != "" && plan.Client_Logging_Config.Duplicates.ValueString() != types.StringNull().ValueString() {
			policyEvaluationLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			managementServiceLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			systemAdminLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
			securityAdminLogger.Duplicates = common.TrimString(plan.Client_Logging_Config.Duplicates.String())
		}
		if plan.Client_Logging_Config.FileEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			policyEvaluationLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			systemAdminLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
			securityAdminLogger.FileEnabled = plan.Client_Logging_Config.FileEnabled.ValueBool()
		}
		if plan.Client_Logging_Config.SyslogEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			policyEvaluationLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			securityAdminLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()
			systemAdminLogger.SyslogEnabled = plan.Client_Logging_Config.SyslogEnabled.ValueBool()

		}
		if plan.Client_Logging_Config.Threshold.ValueString() != "" && plan.Client_Logging_Config.Threshold.ValueString() != types.StringNull().ValueString() {
			managementServiceLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.ValueString())
			policyEvaluationLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.String())
			securityAdminLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.ValueString())
			systemAdminLogger.Threshold = common.TrimString(plan.Client_Logging_Config.Threshold.String())

		}
		if plan.Client_Logging_Config.UploadEnabled.ValueBool() != types.BoolNull().ValueBool() {
			managementServiceLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			policyEvaluationLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			securityAdminLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()
			systemAdminLogger.UploadEnabled = plan.Client_Logging_Config.UploadEnabled.ValueBool()

		}
		payload.ManagementServiceLogger = &managementServiceLogger
		payload.SecurityAdminLogger = &securityAdminLogger
		payload.SystemAdminLogger = &systemAdminLogger
		payload.PolicyEvaluationLogger = &policyEvaluationLogger

	}

	if plan.MetadataScanInterval.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MetadataScanInterval = plan.MetadataScanInterval.ValueInt64()
	}
	if plan.MFAExemptUserSetID.ValueString() != "" && plan.MFAExemptUserSetID.ValueString() != types.StringNull().ValueString() {
		payload.MFAExemptUserSetID = common.TrimString(plan.MFAExemptUserSetID.ValueString())
	}
	if plan.OIDCConnectionID.ValueString() != "" && plan.OIDCConnectionID.ValueString() != types.StringNull().ValueString() {
		payload.OIDCConnectionID = common.TrimString(plan.OIDCConnectionID.ValueString())
	}

	// Add qos_schedules to the payload if set
	var qosSchedules []CTEProfileQOSScheduleJSON
	for _, schedule := range plan.QOSSchedules {
		var scheduleJSON CTEProfileQOSScheduleJSON
		if schedule.EndTimeHour.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.EndTimeHour = schedule.EndTimeHour.ValueInt64()
		}
		if schedule.EndTimeMin.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.EndTimeMin = schedule.EndTimeMin.ValueInt64()
		}
		if schedule.EndWeekday.ValueString() != "" && schedule.EndWeekday.ValueString() != types.StringNull().ValueString() {
			scheduleJSON.EndWeekday = string(schedule.EndWeekday.ValueString())
		}
		if schedule.StartTimeHour.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.StartTimeHour = schedule.StartTimeHour.ValueInt64()
		}
		if schedule.StartTimeMin.ValueInt64() != types.Int64Null().ValueInt64() {
			scheduleJSON.StartTimeMin = schedule.StartTimeMin.ValueInt64()
		}
		if schedule.StartWeekday.ValueString() != "" && schedule.StartWeekday.ValueString() != types.StringNull().ValueString() {
			scheduleJSON.StartWeekday = string(schedule.StartWeekday.ValueString())
		}
		qosSchedules = append(qosSchedules, scheduleJSON)
	}
	payload.QOSSchedules = &qosSchedules

	if plan.RWPOperation.ValueString() != "" && plan.RWPOperation.ValueString() != types.StringNull().ValueString() {
		payload.RWPOperation = common.TrimString(plan.RWPOperation.ValueString())
	}
	if plan.RWPProcessSet.ValueString() != "" && plan.RWPProcessSet.ValueString() != types.StringNull().ValueString() {
		payload.RWPProcessSet = common.TrimString(plan.RWPProcessSet.ValueString())
	}

	if plan.ServerResponseRate.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.ServerResponseRate = plan.ServerResponseRate.ValueInt64()
	}

	// Add server_settings to the payload if set
	var serverSettings []CTEProfileServiceSettingJSON
	for _, setting := range plan.ServerSettings {
		var serverSetting CTEProfileServiceSettingJSON
		if setting.HostName.ValueString() != "" && setting.HostName.ValueString() != types.StringNull().ValueString() {
			serverSetting.HostName = string(setting.HostName.ValueString())
		}
		if setting.Priority.ValueInt64() != types.Int64Null().ValueInt64() {
			serverSetting.Priority = setting.Priority.ValueInt64()
		}
		serverSettings = append(serverSettings, serverSetting)
	}
	payload.ServerSettings = &serverSettings

	// Set syslog_settings in the request
	var syslogSettings CTEProfileSyslogSettingsJSON
	if plan.SyslogSettings.Local.ValueBool() != types.BoolNull().ValueBool() {
		syslogSettings.Local = plan.SyslogSettings.Local.ValueBool()
	}
	if plan.SyslogSettings.Threshold.ValueString() != "" && plan.SyslogSettings.Threshold.ValueString() != types.StringNull().ValueString() {
		syslogSettings.Threshold = common.TrimString(plan.SyslogSettings.Threshold.String())
	}
	var servers []CTEProfileSyslogSettingServerJSON
	for _, item := range plan.SyslogSettings.Servers {
		var server CTEProfileSyslogSettingServerJSON
		if item.CACert.ValueString() != "" && item.CACert.ValueString() != types.StringNull().ValueString() {
			server.CACert = string(item.CACert.ValueString())
		}
		if item.Certificate.ValueString() != "" && item.Certificate.ValueString() != types.StringNull().ValueString() {
			server.Certificate = string(item.Certificate.ValueString())
		}
		if item.MessageFormat.ValueString() != "" && item.MessageFormat.ValueString() != types.StringNull().ValueString() {
			server.MessageFormat = string(item.MessageFormat.ValueString())
		}
		if item.Name.ValueString() != "" && item.Name.ValueString() != types.StringNull().ValueString() {
			server.Name = string(item.Name.ValueString())
		}
		if item.Port.ValueInt64() != types.Int64Null().ValueInt64() {
			server.Port = item.Port.ValueInt64()
		}
		if item.PrivateKey.ValueString() != "" && item.PrivateKey.ValueString() != types.StringNull().ValueString() {
			server.PrivateKey = string(item.PrivateKey.ValueString())
		}
		if item.Protocol.ValueString() != "" && item.Protocol.ValueString() != types.StringNull().ValueString() {
			server.Protocol = string(item.Protocol.ValueString())
		}
		servers = append(servers, server)
	}
	syslogSettings.Servers = servers
	payload.SyslogSettings = &syslogSettings

	// Set upload_settings in the request
	var uploadSettings CTEProfileUploadSettingsJSON
	if !reflect.DeepEqual((*CTEProfileUploadSettingsTFSDK)(nil), plan.UploadSettings) {
		tflog.Debug(ctx, "Cache should not be empty at this point")
		if plan.UploadSettings.ConnectionTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.ConnectionTimeout = plan.UploadSettings.ConnectionTimeout.ValueInt64()
		}
		if plan.UploadSettings.DropIfBusy.ValueBool() != types.BoolNull().ValueBool() {
			uploadSettings.DropIfBusy = plan.UploadSettings.DropIfBusy.ValueBool()
		}
		if plan.UploadSettings.JobCompletionTimeout.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.JobCompletionTimeout = plan.UploadSettings.JobCompletionTimeout.ValueInt64()
		}
		if plan.UploadSettings.MaxInterval.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MaxInterval = plan.UploadSettings.MaxInterval.ValueInt64()
		}
		if plan.UploadSettings.MaxMessages.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MaxMessages = plan.UploadSettings.MaxMessages.ValueInt64()
		}
		if plan.UploadSettings.MinInterval.ValueInt64() != types.Int64Null().ValueInt64() {
			uploadSettings.MinInterval = plan.UploadSettings.MinInterval.ValueInt64()
		}
		if plan.UploadSettings.Threshold.ValueString() != "" && plan.UploadSettings.Threshold.ValueString() != types.StringNull().ValueString() {
			uploadSettings.Threshold = common.TrimString(plan.UploadSettings.Threshold.String())
		}
		payload.UploadSettings = &uploadSettings
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_profile.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Profile Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_CTE_PROFILE, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_profile.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Profile on CipherTrust Manager: ",
			"Could not update CTE Profile, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEProfile) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEProfileTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_PROFILE, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_profile.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Profile",
			"Could not delete CTE Profile, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEProfile) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
