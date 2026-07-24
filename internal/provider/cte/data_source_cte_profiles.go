package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceCTEProfiles{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEProfiles{}
)

func NewDataSourceCTEProfiles() datasource.DataSource {
	return &dataSourceCTEProfiles{}
}

type dataSourceCTEProfiles struct {
	client *common.Client
}

type CTEProfilesDataSourceModel struct {
	Profiles []CTEProfilesListTFSDK `tfsdk:"cte_profiles"`
}

func (d *dataSourceCTEProfiles) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_profiles"
}

func (d *dataSourceCTEProfiles) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"cte_profiles": schema.ListNestedAttribute{
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
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"cache_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Cache settings for the server.",
							Attributes: map[string]schema.Attribute{
								"max_files": schema.Int64Attribute{
									Computed:    true,
									Description: "Maximum number of files. Minimum value is 200.",
								},
								"max_space": schema.Int64Attribute{
									Computed:    true,
									Description: "Max Space. Minimum value is 100 MB.",
								},
							},
						},
						"concise_logging": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether to allow concise logging.",
						},
						"connect_timeout": schema.Int64Attribute{
							Computed:    true,
							Description: "Connect timeout in seconds. Valid values are 5 to 150.",
						},
						"duplicate_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Duplicate setting parameters.",
							Attributes: map[string]schema.Attribute{
								"suppress_interval": schema.Int64Attribute{
									Computed:    true,
									Description: "Suppress interval in seconds. Valid values are 1 to 1000.",
								},
								"suppress_threshold": schema.Int64Attribute{
									Computed:    true,
									Description: "Suppress threshold. Valid values are 1 to 100.",
								},
							},
						},
						"file_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "File settings for the profile.",
							Attributes: map[string]schema.Attribute{
								"allow_purge": schema.BoolAttribute{
									Computed:    true,
									Description: "Allows purge.",
								},
								"file_threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Applicable file threshold. ",
								},
								"max_file_size": schema.Int64Attribute{
									Computed:    true,
									Description: "Maximum file size(bytes) 1,000 - 1,000,000,000 (1KB to 1GB).",
								},
								"max_old_files": schema.Int64Attribute{
									Computed:    true,
									Description: "Maximum number of old files allowed. Valid values are 1 to 100.",
								},
							},
						},
						"ldt_qos_cap_cpu_allocation": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether to allow CPU allocation for Quality of Service (QoS) capabilities.",
						},
						"ldt_qos_cpu_percent": schema.Int64Attribute{
							Computed:    true,
							Description: "CPU application percentage if ldt_qos_cap_cpu_allocation is true. Valid values are 0 to 100.",
						},
						"ldt_qos_rekey_option": schema.StringAttribute{
							Computed:    true,
							Description: "Rekey option and applicable options are RekeyRate and CPU.",
						},
						"ldt_qos_rekey_rate": schema.Int64Attribute{
							Computed:    true,
							Description: "Rekey rate in terms of MB/s. Valid values are 0 to 32767.",
						},
						"ldt_qos_schedule": schema.StringAttribute{
							Computed:    true,
							Description: "Type of QoS schedule.",
						},
						"ldt_qos_status_check_rate": schema.Int64Attribute{
							Computed:    true,
							Description: "Frequency to check and update the LDT status on the CipherTrust Manager. The valid value ranges from 600 to 86400 seconds. The default value is 3600 seconds.",
						},
						"management_service_logger": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Logger configurations for the management service.",
							Attributes: map[string]schema.Attribute{
								"duplicates": schema.StringAttribute{
									Computed:    true,
									Description: "Control duplicate entries, ALLOW or SUPPRESS",
								},
								"file_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable file upload.",
								},
								"syslog_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable support for the Syslog server.",
								},
								"threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Threshold value",
								},
								"upload_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable log upload to the URL.",
								},
							},
						},
						"metadata_scan_interval": schema.Int64Attribute{
							Computed:    true,
							Description: "Time interval in seconds to scan files under the GuardPoint. The default value is 600.",
						},
						"mfa_exempt_user_set_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the user set to be exempted from MFA. MFA will not be enforced on the users of this set.",
						},
						"mfa_exempt_user_set_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the user set to be exempted from MFA. MFA will not be enforced on the users of this set.",
						},
						"oidc_connection_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the OIDC connection.",
						},
						"oidc_connection_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the OIDC connection.",
						},
						"policy_evaluation_logger": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Logger configurations for policy evaluation.",
							Attributes: map[string]schema.Attribute{
								"duplicates": schema.StringAttribute{
									Computed:    true,
									Description: "Control duplicate entries, ALLOW or SUPPRESS",
								},
								"file_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable file upload.",
								},
								"syslog_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable support for the Syslog server.",
								},
								"threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Threshold value",
								},
								"upload_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable log upload to the URL.",
								},
							},
						},
						"qos_schedules": schema.ListNestedAttribute{
							Computed:    true,
							Description: "Schedule of QoS capabilities.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"end_time_hour": schema.Int64Attribute{
										Computed:    true,
										Description: "QoS end hour. Valid values are 1 to 23.",
									},
									"end_time_min": schema.Int64Attribute{
										Computed:    true,
										Description: "QoS end minute. Valid values are 0 to 59.",
									},
									"end_weekday": schema.StringAttribute{
										Computed:    true,
										Description: "QoS end day.",
									},
									"start_time_hour": schema.Int64Attribute{
										Computed:    true,
										Description: "QOS start hour. Valid values are 1 to 23.",
									},
									"start_time_min": schema.Int64Attribute{
										Computed:    true,
										Description: "QOS start minute. Valid values are 0 to 59.",
									},
									"start_weekday": schema.StringAttribute{
										Computed:    true,
										Description: "QoS start day.",
									},
								},
							},
						},
						"rwp_operation": schema.StringAttribute{
							Computed:    true,
							Description: "Applicable to the Ransomware clients only. The valid values are permit(for Audit), deny(for Block), and disable. The default value is deny.",
						},
						"rwp_process_set": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the process set to be whitelisted.",
						},
						"security_admin_logger": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Logger configurations for security administrators.",
							Attributes: map[string]schema.Attribute{
								"duplicates": schema.StringAttribute{
									Computed:    true,
									Description: "Control duplicate entries, ALLOW or SUPPRESS",
								},
								"file_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable file upload.",
								},
								"syslog_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable support for the Syslog server.",
								},
								"threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Threshold value",
								},
								"upload_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable log upload to the URL.",
								},
							},
						},
						"server_response_rate": schema.Int64Attribute{
							Computed:    true,
							Description: "the percentage value of successful API calls to the server, for which the agent will consider the server to be working fine. If the value is set to 75 then, if the server responds to 75% of the calls it is considered OK & no update is sent by agent. Valid values are between 0 to 100, both inclusive. Default value is 0.",
						},
						"server_settings": schema.ListNestedAttribute{
							Computed:    true,
							Description: "Server configuration of cluster nodes. These settings are allowed only in cluster environment.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"host_name": schema.StringAttribute{
										Computed:    true,
										Description: "Host name of the cluster node.",
									},
									"priority": schema.StringAttribute{
										Computed:    true,
										Description: "Priority of the cluster node. Valid values are 1 to 100.",
									},
								},
							},
						},
						"syslog_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Parameters to configure the Syslog server.",
							Attributes: map[string]schema.Attribute{
								"local": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the Syslog server is local.",
								},
								"syslog_threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Applicable threshold.",
								},
								"servers": schema.ListNestedAttribute{
									Computed:    true,
									Description: "Configuration of the Syslog server.",
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"ca_certificate": schema.StringAttribute{
												Computed:    true,
												Description: "CA certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----\n<certificate content>\n-----END CERTIFICATE--------",
											},
											"certificate": schema.StringAttribute{
												Computed:    true,
												Description: "Client certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----\n<certificate content>\n-----END CERTIFICATE--------",
											},
											"message_format": schema.StringAttribute{
												Computed:    true,
												Description: "Format of the message on the Syslog server.",
											},
											"name": schema.StringAttribute{
												Computed:    true,
												Description: "Name of the Syslog server.",
											},
											"port": schema.Int64Attribute{
												Computed:    true,
												Description: "Port for syslog server. Valid values are 1 to 65535.",
											},
											"private_key": schema.StringAttribute{
												Computed:    true,
												Sensitive:   true,
												Description: "Client certificate for syslog application provided by the client. for example: -----BEGIN RSA PRIVATE KEY-----\n<key content>\n-----END RSA PRIVATE KEY-----",
											},
											"protocol": schema.StringAttribute{
												Computed:    true,
												Description: "Protocol of the Syslog server, TCP, UDP and TLS.",
											},
										},
									},
								},
							},
						},
						"system_admin_logger": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Logger configurations for the System administrator.",
							Attributes: map[string]schema.Attribute{
								"duplicates": schema.StringAttribute{
									Computed:    true,
									Description: "Control duplicate entries, ALLOW or SUPPRESS",
								},
								"file_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable file upload.",
								},
								"syslog_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable support for the Syslog server.",
								},
								"threshold": schema.StringAttribute{
									Computed:    true,
									Description: "Threshold value",
								},
								"upload_enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to enable log upload to the URL.",
								},
							},
						},
						"upload_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Configure log upload to the Syslog server.",
							Attributes: map[string]schema.Attribute{
								"upload_threshold": schema.StringAttribute{
									Computed: true,
								},
								"drop_if_busy": schema.BoolAttribute{
									Computed: true,
								},
								"max_interval": schema.Int64Attribute{
									Computed: true,
								},
								"min_interval": schema.Int64Attribute{
									Computed: true,
								},
								"max_messages": schema.Int64Attribute{
									Computed: true,
								},
								"job_completion_timeout": schema.Int64Attribute{
									Computed: true,
								},
								"connection_timeout": schema.Int64Attribute{
									Computed: true,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEProfiles) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_profiles.go -> Read]["+id+"]")
	var state CTEProfilesDataSourceModel

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_CTE_PROFILE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_profiles.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Client profiles from CM",
			err.Error(),
		)
		return
	}

	profiles := []CTEProfilesListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &profiles)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_profiles.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Client profiles from CM",
			err.Error(),
		)
		return
	}

	for _, profile := range profiles {
		profileState := CTEProfilesListTFSDK{}
		profileState.ID = types.StringValue(profile.ID)
		profileState.URI = types.StringValue(profile.URI)
		profileState.Account = types.StringValue(profile.Account)
		profileState.Application = types.StringValue(profile.Application)
		profileState.CreatedAt = types.StringValue(profile.CreatedAt)
		profileState.Name = types.StringValue(profile.Name)
		profileState.UpdatedAt = types.StringValue(profile.UpdatedAt)
		profileState.Description = types.StringValue(profile.Description)
		profileState.LDTQOSStatusCheckRate = types.Int64Value(profile.LDTQOSStatusCheckRate)
		profileState.LDTQOSCapCPUAllocation = types.BoolValue(profile.LDTQOSCapCPUAllocation)
		profileState.LDTQOSCapCPUPercent = types.Int64Value(profile.LDTQOSCapCPUPercent)
		profileState.LDTQOSRekeyOption = types.StringValue(profile.LDTQOSRekeyOption)
		profileState.LDTQOSRekeyRate = types.Int64Value(profile.LDTQOSRekeyRate)
		profileState.ConciseLogging = types.BoolValue(profile.ConciseLogging)
		profileState.ConnectTimeout = types.Int64Value(profile.ConnectTimeout)
		profileState.LDTQOSSchedule = types.StringValue(profile.LDTQOSSchedule)
		profileState.LDTQOSStatusCheckRate = types.Int64Value(profile.LDTQOSStatusCheckRate)
		profileState.MetadataScanInterval = types.Int64Value(profile.MetadataScanInterval)
		profileState.MFAExemptUserSetID = types.StringValue(profile.MFAExemptUserSetID)
		profileState.MFAExemptUserSetName = types.StringValue(profile.MFAExemptUserSetName)
		profileState.OIDCConnectionID = types.StringValue(profile.OIDCConnectionID)
		profileState.OIDCConnectionName = types.StringValue(profile.OIDCConnectionName)
		profileState.RWPOperation = types.StringValue(profile.RWPOperation)
		profileState.RWPProcessSet = types.StringValue(profile.RWPProcessSet)
		profileState.ServerResponseRate = types.Int64Value(profile.ServerResponseRate)
		if profile.CacheSettings != nil {
			profileState.CacheSettings = &CTEProfileCacheSettingsTFSDK{
				MaxFiles: types.Int64Value(profile.CacheSettings.MaxFiles),
				MaxSpace: types.Int64Value(profile.CacheSettings.MaxSpace),
			}
		}

		if profile.DuplicateSettings != nil {
			profileState.DuplicateSettings = &CTEProfileDuplicateSettingsTFSDK{
				SuppressInterval:  types.Int64Value(profile.DuplicateSettings.SuppressInterval),
				SuppressThreshold: types.Int64Value(profile.DuplicateSettings.SuppressThreshold),
			}
		}
		profileState.FileSettings = &CTEProfileFileSettingsTFSDK{
			AllowPurge:    types.BoolValue(profile.FileSettings.AllowPurge),
			FileThreshold: types.StringValue(profile.FileSettings.FileThreshold),
			MaxFileSize:   types.Int64Value(profile.FileSettings.MaxFileSize),
			MaxOldFiles:   types.Int64Value(profile.FileSettings.MaxOldFiles),
		}
		profileState.ManagementServiceLogger = &CTEProfileManagementServiceLoggerTFSDK{
			Duplicates:    types.StringValue(profile.ManagementServiceLogger.Duplicates),
			FileEnabled:   types.BoolValue(profile.ManagementServiceLogger.FileEnabled),
			SyslogEnabled: types.BoolValue(profile.ManagementServiceLogger.SyslogEnabled),
			Threshold:     types.StringValue(profile.ManagementServiceLogger.Threshold),
			UploadEnabled: types.BoolValue(profile.ManagementServiceLogger.UploadEnabled),
		}
		profileState.PolicyEvaluationLogger = &CTEProfileManagementServiceLoggerTFSDK{
			Duplicates:    types.StringValue(profile.ManagementServiceLogger.Duplicates),
			FileEnabled:   types.BoolValue(profile.ManagementServiceLogger.FileEnabled),
			SyslogEnabled: types.BoolValue(profile.ManagementServiceLogger.SyslogEnabled),
			Threshold:     types.StringValue(profile.ManagementServiceLogger.Threshold),
			UploadEnabled: types.BoolValue(profile.ManagementServiceLogger.UploadEnabled),
		}
		profileState.SecurityAdminLogger = &CTEProfileManagementServiceLoggerTFSDK{
			Duplicates:    types.StringValue(profile.ManagementServiceLogger.Duplicates),
			FileEnabled:   types.BoolValue(profile.ManagementServiceLogger.FileEnabled),
			SyslogEnabled: types.BoolValue(profile.ManagementServiceLogger.SyslogEnabled),
			Threshold:     types.StringValue(profile.ManagementServiceLogger.Threshold),
			UploadEnabled: types.BoolValue(profile.ManagementServiceLogger.UploadEnabled),
		}
		profileState.SystemAdminLogger = &CTEProfileManagementServiceLoggerTFSDK{
			Duplicates:    types.StringValue(profile.ManagementServiceLogger.Duplicates),
			FileEnabled:   types.BoolValue(profile.ManagementServiceLogger.FileEnabled),
			SyslogEnabled: types.BoolValue(profile.ManagementServiceLogger.SyslogEnabled),
			Threshold:     types.StringValue(profile.ManagementServiceLogger.Threshold),
			UploadEnabled: types.BoolValue(profile.ManagementServiceLogger.UploadEnabled),
		}
		if profile.SyslogSettings != nil {
			syslog := &CTEProfileSyslogSettingsTFSDK{
				Local:     types.BoolValue(profile.SyslogSettings.Local),
				Threshold: types.StringValue(profile.SyslogSettings.Threshold),
			}
			for _, s := range profile.SyslogSettings.Servers {
				syslog.Servers = append(syslog.Servers, CTEProfileSyslogSettingServerTFSDK{
					CACert:        types.StringValue(s.CACert),
					Certificate:   types.StringValue(s.Certificate),
					MessageFormat: types.StringValue(s.MessageFormat),
					Name:          types.StringValue(s.Name),
					Port:          types.Int64Value(s.Port),
					PrivateKey:    types.StringValue(s.PrivateKey),
					Protocol:      types.StringValue(s.Protocol),
				})
			}
			profileState.SyslogSettings = syslog
		}

		if profile.UploadSettings != nil {
			profileState.UploadSettings = &CTEProfileUploadSettingsTFSDK{
				ConnectionTimeout:    types.Int64Value(profile.UploadSettings.ConnectionTimeout),
				DropIfBusy:           types.BoolValue(profile.UploadSettings.DropIfBusy),
				JobCompletionTimeout: types.Int64Value(profile.UploadSettings.JobCompletionTimeout),
				Threshold:            types.StringValue(profile.UploadSettings.Threshold),
				MaxInterval:          types.Int64Value(profile.UploadSettings.MaxInterval),
				MinInterval:          types.Int64Value(profile.UploadSettings.MinInterval),
				MaxMessages:          types.Int64Value(profile.UploadSettings.MaxMessages),
			}
		}

		if profile.QOSSchedules != nil {
			for _, q := range profile.QOSSchedules {
				profileState.QOSSchedules = append(profileState.QOSSchedules, CTEProfileQOSScheduleTFSDK{
					EndTimeHour:   types.Int64Value(q.EndTimeHour),
					EndTimeMin:    types.Int64Value(q.EndTimeMin),
					EndWeekday:    types.StringValue(q.EndWeekday),
					StartTimeHour: types.Int64Value(q.StartTimeHour),
					StartTimeMin:  types.Int64Value(q.StartTimeMin),
					StartWeekday:  types.StringValue(q.StartWeekday),
				})
			}
		}

		if profile.ServerSettings != nil {
			for _, s := range profile.ServerSettings {
				profileState.ServerSettings = append(profileState.ServerSettings, CTEProfileServiceSettingTFSDK{
					HostName: types.StringValue(s.HostName),
					Priority: types.Int64Value(s.Priority),
				})
			}
		}

		state.Profiles = append(state.Profiles, profileState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_profiles.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEProfiles) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
