package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceScheduler{}
	_ datasource.DataSourceWithConfigure = &dataSourceScheduler{}
)

func NewDataSourceScheduler() datasource.DataSource {
	return &dataSourceScheduler{}
}

type dataSourceScheduler struct {
	client *common.Client
}

type DataSourceModelScheduler struct {
	Filters   types.Map              `tfsdk:"filters"`
	Scheduler []JobConfigParamsTFSDK `tfsdk:"scheduler"`
}

func (d *dataSourceScheduler) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduler_list"
}

func (d *dataSourceScheduler) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists CipherTrust Manager scheduler job configurations via the /v1/scheduler/job-configs API.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM scheduler job-configs list API. Supported keys: \"name\", \"id\", \"operation\", \"disabled\", \"cloud_name\" (matches cloud_name in cckm_synchronization and cckm_key_rotation jobs), \"expire_in\" (matches cckm_key_rotation jobs), \"createdBefore\", and \"createdAfter\" (RFC3339Nano timestamp or relative timestamp, e.g. \"-1Y-2M-5D\").",
			},
			"scheduler": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of scheduler job configurations matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the scheduler job configuration.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the job configuration.",
						},
						"operation": schema.StringAttribute{
							Computed:    true,
							Description: "The type of operation performed by this job configuration. One of: " + strings.Join(supportedOperations, ", ") + ".",
						},
						"run_at": schema.StringAttribute{
							Computed:    true,
							Description: runAt,
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description for the job configuration.",
						},
						"run_on": schema.StringAttribute{
							Computed:    true,
							Description: "The node(s) the job runs on. Default is 'any'. For database_backup, the default is the current node if in a cluster. This attribute is not supported in CDSPaaS.",
						},
						"disabled": schema.BoolAttribute{
							Computed:    true,
							Description: "By default, the job configuration starts in an active state. True indicates the job configuration is disabled.",
						},
						"start_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time when the job starts. Format: YYYY-MM-DDTHH:MM:SSZ.",
						},
						"end_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time when the job ends. Format: YYYY-MM-DDTHH:MM:SSZ.",
						},
						"database_backup_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Database backup operation specific arguments. Populated only when operation is \"database_backup\".",
							Attributes: map[string]schema.Attribute{
								"tied_to_hsm": schema.BoolAttribute{
									Computed:    true,
									Description: "If true, the system backup can only be restored to instances that use the same HSM partition. Valid only with the system scoped backup.",
								},
								"scope": schema.StringAttribute{
									Computed:    true,
									Description: "Scope of the backup to be taken - system (default) or domain.",
								},
								"retention_count": schema.Int64Attribute{
									Computed:    true,
									Description: "Number of backups saved for this job config. Default is an unlimited quantity.",
								},
								"do_scp": schema.BoolAttribute{
									Computed:    true,
									Description: "If true, the system backup will also be transferred to the external server via SCP.",
								},
								"description": schema.StringAttribute{
									Computed:    true,
									Description: "User defined description associated with the backup. This is stored along with the backup, and is returned while retrieving the backup information, or while listing backups. Users may find it useful to store various types of information here: a backup name or description, ID of the HSM the backup is tied to, etc.",
								},
								"connection": schema.StringAttribute{
									Computed:    true,
									Description: "Name or ID of the SCP connection which stores the details for SCP server.",
								},
								"backup_key": schema.StringAttribute{
									Computed:    true,
									Description: "ID of backup key used for encrypting the backup. The default backup key is used if this is not specified.",
								},
								"filters": schema.ListNestedAttribute{
									Computed:    true,
									Description: filterDescription,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"resource_type": schema.StringAttribute{
												Computed:    true,
												Description: "Type of resources to be backed up. Valid values are \"Keys\", \"cte_policies\", \"customer_fragments\" and, \"users_groups\".",
											},
											"resource_query": schema.StringAttribute{
												Computed:    true,
												Description: resourceQueryDescription,
											},
										},
									},
								},
							},
						},
						"cckm_key_rotation_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Cloud key rotation operation specific arguments. Populated only when operation is \"cckm_key_rotation\".",
							Attributes: map[string]schema.Attribute{
								"aws_retain_alias": schema.BoolAttribute{
									Computed:    true,
									Description: "Retain the alias and timestamp on the archived key after rotation. Applicable only to AWS key rotation.",
								},
								"rotate_material": schema.BoolAttribute{
									Computed: true,
									Description: "If true, rotate the key material during the key rotation job. " +
										"Valid for imported (BYOK) symmetric single-region AES keys in CipherTrustManager version 2.21 or later and " +
										"valid for imported (BYOK) symmetric multi-region AES keys in CipherTrustManager version 2.24 or later.",
								},
								"cloud_name": schema.StringAttribute{
									Computed:    true,
									Description: "Name of the cloud for which the key rotation is scheduled. Options are: " + strings.Join(cckmRotationClouds, ",") + ".",
								},
								"expiration": schema.StringAttribute{
									Computed: true,
									Description: "Expiration time of the new key. If not specified, the new key material never expires. " +
										"Use either 'Xd' for x days or 'Yh' for y hours.",
								},
								"expire_in": schema.StringAttribute{
									Computed: true,
									Description: "Period during which certain keys are going to expire. " +
										"The scheduler rotates the keys that are expiring in this period. " +
										"If not specified, the scheduler rotates all the keys. Use either 'Xd' for x days or 'Yh' for y hours.",
								},
								"rotation_after": schema.StringAttribute{
									Computed: true,
									Description: "Number of days after which the keys will be rotated. Specified as Xd for x days. " +
										"The first key rotation happens after x days of key creation; subsequent rotations happen every x days after the last rotation date.",
								},
							},
						},
						"cckm_synchronization_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Cloud key synchronization operation specific arguments. Populated only when operation is \"cckm_synchronization\".",
							Attributes: map[string]schema.Attribute{
								"cloud_name": schema.StringAttribute{
									Computed:    true,
									Description: "The cloud that is synchronized on schedule. Options are: " + strings.Join(cckmSyncClouds, ",") + ".",
								},
								"kms": schema.SetAttribute{
									ElementType: types.StringType,
									Computed:    true,
									Description: "A list of kms resource ID's for which AWS keys are synchronized. Unless synchronizing all AWS keys, at least one kms is required.",
								},
								"oci_vaults": schema.SetAttribute{
									ElementType: types.StringType,
									Computed:    true,
									Description: "A list of OCI vaults resource ID's for which OCI keys are synchronized. Unless synchronizing all OCI keys, at least one vault is required.",
								},
								"synchronize_all": schema.BoolAttribute{
									Computed:    true,
									Description: "True if all keys are synchronized.",
								}},
						},
						"uri":         schema.StringAttribute{Computed: true, Description: "A human readable unique identifier of the resource."},
						"account":     schema.StringAttribute{Computed: true, Description: "The account which owns this resource."},
						"created_at":  schema.StringAttribute{Computed: true, Description: "Date/time the resource was created."},
						"updated_at":  schema.StringAttribute{Computed: true, Description: "Date/time the resource was last updated."},
						"application": schema.StringAttribute{Computed: true, Description: "The application this resource belongs to."},
						"dev_account": schema.StringAttribute{Computed: true, Description: "The developer account which owns this resource's application."},
						"cckm_xks_credential_rotation_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "CCKM XKS credential rotation operation specific arguments. Populated only when operation is \"cckm_xks_credential_rotation\".",
							Attributes: map[string]schema.Attribute{
								"cloud_name": schema.StringAttribute{
									Computed:    true,
									Description: "Name of the cloud in which the rotation operation is triggered. The only supported value is 'aws'.",
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceScheduler) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[resource_scheduler.go -> Read][" + id + "]")
	var state DataSourceModelScheduler
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		strVal, ok := v.(types.String)
		if !ok || strVal.IsNull() || strVal.IsUnknown() {
			resp.Diagnostics.AddError(
				"Invalid filters input",
				fmt.Sprintf("Key %q in filters has an invalid or unconfigured string value", k),
			)
			return
		}
		kv := fmt.Sprintf("%s=%s&", k, strVal.ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_SCHEDULER_JOB_CONFIGS+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scheduler.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read scheduler job configs from CM",
			err.Error(),
		)
		return
	}

	schedulerJobConfigs := []CreateJobConfigParamsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &schedulerJobConfigs)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_scheduler.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read scheduler job configs from CM",
			err.Error(),
		)
		return
	}

	// Initialize to a non-nil empty slice so zero-match filters return [] not null (TFIN-556).
	state.Scheduler = []JobConfigParamsTFSDK{}
	for _, jobs := range schedulerJobConfigs {
		schedulerJobs := JobConfigParamsTFSDK{
			CreateJobConfigParamsTFSDKCommon: CreateJobConfigParamsTFSDKCommon{
				ID:          types.StringValue(jobs.ID),
				URI:         types.StringValue(jobs.URI),
				Account:     types.StringValue(jobs.Account),
				Application: types.StringValue(jobs.Application),
				DevAccount:  types.StringValue(jobs.DevAccount),
				CreatedAt:   types.StringValue(jobs.CreatedAt),
				UpdatedAt:   types.StringValue(jobs.UpdatedAt),
				Name:        types.StringValue(jobs.Name),
				Description: types.StringValue(jobs.Description),
				Operation:   types.StringValue(jobs.Operation),
				RunAt:       types.StringValue(jobs.RunAt),
				RunOn:       types.StringValue(jobs.RunOn),
				Disabled:    types.BoolValue(jobs.Disabled),
				StartDate: func() types.String {
					if jobs.StartDate != nil {
						return types.StringValue(*jobs.StartDate)
					}
					return types.StringValue("")
				}(),
				EndDate: func() types.String {
					if jobs.EndDate != nil {
						return types.StringValue(*jobs.EndDate)
					}
					return types.StringValue("")
				}(),
			},
		}

		switch jobs.Operation {
		case "database_backup":
			getDataBaseBackupParams(ctx, id, &schedulerJobs, jobs.JobConfigParams, &resp.Diagnostics, d.client.Log)
		case "cckm_key_rotation":
			getCCKMKeyRotationParams(ctx, id, &schedulerJobs, jobs.JobConfigParams, &resp.Diagnostics, d.client.Log)
		case "cckm_synchronization":
			getCCKMSynchronizationParams(ctx, id, &schedulerJobs, jobs.JobConfigParams, &resp.Diagnostics, d.client.Log)
		case "cckm_xks_credential_rotation":
			getCCKMCredentialRotationParams(ctx, id, &schedulerJobs, jobs.JobConfigParams, &resp.Diagnostics, d.client.Log)
		}
		state.Scheduler = append(state.Scheduler, schedulerJobs)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[resource_scheduler.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceScheduler) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func getDataBaseBackupParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics, logger hclog.Logger) {
	var dbBackupParams DatabaseBackupParamsJSON
	err := json.Unmarshal(jobConfigParams, &dbBackupParams)
	if err != nil {
		logger.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_scheduler.go -> Read][" + id + "]")
		diags.AddError(
			"Unable to read scheduler database backup params",
			err.Error(),
		)
	}
	schedulerJobs.DatabaseBackupParams = &DatabaseBackupParamsTFSDK{
		BackupKey:      types.StringValue(dbBackupParams.BackupKey),
		Connection:     types.StringValue(dbBackupParams.Connection),
		Description:    types.StringValue(dbBackupParams.Description),
		DoSCP:          types.BoolValue(dbBackupParams.DoSCP),
		Scope:          types.StringValue(dbBackupParams.Scope),
		TiedToHSM:      types.BoolValue(dbBackupParams.TiedToHSM),
		RetentionCount: types.Int64Value(dbBackupParams.RetentionCount),
		Filters: func() types.List {
			filterObjs := make([]attr.Value, 0)
			if dbBackupParams.Filters != nil {
				for _, filter := range *dbBackupParams.Filters {
					var resourceQueryStr string
					switch query := filter.ResourceQuery.(type) {
					case string:
						resourceQueryStr = query
					case map[string]interface{}:
						bytes, err := json.Marshal(query)
						if err != nil {
							resourceQueryStr = "error_serializing_resource_query"
						} else {
							resourceQueryStr = string(bytes)
						}
					default:
						resourceQueryStr = fmt.Sprintf("%v", query)
					}
					obj, objDiags := types.ObjectValue(BackupFilterElemType.AttrTypes, map[string]attr.Value{
						"resource_type":  types.StringValue(filter.ResourceType),
						"resource_query": types.StringValue(resourceQueryStr),
					})
					if objDiags.HasError() {
						diags.Append(objDiags...)
						continue
					}
					filterObjs = append(filterObjs, obj)
				}
			}
			list, listDiags := types.ListValue(BackupFilterElemType, filterObjs)
			if listDiags.HasError() {
				diags.Append(listDiags...)
				return types.ListValueMust(BackupFilterElemType, []attr.Value{})
			}
			return list
		}(),
	}
}

func getCCKMKeyRotationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics, logger hclog.Logger) {
	var cckmKeyRotationParams CCKMKeyRotationParamsJSON
	err := json.Unmarshal(jobConfigParams, &cckmKeyRotationParams)
	if err != nil {
		logger.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_scheduler.go -> Read][" + id + "]")
		diags.AddError(
			"Unable to read scheduler cckm key rotation params",
			err.Error(),
		)
		return
	}
	keyRotationParams := &CCKMKeyRotationParamsDatasourceTFSDK{
		CloudName:      types.StringValue(cckmKeyRotationParams.CloudName),
		AwsRetainAlias: types.BoolValue(cckmKeyRotationParams.RetainAlias),
		RotateMaterial: types.BoolValue(cckmKeyRotationParams.RotateMaterial),
	}
	if cckmKeyRotationParams.Expiration != nil {
		keyRotationParams.Expiration = types.StringValue(*cckmKeyRotationParams.Expiration)
	} else {
		keyRotationParams.Expiration = types.StringValue("")
	}
	if cckmKeyRotationParams.ExpireIn != nil {
		keyRotationParams.ExpireIn = types.StringValue(*cckmKeyRotationParams.ExpireIn)
	} else {
		keyRotationParams.ExpireIn = types.StringValue("")
	}
	if cckmKeyRotationParams.RotationAfter != nil {
		keyRotationParams.RotationAfter = types.StringValue(*cckmKeyRotationParams.RotationAfter)
	} else {
		keyRotationParams.RotationAfter = types.StringValue("")
	}
	schedulerJobs.CCKMKeyRotationParams = keyRotationParams
}

func getCCKMSynchronizationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics, logger hclog.Logger) {
	var cckmSyncParams CCKMSynchronizationParamsJSON
	err := json.Unmarshal(jobConfigParams, &cckmSyncParams)
	if err != nil {
		logger.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_scheduler.go -> Read][" + id + "]")
		diags.AddError(
			"Unable to read scheduler cckm key synchronization params",
			err.Error(),
		)
		return
	}
	synchronizationParams := &CCKMSynchronizationParamsTFSDK{
		CloudName: types.StringValue(cckmSyncParams.CloudName),
	}
	if cckmSyncParams.SynchronizeAll != nil {
		synchronizationParams.SyncAll = types.BoolValue(*cckmSyncParams.SynchronizeAll)
	}
	var kmsValues []attr.Value
	for _, kms := range cckmSyncParams.Kms {
		kmsValues = append(kmsValues, types.StringValue(kms))
	}
	kmses, d := types.SetValue(types.StringType, kmsValues)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	synchronizationParams.Kms = kmses
	var ociValues []attr.Value
	for _, vault := range cckmSyncParams.OCIVaults {
		ociValues = append(ociValues, types.StringValue(vault))
	}
	ociSet, d := types.SetValue(types.StringType, ociValues)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	synchronizationParams.OCIVaults = ociSet
	schedulerJobs.CCKMSynchronizationParams = synchronizationParams
}

func getCCKMCredentialRotationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics, logger hclog.Logger) {
	var rotateCredentialsParams CCKMXksRotateCredentialsParamsJSON
	err := json.Unmarshal(jobConfigParams, &rotateCredentialsParams)
	if err != nil {
		logger.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_scheduler.go -> Read][" + id + "]")
		diags.AddError(
			"Unable to read scheduler rotate credentials params",
			err.Error(),
		)
		return
	}
	schedulerJobs.CCKMXksRotateCredentialsParams = &CCKMXksRotateCredentialsParamsTFSDK{
		CloudName: types.StringValue(rotateCredentialsParams.CloudName),
	}
}
