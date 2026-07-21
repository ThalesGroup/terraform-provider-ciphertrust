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
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
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
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"scheduler": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"operation": schema.StringAttribute{
							Computed: true,
						},
						"run_at": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"run_on": schema.StringAttribute{
							Computed: true,
						},
						"disabled": schema.BoolAttribute{
							Computed: true,
						},
						"start_date": schema.StringAttribute{
							Computed: true,
						},
						"end_date": schema.StringAttribute{
							Computed: true,
						},
						"database_backup_params": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"tied_to_hsm": schema.BoolAttribute{
									Computed: true,
								},
								"scope": schema.StringAttribute{
									Computed: true,
								},
								"retention_count": schema.Int64Attribute{
									Computed: true,
								},
								"do_scp": schema.BoolAttribute{
									Computed: true,
								},
								"description": schema.StringAttribute{
									Computed: true,
								},
								"connection": schema.StringAttribute{
									Computed: true,
								},
								"backup_key": schema.StringAttribute{
									Computed: true,
								},
								"filters": schema.ListNestedAttribute{
									Computed: true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"resource_type": schema.StringAttribute{
												Computed: true,
											},
											"resource_query": schema.StringAttribute{
												Computed: true,
											},
										},
									},
								},
							},
						},
						"cckm_key_rotation_params": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"cloud_name": schema.StringAttribute{
									Computed: true,
								},
								"expiration": schema.StringAttribute{
									Computed: true,
								},
								"expire_in": schema.StringAttribute{
									Computed: true,
								},
								"rotation_after": schema.StringAttribute{
									Computed: true,
								},
								"aws_retain_alias": schema.BoolAttribute{
									Computed: true,
								},
								"rotate_material": schema.BoolAttribute{
									Computed: true,
								},
							},
						},
						"cckm_synchronization_params": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"cloud_name": schema.StringAttribute{
									Computed: true,
								},
								"kms": schema.SetAttribute{
									ElementType: types.StringType,
									Computed:    true,
								},
								"oci_vaults": schema.SetAttribute{
									ElementType: types.StringType,
									Computed:    true,
								},
								"synchronize_all": schema.BoolAttribute{
									Computed: true,
								}},
						},
						"uri":         schema.StringAttribute{Computed: true},
						"account":     schema.StringAttribute{Computed: true},
						"created_at":  schema.StringAttribute{Computed: true},
						"updated_at":  schema.StringAttribute{Computed: true},
						"application": schema.StringAttribute{Computed: true},
						"dev_account": schema.StringAttribute{Computed: true},
						"cckm_xks_credential_rotation_params": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"cloud_name": schema.StringAttribute{
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

func (d *dataSourceScheduler) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Read]["+id+"]")
	var state DataSourceModelScheduler
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_SCHEDULER_JOB_CONFIGS+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scheduler job configs from CM",
			err.Error(),
		)
		return
	}

	gjson.Parse(jsonStr).ForEach(func(_, item gjson.Result) bool {
		jobJSON := item.Raw

		var startDate, endDate types.String
		if r := gjson.Get(jobJSON, "start_date"); r.Exists() {
			startDate = types.StringValue(r.String())
		} else {
			startDate = types.StringNull()
		}
		if r := gjson.Get(jobJSON, "end_date"); r.Exists() {
			endDate = types.StringValue(r.String())
		} else {
			endDate = types.StringNull()
		}

		schedulerJobs := JobConfigParamsTFSDK{
			CreateJobConfigParamsTFSDKCommon: CreateJobConfigParamsTFSDKCommon{
				ID:          types.StringValue(gjson.Get(jobJSON, "id").String()),
				URI:         types.StringValue(gjson.Get(jobJSON, "uri").String()),
				Account:     types.StringValue(gjson.Get(jobJSON, "account").String()),
				Application: types.StringValue(gjson.Get(jobJSON, "application").String()),
				DevAccount:  types.StringValue(gjson.Get(jobJSON, "devAccount").String()),
				CreatedAt:   types.StringValue(gjson.Get(jobJSON, "createdAt").String()),
				UpdatedAt:   types.StringValue(gjson.Get(jobJSON, "updatedAt").String()),
				Name:        types.StringValue(gjson.Get(jobJSON, "name").String()),
				Description: types.StringValue(gjson.Get(jobJSON, "description").String()),
				Operation:   types.StringValue(gjson.Get(jobJSON, "operation").String()),
				RunAt:       types.StringValue(gjson.Get(jobJSON, "run_at").String()),
				RunOn:       types.StringValue(gjson.Get(jobJSON, "run_on").String()),
				Disabled:    types.BoolValue(gjson.Get(jobJSON, "disabled").Bool()),
				StartDate:   startDate,
				EndDate:     endDate,
			},
		}

		operation := gjson.Get(jobJSON, "operation").String()
		jobConfigParamsRaw := json.RawMessage("{}")
		if r := gjson.Get(jobJSON, "job_config_params"); r.Exists() {
			jobConfigParamsRaw = json.RawMessage(r.Raw)
		}

		switch operation {
		case "database_backup":
			getDataBaseBackupParams(ctx, id, &schedulerJobs, jobConfigParamsRaw, &resp.Diagnostics)
		case "cckm_key_rotation":
			getCCKMKeyRotationParams(ctx, id, &schedulerJobs, jobConfigParamsRaw, &resp.Diagnostics)
		case "cckm_synchronization":
			getCCKMSynchronizationParams(ctx, id, &schedulerJobs, jobConfigParamsRaw, &resp.Diagnostics)
		case "cckm_xks_credential_rotation":
			getCCKMCredentialRotationParams(ctx, id, &schedulerJobs, jobConfigParamsRaw, &resp.Diagnostics)
		}
		state.Scheduler = append(state.Scheduler, schedulerJobs)
		return true
	})

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Read]["+id+"]")
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

func getDataBaseBackupParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics) {
	var dbBackupParams DatabaseBackupParamsJSON
	err := json.Unmarshal(jobConfigParams, &dbBackupParams)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_scheduler.go -> Read]["+id+"]")
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

func getCCKMKeyRotationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics) {
	paramsJSON := string(jobConfigParams)
	keyRotationParams := &CCKMKeyRotationParamsDatasourceTFSDK{}

	if r := gjson.Get(paramsJSON, "cloud_name"); r.Exists() {
		keyRotationParams.CloudName = types.StringValue(r.String())
	} else {
		keyRotationParams.CloudName = types.StringNull()
	}
	if r := gjson.Get(paramsJSON, "expiration"); r.Exists() {
		keyRotationParams.Expiration = types.StringValue(r.String())
	} else {
		keyRotationParams.Expiration = types.StringNull()
	}
	if r := gjson.Get(paramsJSON, "expire_in"); r.Exists() {
		keyRotationParams.ExpireIn = types.StringValue(r.String())
	} else {
		keyRotationParams.ExpireIn = types.StringNull()
	}
	if r := gjson.Get(paramsJSON, "rotation_after"); r.Exists() {
		keyRotationParams.RotationAfter = types.StringValue(r.String())
	} else {
		keyRotationParams.RotationAfter = types.StringNull()
	}
	if r := gjson.Get(paramsJSON, "aws_param.retain_alias"); r.Exists() {
		keyRotationParams.AWSRetainAlias = types.BoolValue(r.Bool())
	} else {
		keyRotationParams.AWSRetainAlias = types.BoolNull()
	}
	if r := gjson.Get(paramsJSON, "aws_param.rotate_material"); r.Exists() {
		keyRotationParams.RotateMaterial = types.BoolValue(r.Bool())
	} else {
		keyRotationParams.RotateMaterial = types.BoolNull()
	}
	schedulerJobs.CCKMKeyRotationParams = keyRotationParams
}

func getCCKMSynchronizationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics) {
	var cckmSyncParams CCKMSynchronizationParamsJSON
	err := json.Unmarshal(jobConfigParams, &cckmSyncParams)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_scheduler.go -> Read]["+id+"]")
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

func getCCKMCredentialRotationParams(ctx context.Context, id string, schedulerJobs *JobConfigParamsTFSDK, jobConfigParams json.RawMessage, diags *diag.Diagnostics) {
	var rotateCredentialsParams CCKMXksRotateCredentialsParamsJSON
	err := json.Unmarshal(jobConfigParams, &rotateCredentialsParams)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_scheduler.go -> Read]["+id+"]")
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
