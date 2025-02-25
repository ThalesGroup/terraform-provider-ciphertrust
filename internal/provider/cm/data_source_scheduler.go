package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	Filters   types.Map                    `tfsdk:"filters"`
	Scheduler []CreateJobConfigParamsTFSDK `tfsdk:"scheduler"`
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
						"uri":         schema.StringAttribute{Computed: true},
						"account":     schema.StringAttribute{Computed: true},
						"created_at":  schema.StringAttribute{Computed: true},
						"updated_at":  schema.StringAttribute{Computed: true},
						"application": schema.StringAttribute{Computed: true},
						"dev_account": schema.StringAttribute{Computed: true},
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

	schedulerJobConfigs := []CreateJobConfigParamsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &schedulerJobConfigs)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scheduler job configs from CM",
			err.Error(),
		)
		return
	}

	for _, jobs := range schedulerJobConfigs {
		schedulerJobs := CreateJobConfigParamsTFSDK{
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
			StartDate:   types.StringValue(jobs.StartDate.Format(time.RFC3339)),
			EndDate:     types.StringValue(jobs.EndDate.Format(time.RFC3339)),
		}

		switch jobs.Operation {
		case "database_backup":
			getDataBaseBackupParams(jobs, &schedulerJobs)
		}
		state.Scheduler = append(state.Scheduler, schedulerJobs)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceScheduler) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func getDataBaseBackupParams(jobs CreateJobConfigParamsListJSON, schedulerJobs *CreateJobConfigParamsTFSDK) {
	if jobs.DatabaseBackupParams != nil {
		schedulerJobs.DatabaseBackupParams = &DatabaseBackupParamsTFSDK{
			BackupKey:      types.StringValue(jobs.DatabaseBackupParams.BackupKey),
			Connection:     types.StringValue(jobs.DatabaseBackupParams.Connection),
			Description:    types.StringValue(jobs.DatabaseBackupParams.Description),
			DoSCP:          types.BoolValue(jobs.DatabaseBackupParams.DoSCP),
			Scope:          types.StringValue(jobs.DatabaseBackupParams.Scope),
			TiedToHSM:      types.BoolValue(jobs.DatabaseBackupParams.TiedToHSM),
			RetentionCount: types.Int64Value(jobs.DatabaseBackupParams.RetentionCount),
			Filters: func() []BackupFilterTFSDK {
				var filters []BackupFilterTFSDK
				if jobs.DatabaseBackupParams.Filters != nil {
					for _, filter := range *jobs.DatabaseBackupParams.Filters {
						var resourceQueryStr string

						// Handle ResourceQuery which is an interface
						switch query := filter.ResourceQuery.(type) {
						case string:
							resourceQueryStr = query
						case map[string]interface{}:
							// Serialize map into a JSON string
							bytes, err := json.Marshal(query)
							if err != nil {
								resourceQueryStr = "error_serializing_resource_query"
							} else {
								resourceQueryStr = string(bytes)
							}
						default:
							resourceQueryStr = fmt.Sprintf("%v", query)
						}

						filters = append(filters, BackupFilterTFSDK{
							ResourceType:  types.StringValue(filter.ResourceType),
							ResourceQuery: types.StringValue(resourceQueryStr),
						})
					}
				}
				return filters
			}(),
		}
	}
}
