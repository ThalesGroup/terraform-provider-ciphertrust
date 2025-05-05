package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"regexp"
	"strings"
	"time"

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
	_ resource.Resource              = &resourceScheduler{}
	_ resource.ResourceWithConfigure = &resourceScheduler{}

	runAt = `Described using the cron expression format : "* * * * *" These five values indicate when the job should be executed. They are in order of minute, hour, day of month, month, and day of week. Valid values are 0-59 (minutes), 0-23 (hours), 1-31 (day of month), 1-12 or jan-dec (month), and 0-6 or sun-sat (day of week). Names are case insensitive. For use of special characters, consult the Time Specification description at the top of this page.

For example:

    To run every min: "* * * * *"
    To run on Saturday at 23:45(11:45 PM): "45 23 * * 6"
    To run on Monday at 09:00: "0 9 * * 1"
`
	filterDescription        = `A set of selection criteria to specify what resources to include in the backup. Only applicable to domain-scoped backups. By default, no filters are applied and the backup includes all keys. For example, to back up all keys with a name containing 'enc-key', set the filters to [{"resourceType": "Keys", "resourceQuery":{"name":"*enc-key*"}}].`
	resourceQueryDescription = `A JSON object containing resource attributes and attribute values to be queried. The resources returned in the query are backed up. If empty, all the resources of the specified resourceType will be backed up. For Keys, valid resourceQuery paramater values are the same as the body of the 'vault/query-keys' POST endpoint described on the Keys page. If multiple parameters of 'vault/query-keys' are provided then the result will be AND of all. To back up AES keys with a meta parameter value containing {"info":{"color":"red"}}}, use {"algorithm":"AES", "metaContains": {"info":{"color":"red"}}}. To backup specific keys using names, use {"names":["key1", "key2"]}.

For CTE policies, valid resourceQuery parameter values are the same as query parameters of the list '/v1/transparent-encryption/policies' endpoint described in the CTE > Policies section. For example, to back up LDT policies only, use {"policy_type":"LDT"}. Similarly, to back up policies with learn mode enabled, use {"never_deny": true}. For users, the valid resourceQuery parameter values are the same as query parameters of the list '/v1/usermgmt/users' endpoint as described in the “Users” page. For example, to back up all users with name "frank" and email id "frank@local", use {"name":"frank","email": "frank@local"}.

For Customer fragments, valid resourceQuery parameter values are 'ids' and 'names' of Customer fragments. To backup specific customer fragments using ids, use {"ids":["370c4373-2675-4aa1-8cc7-07a9f95a5861", "4e1b9dec-2e38-40d7-b4d6-244043200546"]}. To backup specific customer fragments using names, use {"names":["customerFragment1", "customerFragment2"]}.

Note: When providing resource_query as a JSON string, ensure proper escaping of special characters like quotes (") and use \n for line breaks if entering the JSON in multiple lines.
For example: "{\"ids\": ["56fc2127-3a96-428e-b93b-ab169728c23c", "a6c8d8eb-1b69-42f0-97d7-4f0845fbf602"]}"
`
	cckmRotationClouds  = []string{"aws"}
	cckmSyncClouds      = []string{"aws"}
	supportedOperations = []string{"database_backup", "cckm_key_rotation", "cckm_synchronization", "cckm_xks_credential_rotation"}
)

const (
	schedulerDateRegEx = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
)

func NewResourceScheduler() resource.Resource {
	return &resourceScheduler{}
}

type resourceScheduler struct {
	client *common.Client
}

func (r *resourceScheduler) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduler"
}

// Schema defines the schema for the resource.
func (r *resourceScheduler) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates a new job configuration. The 'database_backup_params', 'cckm_synchronization_params' and 'cckm_key_rotation_params' fields are mutually exclusive, ie: cannot be set simultaneously.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the job configuration.",
			},
			"operation": schema.StringAttribute{
				Required:    true,
				Description: "The operation field specifies the type of operation to be performed. Currently, only " + strings.Join(supportedOperations, ", ") + " are supported. ",
				Validators: []validator.String{
					stringvalidator.OneOf(supportedOperations...),
				},
			},
			"run_at": schema.StringAttribute{
				Required:    true,
				Description: runAt,
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Description for the job configuration.",
			},
			"run_on": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Default is 'any'. For database_backup, the default will be the current node if in a cluster.",
			},
			"disabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "By default, the job configuration starts in an active state. True disables the job configuration.",
			},
			"start_date": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Date the job configuration becomes active. RFC3339 format. For example, 2018-10-02T14:24:37.436073Z",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(schedulerDateRegEx),
						"Must conform to the format: YYYY-MM-DDTHH:MM:SSZ (e.g., 2021-03-07T00:00:00Z).",
					),
				},
			},
			"end_date": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Date the job configuration becomes inactive. RFC3339 format. For example, 2018-10-02T14:24:37.436073Z",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(schedulerDateRegEx),
						"Must conform to the format: YYYY-MM-DDTHH:MM:SSZ (e.g., 2021-03-07T00:00:00Z).",
					),
				},
			},

			"database_backup_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Object{
					common.NewObjectUseStateForUnknown(),
				},
				Description: "Database backup operation specific arguments. Should be JSON-serializable. Required only for \"database_backup\" operations. Not allowed for other operations.",
				Attributes: map[string]schema.Attribute{
					"tied_to_hsm": schema.BoolAttribute{
						Computed:    true,
						Optional:    true,
						Description: "If true, the system backup can only be restored to instances that use the same HSM partition. Valid only with the system scoped backup.",
					},
					"scope": schema.StringAttribute{
						Computed:    true,
						Optional:    true,
						Description: "Scope of the backup to be taken - system (default) or domain.",
					},
					"retention_count": schema.Int64Attribute{
						Computed:    true,
						Optional:    true,
						Description: "Number of backups saved for this job config. Default is an unlimited quantity.",
					},
					"do_scp": schema.BoolAttribute{
						Computed:    true,
						Optional:    true,
						Description: "If true, the system backup will also be transferred to the external server via SCP.",
					},
					"description": schema.StringAttribute{
						Computed:    true,
						Optional:    true,
						Description: "User defined description associated with the backup. This is stored along with the backup, and is returned while retrieving the backup information, or while listing backups. Users may find it useful to store various types of information here: a backup name or description, ID of the HSM the backup is tied to, etc.",
					},
					"connection": schema.StringAttribute{
						Computed:    true,
						Optional:    true,
						Description: "Name or ID of the SCP connection which stores the details for SCP server.",
					},
					"backup_key": schema.StringAttribute{
						Computed:    true,
						Optional:    true,
						Description: "ID of backup key used for encrypting the backup. The default backup key is used if this is not specified.",
					},
					"filters": schema.ListNestedAttribute{
						Optional: true,
						Computed: true,
						PlanModifiers: []planmodifier.List{
							common.NewListUseStateForUnknown(),
						},
						Description: filterDescription,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"resource_type": schema.StringAttribute{
									Required:    true,
									Description: "Type of resources to be backed up. Valid values are \"Keys\", \"cte_policies\", \"customer_fragments\" and, \"users_groups\".",
								},
								"resource_query": schema.StringAttribute{
									Optional:    true,
									Computed:    true,
									Description: resourceQueryDescription,
								},
							},
						},
					},
				},
			},
			"cckm_xks_credential_rotation_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Object{
					common.NewObjectUseStateForUnknown(),
				},
				Description: "CCKM XKS credential rotation operation specific arguments.",
				Attributes: map[string]schema.Attribute{
					"cloud_name": schema.StringAttribute{
						Computed:    true,
						Optional:    true,
						Description: "Name of the cloud in which the Rotation operation will be triggered. The only supported value is 'aws'.",
						Validators: []validator.String{
							stringvalidator.OneOf("aws"),
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
		Blocks: map[string]schema.Block{
			"cckm_key_rotation_params": schema.ListNestedBlock{
				Description: "Specifies cloud key rotation parameters",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"aws_retain_alias": schema.BoolAttribute{
							Optional:    true,
							Description: "Retain the alias and timestamp on the archived key after rotation. Applicable only to AWS key rotation.",
						},
						"cloud_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the cloud for which to schedule the key rotation. Options are: " + strings.Join(cckmRotationClouds, ",") + ".",
							Validators: []validator.String{
								stringvalidator.OneOf(cckmRotationClouds...),
							},
						},
						"expiration": schema.StringAttribute{
							Optional: true,
							Description: "Expiration time of the new key. If not specified, the new key material never expires. " +
								"For example, if you want the scheduler to the rotate keys that are expiring within six hours of its run, " +
								"set expire_in to 6h. Use either 'Xd' for x days or 'Yh' for y hours.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9]+[d|h]$`), "must contain either Xd for x days or Yh for y hours",
								),
							},
						},
						"expire_in": schema.StringAttribute{
							Optional: true,
							Description: "Period during which certain keys are going to expire. " +
								"The scheduler rotates the keys that are expiring in this period. " +
								"If not specified, the scheduler rotates all the keys. " +
								"For example, if you want the scheduler to rotate the keys that are expiring " +
								"within six hours of its run, set expire_in to 6h. Use either 'Xd' for x days or 'Yh' for y hours.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9]+[d|h]$`), "must contain either Xd for x days or Yh for y hours",
								),
							},
						},
					},
				},
			},
			"cckm_synchronization_params": schema.ListNestedBlock{
				Description: "Specifies cloud key synchronization parameters",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"cloud_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the cloud that will be synchronized on schedule. Options are: " + strings.Join(cckmSyncClouds, ",") + ".",
							Validators: []validator.String{
								stringvalidator.OneOf(cckmSyncClouds...),
							},
						},
						"kms": schema.SetAttribute{
							Optional:    true,
							Computed:    true,
							Description: "IDs or names of kms resources from which AWS keys will be synchronized. Unless synchronizing all AWS keys, At least one kms is required.",
							ElementType: types.StringType,
							Default: setdefault.StaticValue(
								types.SetValueMust(
									types.StringType,
									[]attr.Value{},
								),
							),
						},
						"synchronize_all": schema.BoolAttribute{
							Computed:    true,
							Default:     booldefault.StaticBool(false),
							Optional:    true,
							Description: "Set true to synchronize all keys.",
						},
					},
				},
			},
		},
	}
}

func (r *resourceScheduler) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Create]["+id+"]")

	var plan CreateJobConfigParamsTFSDK
	var payload CreateJobConfigParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Operation.ValueString() != "" && plan.Operation.ValueString() != types.StringNull().ValueString() {
		payload.Operation = plan.Operation.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.RunOn.ValueString() != "" && plan.RunOn.ValueString() != types.StringNull().ValueString() {
		payload.RunOn = plan.RunOn.ValueString()
	}

	if plan.RunAt.ValueString() != "" && plan.RunAt.ValueString() != types.StringNull().ValueString() {
		payload.RunAt = plan.RunAt.ValueString()
	}

	switch plan.Operation.ValueString() {
	case "database_backup":
		dbBackupParams := getDatabaseOperationBackupParams(plan)
		if dbBackupParams != nil {
			payload.DatabaseBackupParams = dbBackupParams
		}
	case "cckm_key_rotation":
		payload.CCKMKeyRotationParams = getCckmKeyRotationOperationParams(ctx, plan, &resp.Diagnostics)
		if diags.HasError() {
			return
		}
	case "cckm_synchronization":
		payload.CCKMSynchronizationParams = getCckmSyncParams(ctx, plan, &resp.Diagnostics)
		if diags.HasError() {
			return
		}
	case "cckm_xks_credential_rotation":
		rotateCredentialsParams := getCckmXksRotateCredentialsParams(plan)
		if rotateCredentialsParams != nil {
			payload.CCKMXksRotateCredentialsParams = rotateCredentialsParams
		}
	}

	if plan.StartDate.ValueString() != "" && plan.StartDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.StartDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided start_date is not in RFC3339 format ",
				"Error parsing the start_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.StartDate = parsedTime
	}

	if plan.EndDate.ValueString() != "" && plan.EndDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.EndDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided end_date is not in RFC3339 format ",
				"Error parsing the end_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.EndDate = parsedTime
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Scheduler Job Config creation failure",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_SCHEDULER_JOB_CONFIGS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Scheduler Job Configs on CipherTrust Manager: ",
			"Could not create scheduler job configs: "+err.Error(),
		)
		return
	}

	getParamsFromResponse(ctx, response, &plan, &resp.Diagnostics)
	if diags.HasError() {
		return
	}

	tflog.Debug(ctx, "[resource_scheduler.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceScheduler) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Read]["+id+"]")

	var state CreateJobConfigParamsTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_SCHEDULER_JOB_CONFIGS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Read Error", "Error fetching scheduler job configs : "+err.Error())
		return
	}
	getParamsFromResponse(ctx, response, &state, &resp.Diagnostics)
	if diags.HasError() {
		return
	}
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Operation = types.StringValue(gjson.Get(response, "operation").String())
	state.RunAt = types.StringValue(gjson.Get(response, "run_at").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

func (r *resourceScheduler) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Update]["+id+"]")

	var plan CreateJobConfigParamsTFSDK
	var state CreateJobConfigParamsTFSDK
	var payload UpdateJobConfigParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.Plan.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.RunOn.ValueString() != "" && plan.RunOn.ValueString() != types.StringNull().ValueString() {
		payload.RunOn = plan.RunOn.ValueString()
	}

	if plan.RunAt.ValueString() != "" && plan.RunAt.ValueString() != types.StringNull().ValueString() {
		payload.RunAt = plan.RunAt.ValueString()
	}

	switch plan.Operation.ValueString() {
	case "database_backup":
		dbBackupParams := getDatabaseOperationBackupParams(plan)
		if dbBackupParams != nil {
			payload.DatabaseBackupParams = dbBackupParams
		}
	case "cckm_key_rotation":
		payload.CCKMRotationParams = getCckmKeyRotationOperationParams(ctx, plan, &resp.Diagnostics)
		if diags.HasError() {
			return
		}
		payload.CCKMRotationParams.CloudName = ""
	case "cckm_synchronization":
		payload.CCKMSynchronizationParams = getCckmSyncParams(ctx, plan, &resp.Diagnostics)
		if diags.HasError() {
			return
		}
		payload.CCKMSynchronizationParams.CloudName = ""
	}

	if plan.StartDate.ValueString() != "" && plan.StartDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.StartDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided start_date is not in RFC3339 format ",
				"Error parsing the start_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.StartDate = parsedTime
	}

	if plan.EndDate.ValueString() != "" && plan.EndDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.EndDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided end_date is not in RFC3339 format ",
				"Error parsing the end_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.EndDate = parsedTime
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Scheduler Job Config update failure",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_SCHEDULER_JOB_CONFIGS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Scheduler Job Configs on CipherTrust Manager: ",
			"Could not udpate scheduler job configs: "+err.Error(),
		)
		return
	}

	getParamsFromResponse(ctx, response, &plan, &resp.Diagnostics)
	if diags.HasError() {
		return
	}

	tflog.Debug(ctx, "[resource_scheduler.go -> Update Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Update]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceScheduler) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CreateJobConfigParamsTFSDK
	diags := req.State.Get(ctx, &state)
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_SCHEDULER_JOB_CONFIGS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Scheduler Job configs",
			"Could not delete scheduler job configs, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")

}

func (r *resourceScheduler) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

func getDatabaseOperationBackupParams(plan CreateJobConfigParamsTFSDK) *DatabaseBackupParamsJSON {

	if plan.DatabaseBackupParams != nil {
		var databaseBackupParams DatabaseBackupParamsJSON

		if plan.DatabaseBackupParams.Description.ValueString() != "" && plan.DatabaseBackupParams.Description.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Description = plan.DatabaseBackupParams.Description.ValueString()
		}

		if plan.DatabaseBackupParams.BackupKey.ValueString() != "" && plan.DatabaseBackupParams.BackupKey.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.BackupKey = plan.DatabaseBackupParams.BackupKey.ValueString()
		}
		if plan.DatabaseBackupParams.Connection.ValueString() != "" && plan.DatabaseBackupParams.Connection.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Connection = plan.DatabaseBackupParams.Connection.ValueString()
		}
		if plan.DatabaseBackupParams.DoSCP.ValueBool() {
			databaseBackupParams.DoSCP = plan.DatabaseBackupParams.DoSCP.ValueBool()
		}
		if plan.DatabaseBackupParams.Scope.ValueString() != "" && plan.DatabaseBackupParams.Scope.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Scope = plan.DatabaseBackupParams.Scope.ValueString()
		}
		if plan.DatabaseBackupParams.TiedToHSM.ValueBool() {
			databaseBackupParams.TiedToHSM = plan.DatabaseBackupParams.TiedToHSM.ValueBool()
		}
		if plan.DatabaseBackupParams.RetentionCount.ValueInt64() != types.Int64Null().ValueInt64() {
			databaseBackupParams.RetentionCount = plan.DatabaseBackupParams.RetentionCount.ValueInt64()
		}

		if len(plan.DatabaseBackupParams.Filters) != 0 {
			var filters []BackupFilterJSON
			for _, filter := range plan.DatabaseBackupParams.Filters {
				if !filter.ResourceType.IsNull() {
					newFilter := BackupFilterJSON{
						ResourceType: filter.ResourceType.ValueString(),
					}
					if !filter.ResourceQuery.IsNull() {
						// Parse the JSON string into a map
						var resourceQuery map[string]interface{}
						err := json.Unmarshal([]byte(filter.ResourceQuery.ValueString()), &resourceQuery)
						if err != nil {
							tflog.Error(context.Background(), "Invalid resource_query JSON: "+err.Error())
						}
						newFilter.ResourceQuery = resourceQuery
					}
					filters = append(filters, newFilter)
				}
			}
			databaseBackupParams.Filters = &filters
		}
		return &databaseBackupParams
	}
	return nil
}

func getCckmKeyRotationOperationParams(ctx context.Context, plan CreateJobConfigParamsTFSDK, diags *diag.Diagnostics) *CCKMKeyRotationParamsJSON {
	if len(plan.CCKMKeyRotationParams.Elements()) != 0 {
		var rotationParams CCKMKeyRotationParamsTFSDK
		for _, v := range plan.CCKMKeyRotationParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &rotationParams)...)
			if diags.HasError() {
				return nil
			}
		}
		awsParams := CCKMRotationAwsParamsJSON{
			RetainAlias: rotationParams.RetainAlias.ValueBool(),
		}
		rotationParamsJSON := CCKMKeyRotationParamsJSON{
			CloudName:                 rotationParams.CloudName.ValueString(),
			CCKMRotationAwsParamsJSON: awsParams,
			Expiration:                rotationParams.Expiration.ValueStringPointer(),
			ExpireIn:                  rotationParams.ExpireIn.ValueStringPointer(),
		}
		return &rotationParamsJSON
	}
	return nil
}

func getCckmSyncParams(ctx context.Context, plan CreateJobConfigParamsTFSDK, diags *diag.Diagnostics) *CCKMSynchronizationParamsJSON {
	if len(plan.CCKMSynchronizationParams.Elements()) != 0 {
		var syncParams CCKMSynchronizationParamsTFSDK
		for _, v := range plan.CCKMSynchronizationParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &syncParams)...)
			if diags.HasError() {
				return nil
			}
		}
		syncParamsJSON := CCKMSynchronizationParamsJSON{
			CloudName:      syncParams.CloudName.ValueString(),
			SynchronizeAll: syncParams.SyncAll.ValueBoolPointer(),
		}
		if len(syncParams.Kms.Elements()) != 0 {
			planKms := make([]string, 0, len(syncParams.Kms.Elements()))
			diags.Append(syncParams.Kms.ElementsAs(ctx, &planKms, false)...)
			if diags.HasError() {
				return nil
			}
			syncParamsJSON.Kms = planKms
		}
		return &syncParamsJSON
	}
	return nil
}

func getCckmXksRotateCredentialsParams(plan CreateJobConfigParamsTFSDK) *CCKMXksRotateCredentialsParamsJSON {
	if plan.CCKMXksRotateCredentialsParams != nil {
		var rotateCredsParams CCKMXksRotateCredentialsParamsJSON
		if plan.CCKMXksRotateCredentialsParams.CloudName.ValueString() != "" {
			rotateCredsParams.CloudName = plan.CCKMXksRotateCredentialsParams.CloudName.ValueString()
		}
		return &rotateCredsParams
	}
	return nil
}

func getParamsFromResponse(ctx context.Context, response string, plan *CreateJobConfigParamsTFSDK, diags *diag.Diagnostics) {
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.Disabled = types.BoolValue(gjson.Get(response, "disabled").Bool())
	plan.Description = types.StringValue(gjson.Get(response, "description").String())
	plan.RunOn = types.StringValue(gjson.Get(response, "run_on").String())
	plan.StartDate = types.StringValue(gjson.Get(response, "start_date").String())
	plan.EndDate = types.StringValue(gjson.Get(response, "end_date").String())

	operation := plan.Operation.ValueString()
	switch operation {
	case "database_backup":
		dbParams := &DatabaseBackupParamsTFSDK{}
		dbParams.BackupKey = types.StringValue(gjson.Get(response, "job_config_params.backupKey").String())
		dbParams.Connection = types.StringValue(gjson.Get(response, "job_config_params.connection").String())
		dbParams.Description = types.StringValue(gjson.Get(response, "job_config_params.description").String())
		dbParams.DoSCP = types.BoolValue(gjson.Get(response, "job_config_params.do_scp").Bool())
		dbParams.TiedToHSM = types.BoolValue(gjson.Get(response, "job_config_params.tiedToHSM").Bool()) // Corrected key
		dbParams.RetentionCount = types.Int64Value(gjson.Get(response, "job_config_params.retentionCount").Int())
		dbParams.Scope = types.StringValue(gjson.Get(response, "job_config_params.scope").String())

		// Parse filters
		filtersArray := gjson.Get(response, "job_config_params.filters").Array()
		var filters []BackupFilterTFSDK
		for _, filter := range filtersArray {
			filters = append(filters, BackupFilterTFSDK{
				ResourceType:  types.StringValue(filter.Get("resourceType").String()),
				ResourceQuery: types.StringValue(filter.Get("resourceQuery").Raw),
			})
		}
		dbParams.Filters = filters
		plan.DatabaseBackupParams = dbParams
	case "cckm_key_rotation_params":
		cckmParams := &CCKMKeyRotationParamsTFSDK{
			CloudName:   types.StringValue(gjson.Get(response, "job_config_params.cloud_name").String()),
			RetainAlias: types.BoolValue(gjson.Get(response, "job_config_params.aw_param.retain_alias").Bool()),
			Expiration:  types.StringValue(gjson.Get(response, "job_config_params.expiration").String()),
			ExpireIn:    types.StringValue(gjson.Get(response, "job_config_params.expire_in").String()),
		}
		cckmParamsList := types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"cloud_name":       types.StringType,
				"aws_retain_alias": types.BoolType,
				"expiration":       types.StringType,
				"expire_in":        types.StringType,
			},
		})
		diags.Append(tfsdk.ValueFrom(ctx, []CCKMKeyRotationParamsTFSDK{*cckmParams}, cckmParamsList.Type(ctx), &cckmParamsList)...)
		if diags.HasError() {
			return
		}
		plan.CCKMKeyRotationParams = cckmParamsList
	case "cckm_synchronization":
		cckmParams := &CCKMSynchronizationParamsTFSDK{
			CloudName: types.StringValue(gjson.Get(response, "job_config_params.cloud_name").String()),
			SyncAll:   types.BoolValue(gjson.Get(response, "job_config_params.synchronize_all").Bool()),
		}
		var elements []string
		for _, kms := range gjson.Get(response, "job_config_params.kms").Array() {
			elements = append(elements, kms.String())
		}
		if len(elements) != 0 {
			cckmParams.Kms, _ = types.SetValueFrom(ctx, types.StringType, elements)
		} else {
			cckmParams.Kms = types.SetValueMust(types.StringType, []attr.Value{})
		}
		cckmParamsList := types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"cloud_name":      types.StringType,
				"synchronize_all": types.BoolType,
				"kms":             types.SetType{ElemType: types.StringType},
			},
		})
		diags.Append(tfsdk.ValueFrom(ctx, []CCKMSynchronizationParamsTFSDK{*cckmParams}, cckmParamsList.Type(ctx), &cckmParamsList)...)
		if diags.HasError() {
			return
		}
		plan.CCKMSynchronizationParams = cckmParamsList
	case "cckm_xks_credential_rotation":
		cckmParams := &CCKMXksRotateCredentialsParamsTFSDK{
			CloudName: types.StringValue(gjson.Get(response, "job_config_params.cloud_name").String()),
		}
		plan.CCKMXksRotateCredentialsParams = cckmParams
	}
}
