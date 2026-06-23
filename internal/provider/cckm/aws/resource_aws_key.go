package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_           resource.Resource                = &resourceAWSKey{}
	_           resource.ResourceWithConfigure   = &resourceAWSKey{}
	_           resource.ResourceWithImportState = &resourceAWSKey{}
	_           resource.ResourceWithModifyPlan  = &resourceAWSKey{}
	awsKeySpecs                                  = []string{"SYMMETRIC_DEFAULT",
		"RSA_2048",
		"RSA_3072",
		"RSA_4096",
		"ECC_NIST_P256",
		"ECC_NIST_P384",
		"ECC_NIST_P521",
		"ECC_SECG_P256K1",
		"HMAC_224",
		"HMAC_256",
		"HMAC_384",
		"HMAC_512"}
)

const (
	policyTemplateTagKey                 = "cckm_policy_template_id"
	longAwsKeyOpSleep                    = 20
	shortAwsKeyOpSleep                   = 5
	awsValidToRegEx                      = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
	awsValidToFormatMsg                  = "must conform to the following example 2027-07-03T14:24:00Z"
	refreshTokenSeconds                  = 200
	autoRotationWaitSeconds              = 180
	updatePrimaryRegionWaitSeconds       = 180
	enableDisableAutoRotationWaitSeconds = 180
	disabledKeyException                 = "DisabledException"
	notMultiRegionPrimaryException       = "is not a multi-Region primary key"
	notFoundError                        = "status: 404"
)

func NewResourceAWSKey() resource.Resource {
	return &resourceAWSKey{}
}

type resourceAWSKey struct {
	client *common.Client
}

func (r *resourceAWSKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key"
}

func (r *resourceAWSKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage AWS keys in CipherTrust Manager. " +
			"If the KMS is not found during refresh the key is kept in state (it is hidden in CipherTrust Manager until the KMS is recovered). " +
			"A key pending deletion is removed from state automatically on refresh, as it is already being deleted.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager ID of the key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "AWS region in which to create the AWS key.",
			},
			"auto_rotate": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "(Updatable) Enable AWS autorotation of the key. Auto-Rotation only is only applicable to native symmetric keys.",
				Default:     booldefault.StaticBool(false),
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Enable or disable the key. Default is true.",
			},
			"kms_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "ID of the KMS to use when creating the key. Required unless replicating a multi-region key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the KMS. Populated from the API response.",
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "(Updatable) Updates the primary region of a multi-region key.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Waiting period after the key is destroyed before it is permanently deleted. Optional; valid values are 7-30 days (inclusive). Defaults to 7 days and is only used when the resource is destroyed.",
				Default:     int64default.StaticInt64(7),
				Validators:  []validator.Int64{int64validator.AtLeast(7), int64validator.AtMost(30)},
			},
			// aws_param holds the AWS key parameters. Input fields are sent to the API on create/update.
			// All fields are Optional/Computed except policy and the rotation fields which are Computed-only.
			"aws_param": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS key parameters. Input fields are sent to the API on create/update; all fields are populated from the API response.",
				Attributes:  nativeKeyAwsParamSchemaAttributes(),
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
			},
			// Read-only top-level fields sourced from the CipherTrust Manager API response.
			// AWS-specific fields (arn, aws_account_id, aws_key_id, deletion_date, enabled,
			// encryption_algorithms, expiration_model, key_manager, key_rotation_enabled,
			// key_state, mac_algorithms, origin, policy) are now inside aws_param.
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "AWS cloud.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was created.",
			},
			"external_accounts": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that have access to this key.",
			},
			"key_admins": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Key material origin.",
			},
			"key_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key.",
			},
			"key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Key type.",
			},
			"key_users": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"multi_region_configuration": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Multi-region configuration for the key. Set only when multi_region is true.",
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
				Attributes: map[string]schema.Attribute{
					"multi_region_key_type": schema.StringAttribute{
						Computed:    true,
						Description: "Whether this key is PRIMARY or REPLICA.",
					},
					"primary_key": schema.SingleNestedAttribute{
						Computed:    true,
						Description: "ARN and region of the primary key.",
						Attributes: map[string]schema.Attribute{
							"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the primary key."},
							"region": schema.StringAttribute{Computed: true, Description: "Region of the primary key."},
						},
					},
					"replica_keys": schema.SetNestedAttribute{
						Computed:    true,
						Description: "ARN and region of each replica key.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the replica key."},
								"region": schema.StringAttribute{Computed: true, Description: "Region of the replica key."},
							},
						},
					},
				},
			},
			"policy_template_tag": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS key tag for an associated policy template.",
			},
			"rotated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time when this key was rotated by a scheduled rotation job.",
			},
			"rotated_from": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID from of the key this key has been rotated from by a scheduled rotation job.",
			},
			"rotated_to": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID which this key has been rotated too by a scheduled rotation job.",
			},
			"rotation_status": schema.StringAttribute{
				Computed:    true,
				Description: "Rotation status of the key.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was synchronized.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was last updated.",
			},
			"rotation_history": rotationHistoryNativeSummarySchemaAttribute(),
			"key_policy":       keyPolicySchemaAttribute(),
			"replicate_key": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Replicate key parameters.",
				Attributes: map[string]schema.Attribute{
					"key_id": schema.StringAttribute{
						Required:    true,
						Description: "CipherTrust Manager resource of the primary key to replicate.",
					},
					"make_primary": schema.BoolAttribute{
						Optional:    true,
						Description: "Update the primary key region to the replicated key's region following replication.",
					},
				},
			},
			"enable_rotation": enableRotationSchemaAttribute(),
		},
	}
}

// Create creates a new AWS key - via native creation or replication -
// and sets Terraform state. After the key itself is successfully created, the following post-creation
// operations are attempted but only produce warnings (not errors) on failure, ensuring the key is
// always saved to state regardless of any subsequent partial failure:
//   - Adding additional aliases beyond the first (the first alias is set during key creation)
//   - Enabling or disabling AWS autorotation (enable_auto_rotate / auto_rotation_period_in_days)
//   - Registering the key with a CipherTrust Manager scheduled rotation job (enable_rotation block)
//   - Disabling the key if enable_key = false
//   - Refreshing final state from the API after all post-creation operations
func (r *resourceAWSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Create]["+id+"]")
	var (
		plan     AWSKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	commonAwsParams := r.getNativeKeyAwsParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.ReplicateKey != nil {
		response = r.replicateNativeKey(ctx, id, &plan, commonAwsParams, &resp.Diagnostics)
	} else {
		kmsID := plan.KMSID.ValueString()
		if kmsID == "" {
			msg := "Error creating AWS key: kms_id is required when not replicating a key."
			resp.Diagnostics.AddError(msg, "")
			return
		}
		if _, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS); err != nil {
			msg := "Error creating AWS key: kms_id does not resolve to a valid KMS."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		response = r.createNativeKey(ctx, id, kmsID, &plan, commonAwsParams, &resp.Diagnostics)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if response == "" {
		resp.Diagnostics.AddError("Error creating AWS key: no response received from API.", "")
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	tflog.Debug(ctx, "[resource_aws_key.go -> Create][response:"+redactAWSResponse(response))

	// Don't return errors after this

	if planParam := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, &resp.Diagnostics); planParam != nil && len(planParam.Alias.Elements()) > 1 {
		var diags diag.Diagnostics
		addAliases(ctx, r.client, id, plan.ID.ValueString(), planParam.Alias, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if plan.AutoRotate.ValueBool() {
		var diags diag.Diagnostics
		r.enableDisableAutoRotation(ctx, id, &plan, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if plan.EnableRotation != nil {
		var diags diag.Diagnostics
		enableKeyRotationJob(ctx, id, r.client, plan.ID.ValueString(), plan.EnableRotation, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		keyID := gjson.Get(response, "id").String()
		disableKey(ctx, id, r.client, keyID, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	keyID := plan.ID.ValueString()
	var err error
	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		tflog.Debug(ctx, "[resource_aws_key.go -> Create][response:"+redactAWSResponse(response))
	}

	var diags diag.Diagnostics
	r.setKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Debug(ctx, "[resource_aws_key.go -> Create][response:"+redactAWSResponse(response))
}

// Read refreshes the Terraform state for an AWS key by fetching the latest data from CipherTrust Manager.
// If the key is not found and the KMS is also not found, the existing state is preserved with a warning
// so that recovery (recreating the KMS) is possible without manual state surgery.
// If the key is found but has gone=true (its region was removed from the KMS regions list), a warning
// is added and state is still updated - the key exists but all key operations will fail until the region
// is restored to the KMS.
func (r *resourceAWSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Read]["+id+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, preserveState := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if preserveState {
		// KMS not found - key is hidden. Keep existing state unchanged until KMS is recovered.
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	if gjson.Get(response, "gone").Bool() {
		msg := "AWS key is gone - its region is not in the KMS regions list. Key operations will fail until the region is restored to the KMS."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if readKeyState == "PendingDeletion" || readKeyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	r.setKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies plan changes to an AWS key including policy, aliases, tags, rotation, and enable/disable state.
// All attributes are always sent to AWS  -  unlike XKS and CloudHSM keys, there is no linked-state condition.
// Returns an error if the key or KMS is not reachable
func (r *resourceAWSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Update]["+id+"]")
	var (
		plan  AWSKeyTFSDK
		state AWSKeyTFSDK
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := state.ID.ValueString()
	response, _ := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if updateKeyState == "PendingDeletion" || updateKeyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	keyEnabled := gjson.Get(response, "aws_param.Enabled").Bool()
	planEnableKey := false
	if !plan.EnableKey.IsUnknown() {
		planEnableKey = plan.EnableKey.ValueBool()
		if !keyEnabled && planEnableKey {
			enableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}
	planParam := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	planDesc := types.StringNull()
	if planParam != nil {
		planDesc = planParam.Description
	}
	planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, Description: planDesc, KeyPolicy: plan.KeyPolicy, EnableRotation: plan.EnableRotation}
	stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy, EnableRotation: state.EnableRotation}
	updateAwsKeyCommon(ctx, id, r.client, planUpdate, stateUpdate, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if planParam != nil && !planParam.Alias.IsUnknown() {
		updateAliases(ctx, id, r.client, keyID, planParam.Alias, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if planParam != nil && !planParam.Tags.IsUnknown() {
		planTags := make(map[string]string, len(planParam.Tags.Elements()))
		if len(planParam.Tags.Elements()) != 0 {
			resp.Diagnostics.Append(planParam.Tags.ElementsAs(ctx, &planTags, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		updateTags(ctx, id, r.client, planTags, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if !plan.AutoRotate.IsUnknown() {
		r.enableDisableAutoRotation(ctx, id, &plan, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if !plan.PrimaryRegion.IsUnknown() && plan.PrimaryRegion != state.PrimaryRegion {
		newPrimaryRegion := plan.PrimaryRegion.ValueString()
		primaryKeyJSON := getPrimaryKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		primaryKeyID := gjson.Get(primaryKeyJSON, "id").String()
		primaryKeyRegion := gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
		if primaryKeyRegion != newPrimaryRegion {
			awsMrkKeyID := gjson.Get(primaryKeyJSON, "aws_param.KeyId").String()
			newPrimaryKeyID := findKeyCMIDByRegion(ctx, id, r.client, awsMrkKeyID, newPrimaryRegion, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
			updatePrimaryRegion(ctx, id, r.client, primaryKeyID, newPrimaryRegion, newPrimaryKeyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			resp.Diagnostics.AddWarning("'primary_region' specifies the current primary region", "")
		}
	}
	if !plan.EnableKey.IsUnknown() && keyEnabled && !planEnableKey {
		disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var err error
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Debug(ctx, "[resource_aws_key.go -> Update][response:"+redactAWSResponse(response))
}

// Delete schedules an AWS key for deletion via the schedule-deletion API. In either case:
//   - If the KMS is not found (404), a warning is added and the key is removed from state.
//   - If the KMS has a non-404 error, a hard error is returned and the key is kept in state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
//   - If the key is already in PendingDeletion or PendingReplicaDeletion state, a warning is returned and the key is removed from state.
func (r *resourceAWSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Delete]["+id+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response, _ := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return // KMS not found or unreachable - hard error, resource kept in state
	}
	if response == "" {
		return // key not found (404) - warning already added, resource removed from state
	}
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := "AWS key is already pending deletion, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error deleting AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), "is pending deletion") {
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
		}
	}
	tflog.Debug(ctx, "[resource_aws_key.go -> Delete][response:"+redactAWSResponse(response))
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	var plan, state AWSKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planParam := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, &resp.Diagnostics)
	stateParam := nativeKeyAwsParamFromObject(ctx, state.AWSParam, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string
	if planParam != nil && stateParam != nil {
		if !planParam.BypassPolicyLockoutSafetyCheck.IsNull() && !planParam.BypassPolicyLockoutSafetyCheck.IsUnknown() &&
			planParam.BypassPolicyLockoutSafetyCheck != stateParam.BypassPolicyLockoutSafetyCheck {
			changed = append(changed, "aws_param.bypass_policy_lockout_safety_check")
		}
		if !planParam.CustomerMasterKeySpec.IsNull() && !planParam.CustomerMasterKeySpec.IsUnknown() &&
			planParam.CustomerMasterKeySpec != stateParam.CustomerMasterKeySpec {
			changed = append(changed, "aws_param.customer_master_key_spec")
		}
		if !planParam.KeyUsage.IsNull() && !planParam.KeyUsage.IsUnknown() &&
			planParam.KeyUsage != stateParam.KeyUsage {
			changed = append(changed, "aws_param.key_usage")
		}
	}

	id := uuid.NewString()
	if !plan.KMSID.IsNull() && !plan.KMSID.IsUnknown() &&
		plan.KMSID != state.KMSID {
		kmsID := state.KMSID.ValueString()
		if kmsID != "" {
			_, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
			if err != nil && strings.Contains(err.Error(), notFoundError) {
				msg := "Previous AWS KMS was not found, allowing update."
				details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
				tflog.Warn(ctx, details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				changed = append(changed, "kms_id")
			}
		}
	}

	if planParam != nil && stateParam != nil {
		if !planParam.MultiRegion.IsNull() && !planParam.MultiRegion.IsUnknown() &&
			planParam.MultiRegion != stateParam.MultiRegion {
			changed = append(changed, "aws_param.multi_region")
		}
	}

	if plan.Region != state.Region {
		changed = append(changed, "region")
	}

	// replicate_key block: compare source fields when block is present in both plan and state.
	if plan.ReplicateKey != nil && state.ReplicateKey != nil {
		if plan.ReplicateKey.KeyID != state.ReplicateKey.KeyID {
			changed = append(changed, "replicate_key.key_id")
		}
	}

	// When primary_region is being *changed* (not already applied), multi_region_configuration
	// will change (the key flips PRIMARY<->REPLICA and the regions swap). The
	// nullOrStateForUnknownObject plan modifier already copied the old state value into the plan,
	// which would cause an "inconsistent result after apply" error. Override it here by marking it
	// unknown so Terraform accepts whatever value the provider returns after apply.
	// Only do this when the value is actually changing - if primary_region is already stored in
	// state with the same value as the plan, the promotion is already done and the plan is stable.
	planPR := plan.PrimaryRegion.ValueString()
	statePR := state.PrimaryRegion.ValueString()
	if !plan.PrimaryRegion.IsNull() && !plan.PrimaryRegion.IsUnknown() && planPR != "" && planPR != statePR {
		resp.Plan.SetAttribute(ctx, path.Root("multi_region_configuration"), types.ObjectUnknown(multiRegionConfigAttrTypes))
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an existing AWS key into Terraform state using its resource ID.
func (r *resourceAWSKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// createNativeKey creates a native or external AWS key and returns the API response JSON.
// kmsID and commonAwsParams are pre-validated and pre-built by Create before calling this function.
func (r *resourceAWSKey) createNativeKey(ctx context.Context, id string, kmsID string, plan *AWSKeyTFSDK, commonAwsParams CommonAWSParamsJSON, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createNativeKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createNativeKey]["+id+"]")
	awsParam := AWSKeyParamJSON{
		CommonAWSParamsJSON: commonAwsParams,
		Origin:              "AWS_KMS",
	}
	keyCreateParams := r.getNativeKeyCreateParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = kmsID
	payload := CreateAWSKeyPayloadJSON{
		CommonAWSKeyCreatePayloadJSON: keyCreateParams,
		AWSParam:                      awsParam,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Debug(ctx, "[resource_aws_key.go -> createNativeKey][response:"+redactAWSResponse(response))
	return response
}

// replicateNativeKey replicates a primary multi-region AWS_KMS key to a new region.
// It delegates to replicateKeyCommon which handles all API calls and polling.
// commonAwsParams is pre-built by Create before calling this function.
func (r *resourceAWSKey) replicateNativeKey(ctx context.Context, id string, plan *AWSKeyTFSDK, commonAwsParams CommonAWSParamsJSON, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> replicateNativeKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> replicateNativeKey]["+id+"]")
	if plan.ReplicateKey == nil {
		return ""
	}
	primaryKeyID := plan.ReplicateKey.KeyID.ValueString()
	mutexKey := fmt.Sprintf("aws-replicate-key-%s", primaryKeyID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)
	return replicateKeyCommon(ctx, id, r.client, plan.ReplicateKey, plan.Region.ValueString(), "AWS_KMS", commonAwsParams, plan.KeyPolicy, diags)
}

// getAWSKeyCreateParams builds the key creation payload fields common to all create paths (region, policy members, etc.).
func (r *resourceAWSKey) getNativeKeyCreateParams(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) CommonAWSKeyCreatePayloadJSON {
	var keyCreateParams CommonAWSKeyCreatePayloadJSON
	keyCreateParams.Region = plan.Region.ValueString()
	keyPolicyPlan := getKeyPolicyParams(ctx, plan.KeyPolicy, diags)
	if diags.HasError() {
		return keyCreateParams
	}
	keyCreateParams.ExternalAccounts = keyPolicyPlan.ExternalAccounts
	keyCreateParams.KeyAdmins = keyPolicyPlan.KeyAdmins
	keyCreateParams.KeyAdminsRoles = keyPolicyPlan.KeyAdminsRoles
	keyCreateParams.KeyUsers = keyPolicyPlan.KeyUsers
	keyCreateParams.KeyUsersRoles = keyPolicyPlan.KeyUsersRoles
	keyCreateParams.PolicyTemplate = keyPolicyPlan.PolicyTemplate
	return keyCreateParams
}

// enableDisableAutoRotation enables or disables AWS autorotation for a key and polls until the change is confirmed.
func (r *resourceAWSKey) enableDisableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableAutoRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableAutoRotation]["+id+"]")
	var (
		err      error
		response string
	)
	planAutoRotateEnabled := plan.AutoRotate.ValueBool()
	planParam := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, diags)
	var planPeriodIsSet bool
	var planDays int64
	if planParam != nil {
		planPeriodIsSet = !planParam.AutoRotationPeriodInDays.IsNull() && !planParam.AutoRotationPeriodInDays.IsUnknown()
		planDays = planParam.AutoRotationPeriodInDays.ValueInt64()
	}
	keyAutoRotateEnabled := gjson.Get(keyJSON, "aws_param.KeyRotationEnabled").Bool()
	keyDays := gjson.Get(keyJSON, "aws_param.RotationPeriodInDays").Int()
	keyID := plan.ID.ValueString()
	daysMatch := !planPeriodIsSet || keyDays == planDays
	updatedAutoRotation := false
	if planAutoRotateEnabled {
		if keyAutoRotateEnabled != planAutoRotateEnabled || !daysMatch {
			r.enableAutoRotation(ctx, id, plan, keyJSON, diags)
			if diags.HasError() {
				return
			}
			updatedAutoRotation = true
		}
	} else if keyAutoRotateEnabled != planAutoRotateEnabled {
		r.disableAutoRotation(ctx, id, plan, keyJSON, diags)
		if diags.HasError() {
			return
		}
		updatedAutoRotation = true
	}
	if updatedAutoRotation {
		response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error reading AWS key after auto-rotation change."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		keyAutoRotateEnabled = gjson.Get(response, "aws_param.KeyRotationEnabled").Bool()
		keyDays = gjson.Get(response, "aws_param.RotationPeriodInDays").Int()
		daysMatch = !planPeriodIsSet || keyDays == planDays
		if keyAutoRotateEnabled != planAutoRotateEnabled || !daysMatch {
			time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
			ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
			defer ticker.Stop()
			deadline := time.Now().Add(time.Duration(autoRotationWaitSeconds) * time.Second)
			for range ticker.C {
				if time.Now().After(deadline) {
					break
				}
				response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
				if err != nil {
					msg := "Error reading AWS key."
					details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
					diags.AddError(details, "")
					return
				}
				keyAutoRotateEnabled = gjson.Get(response, "aws_param.KeyRotationEnabled").Bool()
				keyDays = gjson.Get(response, "aws_param.RotationPeriodInDays").Int()
				daysMatch = !planPeriodIsSet || keyDays == planDays
				if keyAutoRotateEnabled == planAutoRotateEnabled && daysMatch {
					return
				}
			}
		}
	}
	if keyAutoRotateEnabled != planAutoRotateEnabled || !daysMatch {
		msg := "Failed to confirm auto-rotation is configured."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
	}
}

// enableAutoRotation sends the enable-auto-rotation request to AWS, retrying on transient disabled-key errors.
func (r *resourceAWSKey) enableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableAutoRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableAutoRotation]["+id+"]")
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.ID.ValueString()
	var payload EnableAutoRotationPayloadJSON
	if p := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, diags); p != nil {
		if !p.AutoRotationPeriodInDays.IsNull() && !p.AutoRotationPeriodInDays.IsUnknown() {
			days := p.AutoRotationPeriodInDays.ValueInt64()
			payload.RotationPeriodInDays = &days
		}
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto-rotation for AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-auto-rotation", payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), disabledKeyException) && keyEnabled {
			ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
			defer ticker.Stop()
			deadline := time.Now().Add(time.Duration(enableDisableAutoRotationWaitSeconds) * time.Second)
			for range ticker.C {
				if time.Now().After(deadline) {
					break
				}
				_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-auto-rotation", payloadJSON)
				if err == nil || !strings.Contains(err.Error(), disabledKeyException) {
					break
				}
			}
		}
		if err != nil {
			msg := "Error enabling auto-rotation for AWS key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			tflog.Error(ctx, details)
			return
		}
	}
	tflog.Info(ctx, fmt.Sprintf("[resource_aws_key.go -> enableAutoRotation] auto-rotation enabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[resource_aws_key.go -> enableAutoRotation][response:"+redactAWSResponse(response))
}

// disableAutoRotation sends the disable-auto-rotation request to AWS, retrying on transient disabled-key errors.
func (r *resourceAWSKey) disableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> disableAutoRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> disableAutoRotation]["+id+"]")
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.ID.ValueString()
	response, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-auto-rotation")
	if err != nil {
		if strings.Contains(err.Error(), disabledKeyException) && keyEnabled {
			ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
			defer ticker.Stop()
			deadline := time.Now().Add(time.Duration(r.client.CCKMConfig.AwsOperationTimeout) * time.Second)
			for range ticker.C {
				if time.Now().After(deadline) {
					break
				}
				response, err = r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-auto-rotation")
				if err == nil || !strings.Contains(err.Error(), disabledKeyException) {
					break
				}
			}
		}
		if err != nil {
			msg := "Error disabling auto-rotation for AWS key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			tflog.Error(ctx, details)
			return
		}
	}
	tflog.Info(ctx, fmt.Sprintf("[resource_aws_key.go -> disableAutoRotation] auto-rotation disabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[resource_aws_key.go -> disableAutoRotation][response:"+redactAWSResponse(response))
}

// getNativeKeyAwsParams builds the common AWS parameter payload including alias, spec, description, tags, and policy.
// All AWS-specific input fields are read from plan.AWSParam when it is non-nil.
func (r *resourceAWSKey) getNativeKeyAwsParams(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) CommonAWSParamsJSON {
	var awsParams CommonAWSParamsJSON
	p := nativeKeyAwsParamFromObject(ctx, plan.AWSParam, diags)
	if p == nil {
		return awsParams
	}
	if len(p.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(p.Alias.Elements()))
		diags.Append(p.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return awsParams
		}
		awsParams.Alias = aliases[0]
	}
	if !p.BypassPolicyLockoutSafetyCheck.IsNull() && !p.BypassPolicyLockoutSafetyCheck.IsUnknown() {
		awsParams.BypassPolicyLockoutSafetyCheck = p.BypassPolicyLockoutSafetyCheck.ValueBool()
	}
	if !p.CustomerMasterKeySpec.IsNull() && !p.CustomerMasterKeySpec.IsUnknown() && p.CustomerMasterKeySpec.ValueString() != "" {
		awsParams.CustomerMasterKeySpec = p.CustomerMasterKeySpec.ValueString()
	}
	if !p.Description.IsNull() && !p.Description.IsUnknown() && p.Description.ValueString() != "" {
		awsParams.Description = p.Description.ValueString()
	}
	if !p.KeyUsage.IsNull() && !p.KeyUsage.IsUnknown() && p.KeyUsage.ValueString() != "" {
		awsParams.KeyUsage = p.KeyUsage.ValueString()
	}
	if awsParams.KeyUsage == "" && awsParams.CustomerMasterKeySpec != "" {
		if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "ECC") {
			awsParams.KeyUsage = "SIGN_VERIFY"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "RSA") {
			awsParams.KeyUsage = "ENCRYPT_DECRYPT"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "HMAC") {
			awsParams.KeyUsage = "GENERATE_VERIFY_MAC"
		} else if awsParams.CustomerMasterKeySpec == "SYMMETRIC_DEFAULT" {
			awsParams.KeyUsage = "ENCRYPT_DECRYPT"
		}
	}
	if !p.MultiRegion.IsNull() && !p.MultiRegion.IsUnknown() {
		awsParams.MultiRegion = p.MultiRegion.ValueBool()
	}
	if len(p.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, p.Tags, diags)
		if diags.HasError() {
			return awsParams
		}
		awsParams.Tags = tags
	}
	if plan.KeyPolicy != nil {
		if !plan.KeyPolicy.Policy.IsNull() && len(plan.KeyPolicy.Policy.ValueString()) != 0 {
			awsParams.Policy = json.RawMessage(plan.KeyPolicy.Policy.ValueString())
		}
	}
	return awsParams
}

// setKeyState populates the full Terraform state for an AWS key from an API response JSON string.
func (r *resourceAWSKey) setKeyState(ctx context.Context, response string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, "[resource_aws_key.go -> setKeyState][response:"+redactAWSResponse(response))
	setNativeAndByokKeyCommonState(ctx, response, &state.AWSNativeAndByokKeyCommonTFSDK, diags)
	if diags.HasError() {
		return
	}
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	existing := nativeKeyAwsParamFromObject(ctx, state.AWSParam, diags)
	state.AWSParam = nativeKeyAwsParamToObject(ctx, r.setNativeKeyAwsParamState(ctx, response, existing, diags), diags)
	state.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.MultiRegionConfiguration = setMultiRegionConfig(response, diags)
	// Initialize rotation_history to a known empty list before any early-return path.
	emptyRotHistory, _ := types.ListValue(rotationHistoryNativeSummaryElemType, []attr.Value{})
	state.RotationHistory = emptyRotHistory
	keyID := gjson.Get(response, "id").String()
	rotID := uuid.New().String()
	state.RotationHistory, _ = fetchRotationHistoryNativeSummary(ctx, rotID, r.client, keyID)
}

// setNativeKeyAwsParamState builds an AWSKeyAwsParamTFSDK from the API response JSON.
// It captures the AWS-side metadata returned under the aws_param object. The existing pointer
// is reused when non-nil so that tag filtering (which uses the prior state keys) is preserved.
func (r *resourceAWSKey) setNativeKeyAwsParamState(ctx context.Context, response string, existing *AWSKeyAwsParamTFSDK, diags *diag.Diagnostics) *AWSKeyAwsParamTFSDK {
	p := existing
	if p == nil {
		p = &AWSKeyAwsParamTFSDK{}
	}
	setAliases(response, &p.Alias, diags)
	setKeyTags(ctx, response, &p.Tags, diags)
	// Input/Computed fields
	p.CurrentKeyMaterialID = types.StringValue(gjson.Get(response, "aws_param.CurrentKeyMaterialId").String())
	p.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	p.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	// Policy - only update when changed to avoid spurious diffs from equivalent JSON.
	policy := gjson.Get(response, "aws_param.Policy").String()
	if p.Policy.IsUnknown() || !getPoliciesAreEqual(ctx, policy, p.Policy.ValueString(), diags) {
		p.Policy = types.StringValue(policy)
	}
	// Computed-only fields from aws_param
	p.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	p.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	p.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	p.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	p.ReplicaPolicy = types.StringValue(gjson.Get(response, "aws_param.ReplicaPolicy").String())
	p.ReplicaTags = types.StringValue(gjson.Get(response, "aws_param.ReplicaTags").Raw)
	// Native-key-only rotation fields
	if gjson.Get(response, "aws_param.RotationPeriodInDays").Exists() {
		p.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	} else {
		p.AutoRotationPeriodInDays = types.Int64Null()
	}
	p.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	return p
}
