package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
	_ resource.Resource                = &resourceAWSCloudHSMKey{}
	_ resource.ResourceWithConfigure   = &resourceAWSCloudHSMKey{}
	_ resource.ResourceWithImportState = &resourceAWSCloudHSMKey{}
	_ resource.ResourceWithModifyPlan  = &resourceAWSCloudHSMKey{}
)

func NewResourceAWSCloudHSMKey() resource.Resource {
	return &resourceAWSCloudHSMKey{}
}

type resourceAWSCloudHSMKey struct {
	client *common.Client
}

func (r *resourceAWSCloudHSMKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_cloudhsm_key"
}

func (r *resourceAWSCloudHSMKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSCloudHSMKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage AWS CloudHSM keys in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID. The legacy format '<aws-region>\\<key-id>' is also accepted for backwards compatibility when migrating from beta provider versions.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region in which the CloudHSM key resides.",
			},
			"bypass_policy_lockout_safety_check": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to bypass the key policy lockout safety check.",
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS key parameters. Alias, description, and tags are updatable for linked keys; all other fields are computed.",
				Attributes:  cloudHSMKeyAwsParamSchemaAttributes(),
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Enable or disable the key. Default is true.",
				Default:     booldefault.StaticBool(true),
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Computed:    true,
				Optional:    true,
				Description: "(Updatable) Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Default:     int64default.StaticInt64(7),
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
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
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name or of the KMS.",
			},
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the KMS",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key name of the external key.",
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
			"valid_to": schema.StringAttribute{
				Computed:    true,
				Description: "Date of key material expiry.",
			},
			"key_source_container_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the source container of the key.",
			},
			"key_source_container_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the source container of the key.",
			},
			"custom_key_store_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager ID of the CloudHSM keystore where key is to be created.",
			},
			"linked": schema.BoolAttribute{
				Computed:    true,
				Description: "Parameter to indicate if AWS CloudHSM key is linked with AWS.",
			},
			"blocked": schema.BoolAttribute{
				Computed:    true,
				Description: "Parameter to indicate if AWS CloudHSM key is blocked for any data plane operation.",
			},
			"key_policy":      keyPolicySchemaAttribute(),
			"enable_rotation": enableRotationSchemaAttribute(),
		},
	}
}

// Create creates a new AWS CloudHSM key in a custom key store via CipherTrust Manager and sets Terraform state.
// After the key is successfully created, the following post-creation operations are attempted but only
// produce warnings (not errors) on failure, ensuring the key is always saved to state:
//   - Adding additional aliases beyond the first  -  only applied when the key is linked (linked_state = true);
//     unlinked keys do not support alias management via AWS
//   - Registering the key with a CipherTrust Manager scheduled rotation job (enable_rotation block)
//   - Disabling the key if enable_key = false  -  only applied when the key is linked
//   - Refreshing final state from the API after all post-creation operations
func (r *resourceAWSCloudHSMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_cloudhsm_key.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_cloudhsm_key.go -> Create]["+id+"]")
	var (
		plan     AWSCloudHSMKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var base *AWSKeyStoreCommonAwsParamTFSDK
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		cloudHSMP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if cloudHSMP != nil {
			base = &cloudHSMP.AWSKeyStoreCommonAwsParamTFSDK
		}
	}
	awsParams := getKeyStoreKeyAWSParams(ctx, plan.KeyPolicy, base, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := CreateCloudHSMKeyInputPayloadJSON{}
	if awsParams != nil {
		payload.AWSParams = *awsParams
	}
	keyPolicy := getKeyPolicyParams(ctx, plan.KeyPolicy, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if keyPolicy.KeyUsers != nil && len(*keyPolicy.KeyUsers) != 0 {
		payload.KeyUsers = keyPolicy.KeyUsers
	}
	if keyPolicy.KeyUsersRoles != nil && len(*keyPolicy.KeyUsersRoles) != 0 {
		payload.KeyUsersRoles = keyPolicy.KeyUsersRoles
	}
	if keyPolicy.KeyAdmins != nil && len(*keyPolicy.KeyAdmins) != 0 {
		payload.KeyAdmins = keyPolicy.KeyAdmins
	}
	if keyPolicy.KeyAdminsRoles != nil && len(*keyPolicy.KeyAdminsRoles) != 0 {
		payload.KeyAdminsRoles = keyPolicy.KeyAdminsRoles
	}
	if keyPolicy.ExternalAccounts != nil && len(*keyPolicy.ExternalAccounts) != 0 {
		payload.ExternalAccounts = keyPolicy.ExternalAccounts
	}
	if keyPolicy.PolicyTemplate != nil && *keyPolicy.PolicyTemplate != "" {
		payload.PolicyTemplate = keyPolicy.PolicyTemplate
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS CloudHSM key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	customKeyStoreID := plan.CustomKeyStoreID.ValueString()
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_XKS+"/"+customKeyStoreID+"/create-aws-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[resource_aws_cloudhsm_key.go -> Create][response:"+redactAWSResponse(response)+"]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// No error after this

	keyID := gjson.Get(response, "id").String()
	if gjson.Get(response, "linked_state").Bool() && !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if planP != nil && len(planP.AWSKeyStoreCommonAwsParamTFSDK.Alias.Elements()) > 1 {
			var diags diag.Diagnostics
			addAliases(ctx, r.client, id, keyID, planP.AWSKeyStoreCommonAwsParamTFSDK.Alias, response, &diags)
			for _, d := range diags {
				resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
			}
		}
	}
	if plan.EnableRotation != nil {
		var diags diag.Diagnostics
		enableKeyRotationJob(ctx, id, r.client, keyID, plan.EnableRotation, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if gjson.Get(response, "linked_state").Bool() && !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		disableKey(ctx, id, r.client, keyID, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	var plannedAlias types.Set
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if planP != nil {
			plannedAlias = planP.AWSKeyStoreCommonAwsParamTFSDK.Alias
		}
	}

	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		tflog.Debug(ctx, "[resource_aws_cloudhsm_key.go -> Create][response:"+redactAWSResponse(response)+"]")
	}

	var diags diag.Diagnostics
	setCloudHSMKeyResourceState(ctx, response, &plan.AWSKeyStoreResourceCommonTFSDK, &diags)
	// Restore the planned alias if setCloudHSMKeyResourceState overwrote it with API values.
	if !plannedAlias.IsNull() && !plannedAlias.IsUnknown() {
		planP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &diags)
		if planP != nil && !reflect.DeepEqual(planP.AWSKeyStoreCommonAwsParamTFSDK.Alias, plannedAlias) {
			planP.AWSKeyStoreCommonAwsParamTFSDK.Alias = plannedAlias
			plan.AWSParam = packCloudHSMKeyAwsParam(ctx, planP, &diags)
		}
	}
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes Terraform state for an AWS CloudHSM key by reading its current data from CipherTrust Manager.
// If the linked key is in PendingDeletion or PendingReplicaDeletion state, it is removed from state.
// For unlinked keys, the description attribute is preserved from prior state rather than overwritten.
// Returns an error if the key or key store is not reachable.
func (r *resourceAWSCloudHSMKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_cloudhsm_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_cloudhsm_key.go -> Read]["+id+"]")
	var state AWSCloudHSMKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := r.getAwsCloudHsmKey(ctx, id, state.CustomKeyStoreID.ValueString(), state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if gjson.Get(response, "linked_state").Bool() &&
		(readKeyState == "PendingDeletion" || readKeyState == "PendingReplicaDeletion") {
		msg := "AWS CloudHSM key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	var savedDesc types.String
	if !state.AWSParam.IsNull() && !state.AWSParam.IsUnknown() {
		stateP := extractCloudHSMKeyAwsParam(ctx, state.AWSParam, &resp.Diagnostics)
		if stateP != nil {
			savedDesc = stateP.AWSKeyStoreCommonAwsParamTFSDK.Description
		}
	}
	setCloudHSMKeyResourceState(ctx, response, &state.AWSKeyStoreResourceCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS CloudHSM key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if !gjson.Get(response, "linked_state").Bool() {
		stateP := extractCloudHSMKeyAwsParam(ctx, state.AWSParam, &resp.Diagnostics)
		// Only restore savedDesc when it was a known value from prior state.
		// If savedDesc is null (e.g. after import with no prior state), keep the
		// API value ("") so that aws_param.description is always present in state.
		if stateP != nil && !savedDesc.IsNull() && !savedDesc.IsUnknown() {
			stateP.AWSKeyStoreCommonAwsParamTFSDK.Description = savedDesc
		}
		state.AWSParam = packCloudHSMKeyAwsParam(ctx, stateP, &resp.Diagnostics)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update applies plan changes to an AWS CloudHSM key. Only keys in a linked state (linked_state = true)
// have their AWS-facing attributes updated. Specifically:
//
//	When linked (linked_state = true):
//	  - description, key_policy, enable_rotation (via updateAwsKeyCommon)
//	  - alias
//	  - tags
//	  - enable_key (enable or disable the key in AWS)
//
//	When unlinked (linked_state = false):
//	  - No AWS updates are applied; all plan changes are silently skipped
//	  - description is preserved from the prior state value rather than overwritten
//
// Block/unblock and link operations are not supported for CloudHSM keys.
// Returns an error if the key or key store is not reachable.
func (r *resourceAWSCloudHSMKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_cloudhsm_key.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_cloudhsm_key.go -> Update]["+id+"]")
	var (
		plan  AWSCloudHSMKeyTFSDK
		state AWSCloudHSMKeyTFSDK
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := r.getAwsCloudHsmKey(ctx, id, state.CustomKeyStoreID.ValueString(), state.ID.ValueString(), "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := gjson.Get(response, "id").String()
	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if gjson.Get(response, "linked_state").Bool() &&
		(updateKeyState == "PendingDeletion" || updateKeyState == "PendingReplicaDeletion") {
		msg := "AWS CloudHSM key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	planDesc := types.StringNull()
	planAlias := types.SetNull(types.StringType)
	planTags := types.MapNull(types.StringType)
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if planP != nil {
			planDesc = planP.AWSKeyStoreCommonAwsParamTFSDK.Description
			planAlias = planP.AWSKeyStoreCommonAwsParamTFSDK.Alias
			planTags = planP.AWSKeyStoreCommonAwsParamTFSDK.Tags
		}
	}
	if gjson.Get(response, "linked_state").Bool() {
		var keyEnabled bool
		planEnableKey := false
		if !plan.EnableKey.IsUnknown() {
			keyEnabled = gjson.Get(response, "aws_param.Enabled").Bool()
			planEnableKey = plan.EnableKey.ValueBool()
			if !keyEnabled && planEnableKey {
				enableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return
				}
			}
		}
		planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, Description: planDesc, KeyPolicy: plan.KeyPolicy, EnableRotation: plan.EnableRotation}
		stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy, EnableRotation: state.EnableRotation}
		updateAwsKeyCommon(ctx, id, r.client, planUpdate, stateUpdate, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if !planAlias.IsNull() && !planAlias.IsUnknown() {
			updateAliases(ctx, id, r.client, keyID, planAlias, response, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		if !planTags.IsUnknown() {
			planTagsMap := make(map[string]string, len(planTags.Elements()))
			if len(planTags.Elements()) != 0 {
				resp.Diagnostics.Append(planTags.ElementsAs(ctx, &planTagsMap, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
			}
			updateTags(ctx, id, r.client, planTagsMap, response, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		if !plan.EnableKey.IsUnknown() {
			if keyEnabled && !planEnableKey {
				disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return
				}
			}
		}
	}
	var err error
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	savedPlanDesc := planDesc
	setCloudHSMKeyResourceState(ctx, response, &plan.AWSKeyStoreResourceCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS CloudHSM key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if !gjson.Get(response, "linked_state").Bool() {
		updP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if updP != nil {
			if !savedPlanDesc.IsNull() && !savedPlanDesc.IsUnknown() {
				updP.AWSKeyStoreCommonAwsParamTFSDK.Description = savedPlanDesc
			} else {
				updP.AWSKeyStoreCommonAwsParamTFSDK.Description = types.StringValue("")
			}
			plan.AWSParam = packCloudHSMKeyAwsParam(ctx, updP, &resp.Diagnostics)
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "[resource_aws_cloudhsm_key.go -> Update][response:"+redactAWSResponse(response)+"]")
}

// Delete schedules a linked AWS CloudHSM key for deletion via the schedule-deletion API, or directly
// deletes an unlinked key from CipherTrust Manager. In either case:
//   - If the custom key store cannot be found or is unreachable, a hard error is returned and the key is kept in state.
//   - If the key is already in PendingDeletion state, a warning is returned and the key is removed from state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
func (r *resourceAWSCloudHSMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_cloudhsm_key.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_cloudhsm_key.go -> Delete]["+id+"]")
	var state AWSCloudHSMKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := r.getAwsCloudHsmKey(ctx, id, state.CustomKeyStoreID.ValueString(), keyID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return // key store not found or unreachable - hard error, resource kept in state
	}
	if response == "" {
		return // key not found (404) - warning already added, resource removed from state
	}
	if gjson.Get(response, "linked_state").Bool() {
		keyState := gjson.Get(response, "aws_param.KeyState").String()
		if keyState == "PendingDeletion" {
			msg := "AWS CloudHSM key is already pending deletion, it will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
			return
		}
		removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
		payload := ScheduleForDeletionJSON{
			Days: state.ScheduleForDeletionDays.ValueInt64(),
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error deleting AWS CloudHSM key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS CloudHSM key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				tflog.Warn(ctx, details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS CloudHSM key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				resp.Diagnostics.AddError(details, "")
			}
		}
	} else {
		_, err := r.client.DeleteByURL(ctx, keyID, common.URL_AWS_KEY+"/"+keyID)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS CloudHSM key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				tflog.Warn(ctx, details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS CloudHSM Key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				resp.Diagnostics.AddError(details, "")
				return
			}
		}
	}
	tflog.Debug(ctx, "[resource_aws_cloudhsm_key.go -> Delete][response:"+redactAWSResponse(response)+"]")
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSCloudHSMKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state AWSCloudHSMKeyTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	if !plan.BypassPolicyLockoutSafetyCheck.IsNull() && !plan.BypassPolicyLockoutSafetyCheck.IsUnknown() &&
		plan.BypassPolicyLockoutSafetyCheck != state.BypassPolicyLockoutSafetyCheck {
		changed = append(changed, "bypass_policy_lockout_safety_check")
	}

	if plan.CustomKeyStoreID != state.CustomKeyStoreID {
		changed = append(changed, "custom_key_store_id")
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

// ImportState imports an existing AWS CloudHSM key into Terraform state using its resource ID.
func (r *resourceAWSCloudHSMKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_cloudhsm_key.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_cloudhsm_key.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// decodeCloudHSMKeyTerraformResourceID splits a Terraform resource ID into the AWS region and key ID
// components. The legacy format is '<region>\<aws-key-id>'; the new format is a CM resource UUID with
// no backslash.
func (r *resourceAWSCloudHSMKey) decodeCloudHSMKeyTerraformResourceID(resourceID string) (region string, kid string, err error) {
	idParts := strings.Split(resourceID, "\\")
	if len(idParts) == 1 {
		kid = idParts[0]
	} else if len(idParts) == 2 {
		region = idParts[0]
		kid = idParts[1]
	} else {
		err = fmt.Errorf("%s is not a valid aws cloudhsm key resource id", resourceID)
	}
	return
}

// getAwsCloudHsmKey fetches an AWS CloudHSM key from CipherTrust Manager using the Terraform resource ID.
// If customKeyStoreID is not empty, the custom key store is verified to exist before fetching the key;
// a missing or unreachable key store is always a hard error regardless of opLabel.
// If terraformID has no backslash (new format - CM resource UUID), the key is fetched directly by ID.
// If terraformID has a backslash (legacy region\aws-key-id format), the key is fetched via list query.
// A 404 on the key itself is treated according to opLabel: when opLabel is "deleting" a warning is
// added and an empty string is returned; for any other opLabel an error is added and an empty string is returned.
func (r *resourceAWSCloudHSMKey) getAwsCloudHsmKey(ctx context.Context, id string, customKeyStoreID string, terraformID string, opLabel string, diags *diag.Diagnostics) string {
	if customKeyStoreID != "" {
		getAwsCustomKeyStore(ctx, r.client, id, customKeyStoreID, "reading", diags)
		if diags.HasError() {
			return ""
		}
	}
	region, kid, err := r.decodeCloudHSMKeyTerraformResourceID(terraformID)
	if err != nil {
		diags.AddError("Failed to decode terraform ID "+terraformID+".", err.Error())
		return ""
	}
	if region == "" {
		// New format: terraformID is the CM resource UUID. Fetch directly.
		keyJSON, err := r.client.GetById(ctx, id, terraformID, common.URL_AWS_KEY)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				if opLabel == "deleting" {
					msg := "AWS CloudHSM key (" + terraformID + ") was not found. It will be removed from state."
					details := utils.ApiError(msg, map[string]interface{}{"key_id": terraformID})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
				} else {
					msg := "AWS CloudHSM key (" + terraformID + ") was not found."
					details := utils.ApiError(msg, map[string]interface{}{"key_id": terraformID})
					tflog.Error(ctx, details)
					diags.AddError(details, "")
				}
				return ""
			}
			msg := "Error reading AWS CloudHSM key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": terraformID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
		return keyJSON
	}
	// Legacy format: region\aws-key-id. Use list query for backwards compatibility.
	filters := url.Values{}
	filters.Add("keyid", kid)
	filters.Add("region", region)
	response, err := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Failed to read AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "AWS CloudHSM key was not found."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		if opLabel == "deleting" {
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			diags.AddError(details, "")
		}
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS CloudHSM key, failed to list just one key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	var keyJSON string
	for _, keyResourceJSON := range resources {
		keyJSON = keyResourceJSON.Raw
	}
	return keyJSON
}
