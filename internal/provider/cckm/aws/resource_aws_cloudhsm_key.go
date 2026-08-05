package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
				Description: "(Immutable) Whether to bypass the key policy lockout safety check.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Description: "AWS key parameters. At creation, only the first alias in 'alias' is applied; " +
					"additional aliases require update after the key has been created. " +
					"Description and tags are also updatable; all other fields are computed.",
				Attributes: cloudHSMKeyAwsParamSchemaAttributes(),
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable the key. Cannot be set to false at creation time; disable via update after the key has been created.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "Number of days to wait before permanently deleting the AWS KMS key " +
					"when this resource is destroyed. If omitted during resource creation, " +
					"the value defaults to 7. Once set, the last configured value is retained in state " +
					"and is used during destroy unless changed explicitly.",
				PlanModifiers: []planmodifier.Int64{retainOrDefaultInt64{defaultVal: 7}},
				Validators:    []validator.Int64{int64validator.AtLeast(7), int64validator.AtMost(30)},
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
				Description: "(Immutable) CipherTrust Manager ID of the CloudHSM keystore where key is to be created.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"linked": schema.BoolAttribute{
				Computed:    true,
				Description: "Parameter to indicate if AWS CloudHSM key is linked with AWS.",
			},
			"key_policy": keyStoreKeyPolicySchemaAttribute(),
			"enable_rotation": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Register the key with a CipherTrust Manager scheduled rotation job. " +
					"The 'disable_encrypt' and 'disable_encrypt_on_all_accounts' parameters are mutually exclusive. " +
					"Cannot be configured during key creation; configure via update after the key has been created.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "ID of the scheduler configuration job.",
					},
					"key_source": schema.StringAttribute{
						Required:    true,
						Description: "Key source for rotation. Options: 'local'.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"local"}...)},
					},
					"disable_encrypt": schema.BoolAttribute{
						Optional:    true,
						Description: "Disable encryption on the old key after rotation.",
					},
					"disable_encrypt_on_all_accounts": schema.BoolAttribute{
						Optional:    true,
						Description: "Disable encryption on the old key for all accounts after rotation.",
					},
				},
			},
		},
	}
}

// Create creates a new AWS CloudHSM key in a custom key store via CipherTrust Manager and sets Terraform state.
// The key is always saved to state before returning, even if the final read-back fails (a warning is
// emitted instead of an error so the key ID is preserved for subsequent operations and destroy).
func (r *resourceAWSCloudHSMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_cloudhsm_key.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_cloudhsm_key.go -> Create][" + id + "]")
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
	awsParamsPayload := getKeyStoreKeyAWSParams(ctx, plan.KeyPolicy, base, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := CreateCloudHSMKeyInputPayloadJSON{}
	if awsParamsPayload != nil {
		payload.AWSParams = *awsParamsPayload
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
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	customKeyStoreID := plan.CustomKeyStoreID.ValueString()
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_XKS+"/"+customKeyStoreID+"/create-aws-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Create][response:" + redactAWSResponse(response) + "]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Do not return error after this

	keyID := gjson.Get(response, "id").String()

	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Create][get response:" + redactAWSResponse(response) + "]")
	}

	var diags diag.Diagnostics
	setCloudHSMKeyResourceState(ctx, r.client, response, &plan.AWSKeyStoreResourceCommonTFSDK, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes Terraform state for an AWS CloudHSM key by reading its current data from CipherTrust Manager.
// If the linked key is in PendingDeletion or PendingReplicaDeletion state, a warning is added.
// Returns an error if the key or key store is not reachable.
func (r *resourceAWSCloudHSMKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_cloudhsm_key.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_cloudhsm_key.go -> Read][" + id + "]")
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
		msg := fmt.Sprintf(utils.PendingDeletionReadFmt, "AWS", "CloudHSM key", readKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
	}
	setCloudHSMKeyResourceState(ctx, r.client, response, &state.AWSKeyStoreResourceCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS CloudHSM key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update applies plan changes to an AWS CloudHSM key. All plan changes are passed through to CCKM
// unconditionally; CCKM will return an error for any operation that is not supported on an unlinked key.
// Returns an error if the key or key store is not reachable.
func (r *resourceAWSCloudHSMKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_cloudhsm_key.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_cloudhsm_key.go -> Update][" + id + "]")
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
	r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Update][get response:" + redactAWSResponse(response) + "]")

	keyID := gjson.Get(response, "id").String()
	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if gjson.Get(response, "linked_state").Bool() &&
		(updateKeyState == "PendingDeletion" || updateKeyState == "PendingReplicaDeletion") {
		msg := fmt.Sprintf(utils.PendingDeletionUpdateFmt, "AWS", "CloudHSM key", updateKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
		// Policy updates are permitted by AWS on keys pending deletion.
		if plan.KeyPolicy != nil || state.KeyPolicy != nil {
			planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: plan.KeyPolicy}
			stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy}
			var policyDiags diag.Diagnostics
			updateKeyPolicy(ctx, id, r.client, planUpdate, stateUpdate, &policyDiags)
			for _, d := range policyDiags {
				if d.Severity() == diag.SeverityError {
					resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
				} else {
					resp.Diagnostics.Append(d)
				}
			}
			// Re-fetch to reflect any policy change in state.
			if updated, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY); err == nil {
				response = updated
			}
		}
		// key_policy IS updated in this path - reflect the new config value in state.
		state.KeyPolicy = plan.KeyPolicy
		setCloudHSMKeyResourceState(ctx, r.client, response, &state.AWSKeyStoreResourceCommonTFSDK, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	var planP *AWSCloudHSMKeyAwsParamTFSDK
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planP = extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	planDesc := types.StringNull()
	if planP != nil {
		planDesc = planP.Description
	}
	keyEnabled := gjson.Get(response, "aws_param.Enabled").Bool()
	if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() {
		if !keyEnabled && plan.EnableKey.ValueBool() {
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
	if planP != nil && !planP.Alias.IsNull() && !planP.Alias.IsUnknown() {
		updateAliases(ctx, id, r.client, keyID, planP.Alias, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if planP != nil && !planP.Tags.IsUnknown() {
		planTagsMap := make(map[string]string, len(planP.Tags.Elements()))
		if len(planP.Tags.Elements()) != 0 {
			resp.Diagnostics.Append(planP.Tags.ElementsAs(ctx, &planTagsMap, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		updateTags(ctx, id, r.client, planTagsMap, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && keyEnabled && !plan.EnableKey.ValueBool() {
		disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var err error
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Update][response:" + redactAWSResponse(response) + "]")
	setCloudHSMKeyResourceState(ctx, r.client, response, &plan.AWSKeyStoreResourceCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS CloudHSM key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Update][response:" + redactAWSResponse(response) + "]")
}

// Delete schedules a linked AWS CloudHSM key for deletion via the schedule-deletion API, or directly
// deletes an unlinked key from CipherTrust Manager. In either case:
//   - If the custom key store cannot be found or is unreachable, a hard error is returned and the key is kept in state.
//   - If the key is already in PendingDeletion state, a warning is returned and the key is removed from state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
func (r *resourceAWSCloudHSMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_cloudhsm_key.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_cloudhsm_key.go -> Delete][" + id + "]")
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
			msg := fmt.Sprintf(utils.PendingDeletionDeleteFmt, "AWS", "CloudHSM key")
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			r.client.Log.Warn(details)
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
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS CloudHSM key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				r.client.Log.Warn(details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS CloudHSM key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				resp.Diagnostics.AddError(details, "")
			}
		}
	} else {
		_, err := r.client.DeleteByURL(ctx, keyID, common.URL_AWS_KEY+"/"+keyID)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS CloudHSM key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				r.client.Log.Warn(details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS CloudHSM Key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				resp.Diagnostics.AddError(details, "")
				return
			}
		}
	}
	r.client.Log.Debug("[resource_aws_cloudhsm_key.go -> Delete][response:" + redactAWSResponse(response) + "]")
}

// ModifyPlan enforces two categories of plan-time constraint:
//  1. On create (no prior state): rejects attributes that cannot be configured until after
//     the key has been created (e.g. additional aliases, rotation scheduler, disable).
//  2. On update (prior state exists): rejects changes to immutable attributes that cannot be
//     modified after creation.
func (r *resourceAWSCloudHSMKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip destroy operations.
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan, state AWSCloudHSMKeyTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// On create (no prior state), reject attributes that require the key to be linked.
	if req.State.Raw.IsNull() {
		var invalid []string

		if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
			cloudHSMP := extractCloudHSMKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
			if cloudHSMP != nil && len(cloudHSMP.Alias.Elements()) > 1 {
				invalid = append(invalid, "aws_param.alias (more than one alias)")
			}
		}
		if plan.EnableRotation != nil {
			invalid = append(invalid, "enable_rotation")
		}
		if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
			invalid = append(invalid, "enable_key = false")
		}

		if len(invalid) > 0 {
			resp.Diagnostics.AddError(
				"Invalid configuration for a new CloudHSM key",
				"The following attributes cannot be set at creation time: "+
					strings.Join(invalid, ", ")+". "+
					"\nConfigure these via update after the key has been created.",
			)
		}
		return
	}

}

// ImportState imports an existing AWS CloudHSM key into Terraform state using its resource ID.
func (r *resourceAWSCloudHSMKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_cloudhsm_key.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_cloudhsm_key.go -> ImportState][" + id + "]")
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

// setCloudHSMKeyResourceState populates the full Terraform state for an aws_cloudhsm_key resource.
// Identical to setXKSKeyResourceState except it uses the CloudHSM-typed aws_param struct and
// sets key_rotation_enabled instead of xks_key_configuration.
func setCloudHSMKeyResourceState(ctx context.Context, client *common.Client, response string, state *AWSKeyStoreResourceCommonTFSDK, diags *diag.Diagnostics) {
	setKeyStoreResourceCommonTopLevel(ctx, client, response, state, diags)
	if diags.HasError() {
		return
	}
	p := extractCloudHSMKeyAwsParam(ctx, state.AWSParam, diags)
	if p == nil {
		p = &AWSCloudHSMKeyAwsParamTFSDK{}
	}
	setAliases(response, &p.Alias, diags)
	setKeyTags(ctx, response, &p.Tags, diags)
	p.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	p.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	p.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_param.CustomKeyStoreId").String())
	p.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.CreationDate = types.StringValue(gjson.Get(response, "aws_param.CreationDate").String())
	p.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.KeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	p.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	policy := gjson.Get(response, "aws_param.Policy").String()
	if state.AWSParam.IsNull() || state.AWSParam.IsUnknown() ||
		p.Policy.IsNull() || p.Policy.IsUnknown() ||
		!getPoliciesAreEqual(client, policy, p.Policy.ValueString(), diags) {
		p.Policy = types.StringValue(policy)
	}
	// CloudHSM-specific computed field.
	p.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.AWSParam = packCloudHSMKeyAwsParam(ctx, p, diags)
}
