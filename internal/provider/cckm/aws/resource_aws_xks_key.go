package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceAWSXKSKey{}
	_ resource.ResourceWithConfigure   = &resourceAWSXKSKey{}
	_ resource.ResourceWithImportState = &resourceAWSXKSKey{}
	_ resource.ResourceWithModifyPlan  = &resourceAWSXKSKey{}
)

func NewResourceAWSXKSKey() resource.Resource {
	return &resourceAWSXKSKey{}
}

type resourceAWSXKSKey struct {
	client *common.Client
}

func (r *resourceAWSXKSKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_xks_key"
}

func (r *resourceAWSXKSKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSXKSKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage AWS XKS keys in CipherTrust Manager. ",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "XKS key ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region in which the XKS key resides.",
			},
			"bypass_policy_lockout_safety_check": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) Whether to bypass the key policy lockout safety check.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS key parameters. Alias, description, and tags are updatable for linked keys; all other fields are computed.",
				Attributes:  xksKeyAwsParamSchemaAttributes(),
			},
			"enable_key": schema.BoolAttribute{
				Optional: true,
				Description: "Enable or disable the key. Only applied when the key is in a linked state. " +
					"Cannot be set to false at creation time; disable the key via update after it is created.",
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
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the KMS.",
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the KMS.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A map of key/value pairs associated with the key.",
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
				Computed:    true,
				Description: "Custom keystore ID in AWS.",
			},
			"linked": schema.BoolAttribute{
				Computed:    true,
				Description: "Parameter to indicate if AWS XKS key is linked with AWS.",
			},
			"blocked": schema.BoolAttribute{
				Computed:    true,
				Description: "Parameter to indicate if AWS XKS key is blocked for any data plane operation.",
			},
			"key_policy":      keyStoreKeyPolicySchemaAttribute(),
			"enable_rotation": enableRotationSchemaAttribute(),
			"local_hosted_params": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Parameters for a AWS XKS key.",
				Attributes: map[string]schema.Attribute{
					"blocked": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Parameter to indicate if AWS XKS key is blocked for any data plane operation.",
					},
					"custom_key_store_id": schema.StringAttribute{
						Required:    true,
						Description: "(Immutable) ID of the custom keystore where XKS key is to be created.",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								regexp.MustCompile(`\S`),
								"must contain at least one non-whitespace character",
							),
						},
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableString(),
						},
					},
					"source_key_id": schema.StringAttribute{
						Required:    true,
						Description: "(Immutable) ID of the source key for AWS XKS key.",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								regexp.MustCompile(`\S`),
								"must contain at least one non-whitespace character",
							),
						},
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableString(),
						},
					},
					"source_key_tier": schema.StringAttribute{
						Required:    true,
						Description: "(Immutable) Source key tier for AWS XKS key. Current option is local. Default is local.",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								regexp.MustCompile(`\S`),
								"must contain at least one non-whitespace character",
							),
						},
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableString(),
						},
					},
					"linked": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Parameter to indicate if AWS XKS key is linked with AWS.",
					},
				},
			},
		},
	}
}

// Create creates a new AWS XKS key in CipherTrust Manager and sets Terraform state.
// blocked and linked are sent directly in the create payload (the API supports both at creation time).
// Post-create operations such as adding extra aliases, enabling rotation, disabling the key, and
// adding tags must be applied via update after the key is created.
func (r *resourceAWSXKSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> Create][" + id + "]")
	var (
		plan     AWSXKSKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var base *AWSKeyStoreCommonAwsParamTFSDK
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if xksP != nil {
			base = &xksP.AWSKeyStoreCommonAwsParamTFSDK
		}
	}
	payload := CreateXKSKeyInputPayloadJSON{}
	awsParams := getKeyStoreKeyAWSParams(ctx, plan.KeyPolicy, base, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if awsParams != nil {
		payload.AWSParams = *awsParams
	}
	localHostedParamsJSON := r.getLocalHostedParams(&plan)
	if localHostedParamsJSON != nil {
		payload.XKSKeyLocalHostedInputParamsJSON = *localHostedParamsJSON
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
		msg := "Error creating AWS XKS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_XKS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_xks_key.go -> Create][response:" + redactAWSResponse(response) + "]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Do not return error after this

	keyID := gjson.Get(response, "id").String()

	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		r.client.Log.Debug("[resource_aws_xks_key.go -> Create][get response:" + redactAWSResponse(response) + "]")
	}

	var diags diag.Diagnostics
	r.setXKSKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes Terraform state for an AWS XKS key by reading its current data from CipherTrust Manager.
// Returns an error if the key or key store is not reachable.
func (r *resourceAWSXKSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> Read][" + id + "]")
	var state AWSXKSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := r.getAwsXksKey(ctx, id, state.CustomKeyStoreID.ValueString(), keyID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if readKeyState == "PendingDeletion" {
		msg := fmt.Sprintf(utils.PendingDeletionReadFmt, "AWS", "XKS key", readKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setXKSKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update applies plan changes to an AWS XKS key. Returns an error if the key or key store is not reachable.
// Attributes that require a linked key (key_policy, enable_rotation,
// enable_key = false, >1 alias, tags) are rejected at plan time by ModifyPlan when the key stays unlinked.
func (r *resourceAWSXKSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> Update][" + id + "]")
	var (
		plan  AWSXKSKeyTFSDK
		state AWSXKSKeyTFSDK
		err   error
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
	response := r.getAwsXksKey(ctx, id, state.CustomKeyStoreID.ValueString(), keyID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if gjson.Get(response, "linked_state").Bool() && updateKeyState == "PendingDeletion" {
		msg := fmt.Sprintf(utils.PendingDeletionUpdateFmt, "AWS", "XKS key", updateKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	var localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON
	if plan.LocalHostParams != nil {
		localHostedParamsJSON = r.getLocalHostedParams(&plan)

		// Unblock first so that subsequent operations on the key are not blocked.
		if localHostedParamsJSON != nil && !localHostedParamsJSON.Blocked && gjson.Get(response, "blocked").Bool() {
			r.unblockXKSKey(ctx, id, keyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		if localHostedParamsJSON != nil {
			r.linkXKSKey(ctx, id, &plan, response, localHostedParamsJSON, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error updating AWS XKS key. Failed to read key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
	}

	// The following updates are only valid for linked keys

	keyEnabled := gjson.Get(response, "aws_param.Enabled").Bool()
	if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() {
		if !keyEnabled && plan.EnableKey.ValueBool() {
			enableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	if plan.KeyPolicy != nil || state.KeyPolicy != nil {
		planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: plan.KeyPolicy}
		stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy}
		updateKeyPolicy(ctx, id, r.client, planUpdate, stateUpdate, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var planAwsParam *AWSXKSKeyAwsParamTFSDK
	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planAwsParam = extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	stateUpdate := &AWSKeyUpdateInputTFSDK{
		KeyID:          keyID,
		KeyPolicy:      state.KeyPolicy,
		EnableRotation: state.EnableRotation,
	}

	planUpdate := &AWSKeyUpdateInputTFSDK{
		KeyID:       keyID,
		Description: types.StringNull(),
	}

	if plan.EnableRotation != nil {
		planUpdate.EnableRotation = plan.EnableRotation
	}
	if plan.KeyPolicy != nil {
		planUpdate.KeyPolicy = plan.KeyPolicy
	}
	if planAwsParam != nil && !planAwsParam.Description.IsNull() && !planAwsParam.Description.IsUnknown() {
		planUpdate.Description = planAwsParam.Description
	}
	updateAwsKeyCommon(ctx, id, r.client, planUpdate, stateUpdate, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if planAwsParam != nil {
		if !planAwsParam.Alias.IsNull() && !planAwsParam.Alias.IsUnknown() {
			updateAliases(ctx, id, r.client, keyID, planAwsParam.Alias, response, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		if !planAwsParam.Tags.IsNull() && !planAwsParam.Tags.IsUnknown() {
			planTagsMap := make(map[string]string, len(planAwsParam.Tags.Elements()))
			if len(planAwsParam.Tags.Elements()) != 0 {
				resp.Diagnostics.Append(planAwsParam.Tags.ElementsAs(ctx, &planTagsMap, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
			}
			updateTags(ctx, id, r.client, planTagsMap, response, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && keyEnabled && !plan.EnableKey.ValueBool() {
		disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Block last so the key is unblocked for as long as possible during the update.
	if localHostedParamsJSON != nil && localHostedParamsJSON.Blocked && !gjson.Get(response, "blocked").Bool() {
		r.blockXKSKey(ctx, id, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	r.client.Log.Debug("[resource_aws_xks_key.go -> Update][response:" + redactAWSResponse(response) + "]")
	r.setXKSKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS XKS key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_xks_key.go -> Update][response:" + redactAWSResponse(response) + "]")
}

// Delete schedules a linked AWS XKS key for deletion via the schedule-deletion API, or directly
// deletes an unlinked key from CipherTrust Manager. In either case:
//   - If the custom key store cannot be found or is unreachable, a hard error is returned and the key is kept in state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
//   - If the key is already in PendingDeletion state, a warning is returned and the key is removed from state.
func (r *resourceAWSXKSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> Delete][" + id + "]")
	var state AWSXKSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := r.getAwsXksKey(ctx, id, state.CustomKeyStoreID.ValueString(), keyID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return // key store not found or unreachable - hard error, resource kept in state
	}
	if response == "" {
		return // key not found (404) - warning already added, resource removed from state
	}
	if gjson.Get(response, "linked_state").Bool() {
		keyState := gjson.Get(response, "aws_param.KeyState").String()
		if keyState == "PendingDeletion" {
			msg := fmt.Sprintf(utils.PendingDeletionDeleteFmt, "AWS", "XKS key")
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
			msg := "Error deleting AWS XKS key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS XKS key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				r.client.Log.Warn(details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS XKS key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				resp.Diagnostics.AddError(details, "")
			}
		}
	} else {
		_, err := r.client.DeleteByURL(ctx, keyID, common.URL_AWS_KEY+"/"+keyID)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS XKS key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				r.client.Log.Warn(details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS XKS Key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				resp.Diagnostics.AddError(details, "")
				return
			}
		}
	}
	r.client.Log.Debug("[resource_aws_xks_key.go -> Delete][response:" + redactAWSResponse(response) + "]")
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSXKSKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip destroy operations.
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan, state AWSXKSKeyTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// On create (no prior state), validate the configuration.
	if req.State.Raw.IsNull() {
		// These attributes require separate post-create API calls and cannot be applied at creation time.
		// They must be set via update after the key is created.
		var createInvalid []string
		if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
			xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
			if xksP != nil {
				if len(xksP.Alias.Elements()) > 1 {
					createInvalid = append(createInvalid, "aws_param.alias (only one alias may be set at creation; add more via update)")
				}
			}
		}
		if plan.EnableRotation != nil {
			createInvalid = append(createInvalid, "enable_rotation (cannot be set at creation; configure via update)")
		}
		if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
			createInvalid = append(createInvalid, "enable_key = false (cannot be set at creation; disable via update)")
		}
		if len(createInvalid) > 0 {
			resp.Diagnostics.AddError(
				"Invalid attribute at creation time",
				"The following attributes cannot be set when creating an XKS key: "+
					strings.Join(createInvalid, "; ")+".",
			)
		}

		// aws_param.tags and key_policy are only valid when linked = true at creation time;
		// the API only applies them to the AWS-side key when the key is linked.
		if plan.LocalHostParams != nil && !plan.LocalHostParams.Linked.ValueBool() {
			var unlinkedInvalid []string
			if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
				xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
				if xksP != nil {
					if !xksP.Tags.IsNull() && !xksP.Tags.IsUnknown() &&
						len(xksP.Tags.Elements()) > 0 {
						unlinkedInvalid = append(unlinkedInvalid, "aws_param.tags (only valid when local_hosted_params.linked = true)")
					}
				}
			}
			if plan.KeyPolicy != nil {
				unlinkedInvalid = append(unlinkedInvalid, "key_policy (only valid when local_hosted_params.linked = true)")
			}
			if len(unlinkedInvalid) > 0 {
				resp.Diagnostics.AddError(
					"Invalid configuration for an unlinked key",
					"The following attributes cannot be set when local_hosted_params.linked = false: "+
						strings.Join(unlinkedInvalid, "; ")+".",
				)
			}
		}
		return
	}

	// On update, block attributes that require a linked key when the key is staying unlinked.
	// If plan.Linked is true the key is being linked in this same update, so the attributes are valid.
	if plan.LocalHostParams != nil && state.LocalHostParams != nil &&
		!state.LocalHostParams.Linked.ValueBool() && !plan.LocalHostParams.Linked.ValueBool() {
		var invalid []string

		if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
			xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
			if xksP != nil {
				if len(xksP.Alias.Elements()) > 1 {
					invalid = append(invalid, "aws_param.alias (more than one alias)")
				}
				if !xksP.Tags.IsNull() && !xksP.Tags.IsUnknown() &&
					len(xksP.Tags.Elements()) > 0 {
					invalid = append(invalid, "aws_param.tags")
				}
			}
		}
		if plan.KeyPolicy != nil {
			invalid = append(invalid, "key_policy")
		}
		if plan.EnableRotation != nil {
			invalid = append(invalid, "enable_rotation")
		}
		if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
			invalid = append(invalid, "enable_key = false")
		}

		if len(invalid) > 0 {
			resp.Diagnostics.AddError(
				"Invalid configuration for an unlinked key",
				"The following attributes cannot be set when local_hosted_params.linked = false: "+
					strings.Join(invalid, ", ")+". "+
					"\nSet local_hosted_params.linked = true, or remove these attributes.",
			)
			return
		}
	}

}

// ImportState imports an existing AWS XKS key into Terraform state using its resource ID.
func (r *resourceAWSXKSKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setXKSKeyState populates the Terraform state for an AWS XKS key from an API response JSON string.
// In addition to the common top-level and aws_param fields, it refreshes all local_hosted_params
// fields from the API response so that drift in blocked, linked, custom_key_store_id,
// source_key_id (local_key_id), and source_key_tier (key_source) can be detected.
func (r *resourceAWSXKSKey) setXKSKeyState(ctx context.Context, response string, state *AWSXKSKeyTFSDK, diags *diag.Diagnostics) {
	setKeyStoreResourceCommonTopLevel(ctx, r.client, response, &state.AWSKeyStoreResourceCommonTFSDK, diags)
	state.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	if diags.HasError() {
		return
	}
	p := extractXKSKeyAwsParam(ctx, state.AWSParam, diags)
	if p == nil {
		p = &AWSXKSKeyAwsParamTFSDK{}
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
		!getPoliciesAreEqual(r.client, policy, p.Policy.ValueString(), diags) {
		p.Policy = types.StringValue(policy)
	}
	// XKS-specific computed field: populate the nested xks_key_configuration object.
	// Set to nil (null object) when the key is unlinked or the ID is not yet populated.
	xksConfigID := gjson.Get(response, "aws_param.XksKeyConfiguration.Id").String()
	if xksConfigID != "" {
		p.XksKeyConfiguration = &XksKeyConfigurationTFSDK{ID: types.StringValue(xksConfigID)}
	} else {
		p.XksKeyConfiguration = nil
	}
	state.AWSParam = packXKSKeyAwsParam(ctx, p, diags)

	if state.LocalHostParams == nil {
		state.LocalHostParams = &XKSKeyLocalHostedParamsTFSDK{}
	}
	state.LocalHostParams.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	state.LocalHostParams.Linked = types.BoolValue(gjson.Get(response, "linked_state").Bool())
	state.LocalHostParams.CustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
	state.LocalHostParams.SourceKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalHostParams.SourceKeyTier = types.StringValue(gjson.Get(response, "key_source").String())
}

// unblockXKSKey unblocks an AWS XKS key.
func (r *resourceAWSXKSKey) unblockXKSKey(ctx context.Context, id string, keyID string, diags *diag.Diagnostics) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> unblockXKSKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> unblockXKSKey][" + id + "]")
	_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/unblock")
	if err != nil {
		msg := "Error unblocking AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		r.client.Log.Error(details)
	} else {
		r.client.Log.Info(fmt.Sprintf("[resource_aws_xks_key.go -> unblockXKSKey] key unblocked successfully. key_id: %s", keyID))
	}
}

// blockXKSKey blocks an AWS XKS key.
func (r *resourceAWSXKSKey) blockXKSKey(ctx context.Context, id string, keyID string, diags *diag.Diagnostics) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> blockXKSKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> blockXKSKey][" + id + "]")
	_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/block")
	if err != nil {
		msg := "Error blocking AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		r.client.Log.Error(details)
	} else {
		r.client.Log.Info(fmt.Sprintf("[resource_aws_xks_key.go -> blockXKSKey] key blocked successfully. key_id: %s", keyID))
	}
}

// linkXKSKey links an AWS XKS key with AWS if the planned linked state differs from current; unlink is not supported.
func (r *resourceAWSXKSKey) linkXKSKey(ctx context.Context, id string, plan *AWSXKSKeyTFSDK, keyJSON string, localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON, diags *diag.Diagnostics) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_xks_key.go -> linkXKSKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_xks_key.go -> linkXKSKey][" + id + "]")
	keyID := gjson.Get(keyJSON, "id").String()
	planLinked := localHostedParamsJSON.LinkedState
	keyLinked := gjson.Get(keyJSON, "linked_state").Bool()
	if keyLinked != planLinked {
		if planLinked {
			var base *AWSKeyStoreCommonAwsParamTFSDK
			if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
				xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, diags)
				if xksP != nil {
					base = &xksP.AWSKeyStoreCommonAwsParamTFSDK
				}
			}
			awsParams := getKeyStoreKeyAWSParams(ctx, plan.KeyPolicy, base, diags)
			if diags.HasError() {
				return
			}
			payload := LinkXKSKeyAWSParamsJSON{}
			if awsParams != nil {
				payload.AWSParams = *awsParams
			}
			if plan.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
				payload.BypassPolicyLockoutSafetyCheck = plan.BypassPolicyLockoutSafetyCheck.ValueBoolPointer()
			}
			// Populate key policy fields (admins, users, external accounts, policy template)
			// from plan.KeyPolicy. getKeyStoreKeyAWSParams already copies Policy into
			// payload.AWSParams.Policy, so we only need the remaining top-level fields here.
			kp := getKeyPolicyParams(ctx, plan.KeyPolicy, diags)
			if diags.HasError() {
				return
			}
			payload.KeyAdmins = kp.KeyAdmins
			payload.KeyAdminsRoles = kp.KeyAdminsRoles
			payload.KeyUsers = kp.KeyUsers
			payload.KeyUsersRoles = kp.KeyUsersRoles
			payload.ExternalAccounts = kp.ExternalAccounts
			payload.PolicyTemplate = kp.PolicyTemplate
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error linking AWS XKS key, invalid data input."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				diags.AddError(details, "")
				return
			}
			_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/link", payloadJSON)
			if err != nil {
				msg := "Error linking AWS XKS key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				diags.AddError(details, "")
				return
			}
			r.client.Log.Info(fmt.Sprintf("[resource_aws_xks_key.go -> linkXKSKey] key linked successfully. key_id: %s", keyID))
		} else {
			msg := "Changing an AWS XKS key resource from linked to unlinked state is not supported."
			diags.AddError(msg, "")
		}
	}
}

// getLocalHostedParams extracts the local_hosted_params block from the XKS key plan into a JSON payload struct.
func (r *resourceAWSXKSKey) getLocalHostedParams(plan *AWSXKSKeyTFSDK) *XKSKeyLocalHostedInputParamsJSON {
	if plan.LocalHostParams != nil {
		var localHostedInputParams XKSKeyLocalHostedInputParamsJSON
		localHostedInputParams.Blocked = plan.LocalHostParams.Blocked.ValueBool()
		localHostedInputParams.SourceKeyTier = plan.LocalHostParams.SourceKeyTier.ValueString()
		localHostedInputParams.SourceKeyIdentifier = plan.LocalHostParams.SourceKeyID.ValueString()
		localHostedInputParams.CustomKeyStoreID = plan.LocalHostParams.CustomKeyStoreID.ValueString()
		localHostedInputParams.LinkedState = plan.LocalHostParams.Linked.ValueBool()
		return &localHostedInputParams
	}
	return nil
}

// getKeyStoreKeyAWSParams builds the AWS parameter payload (alias, description, tags, policy)
// shared by both XKS and CloudHSM key resource create and link operations. base holds the
// already-extracted common aws_param fields (alias, description, tags). keyPolicy holds the
// key_policy block read from the resource plan directly.
func getKeyStoreKeyAWSParams(ctx context.Context, keyPolicy *AWSKeyPolicyTFSDK, base *AWSKeyStoreCommonAwsParamTFSDK, diags *diag.Diagnostics) *XKSKeyCommonAWSParamsJSON {
	var awsParams XKSKeyCommonAWSParamsJSON
	hasParam := base != nil
	if hasParam && base.Description.ValueString() != "" {
		awsParams.Description = base.Description.ValueStringPointer()
	}
	kp := getKeyPolicyParams(ctx, keyPolicy, diags)
	if diags.HasError() {
		return nil
	}
	if kp.Policy != nil {
		awsParams.Policy = kp.Policy
	}
	if hasParam && len(base.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, base.Tags, diags)
		if diags.HasError() {
			return nil
		}
		for _, t := range tags {
			tag := AWSKeyParamTagJSON{
				TagKey:   t.TagKey,
				TagValue: t.TagValue,
			}
			awsParams.Tags = append(awsParams.Tags, &tag)
		}
	}
	if hasParam && len(base.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(base.Alias.Elements()))
		diags.Append(base.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return nil
		}
		awsParams.Alias = aliases[0]
	}
	return &awsParams
}
