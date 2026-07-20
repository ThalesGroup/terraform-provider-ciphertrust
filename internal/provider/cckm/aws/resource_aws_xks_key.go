package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
				Description: "Whether to bypass the key policy lockout safety check.",
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS key parameters. Alias, description, and tags are updatable for linked keys; all other fields are computed.",
				Attributes:  xksKeyAwsParamSchemaAttributes(),
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Description: "(Updatable) Enable or disable the key. Only applied when the key is in a linked state. If not set, the key state is not changed after creation.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "(Updatable) Number of days to wait before permanently deleting the AWS KMS key " +
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
						Required:    true,
						Description: "(Updatable) Parameter to indicate if AWS XKS key is blocked for any data plane operation.",
					},
					"custom_key_store_id": schema.StringAttribute{
						Required:    true,
						Description: "ID of the custom keystore where XKS key is to be created.",
					},
					"source_key_id": schema.StringAttribute{
						Required:    true,
						Description: "ID of the source key for AWS XKS key.",
					},
					"source_key_tier": schema.StringAttribute{
						Required:    true,
						Description: "Source key tier for AWS XKS key. Current option is local. Default is local.",
					},
					"linked": schema.BoolAttribute{
						Required:    true,
						Description: "(Updatable) Parameter to indicate if AWS XKS key is linked with AWS.",
					},
				},
			},
		},
	}
}

// Create creates a new AWS XKS key in CipherTrust Manager and sets Terraform state.
// After the key is successfully created, the following post-creation operations are attempted but only
// produce warnings (not errors) on failure, ensuring the key is always saved to state:
//   - Adding additional aliases beyond the first  -  only applied when the key is linked (linked_state = true);
//     unlinked keys do not support alias management via AWS
//   - Registering the key with a CipherTrust Manager scheduled rotation job (enable_rotation block)
//   - Disabling the key if enable_key = false  -  only applied when the key is linked
//   - Refreshing final state from the API after all post-creation operations
func (r *resourceAWSXKSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Create]["+id+"]")
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
		// Block later
		payload.XKSKeyLocalHostedInputParamsJSON.Blocked = false
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
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_XKS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[resource_aws_xks_key.go -> Create][response:"+redactAWSResponse(response)+"]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Do not return error after this

	keyID := gjson.Get(response, "id").String()

	// The following updates are only valid for linked keys

	if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
		planP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
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

	if !plan.EnableKey.IsNull() && !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		disableKey(ctx, id, r.client, keyID, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	if localHostedParamsJSON != nil && localHostedParamsJSON.Blocked {
		var blockDiags diag.Diagnostics
		r.blockXKSKey(ctx, id, keyID, &blockDiags)
		for _, d := range blockDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		tflog.Debug(ctx, "[resource_aws_xks_key.go -> Create][get response:"+redactAWSResponse(response)+"]")
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
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Read]["+id+"]")
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
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
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
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Update]["+id+"]")
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
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		if plan.KeyPolicy != nil || state.KeyPolicy != nil {
			policyPlanUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: plan.KeyPolicy}
			policyStateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy}
			var policyDiags diag.Diagnostics
			updateKeyPolicy(ctx, id, r.client, policyPlanUpdate, policyStateUpdate, &policyDiags)
			for _, d := range policyDiags {
				if d.Severity() == diag.SeverityError {
					resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
				} else {
					resp.Diagnostics.Append(d)
				}
			}
		}
		r.setXKSKeyState(ctx, response, &plan, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		return
	}

	var localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON
	if plan.LocalHostParams != nil {
		localHostedParamsJSON = r.getLocalHostedParams(&plan)

		// Unblock first so that subsequent operations on the key are not blocked.
		if !localHostedParamsJSON.Blocked && gjson.Get(response, "blocked").Bool() {
			r.unblockXKSKey(ctx, id, keyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		r.linkXKSKey(ctx, id, &plan, response, localHostedParamsJSON, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error updating AWS XKS key. Failed to read key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
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
	if planAwsParam != nil && !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Description.IsNull() && !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Description.IsUnknown() {
		planUpdate.Description = planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Description
	}
	updateAwsKeyCommon(ctx, id, r.client, planUpdate, stateUpdate, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if planAwsParam != nil {
		if !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Alias.IsNull() && !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Alias.IsUnknown() {
			updateAliases(ctx, id, r.client, keyID, planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Alias, response, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		if !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsNull() && !planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsUnknown() {
			planTagsMap := make(map[string]string, len(planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Tags.Elements()))
			if len(planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Tags.Elements()) != 0 {
				resp.Diagnostics.Append(planAwsParam.AWSKeyStoreCommonAwsParamTFSDK.Tags.ElementsAs(ctx, &planTagsMap, false)...)
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
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	tflog.Trace(ctx, "[resource_aws_xks_key.go -> Update][response:"+redactAWSResponse(response)+"]")
	r.setXKSKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS XKS key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "[resource_aws_xks_key.go -> Update][response:"+redactAWSResponse(response)+"]")
}

// Delete schedules a linked AWS XKS key for deletion via the schedule-deletion API, or directly
// deletes an unlinked key from CipherTrust Manager. In either case:
//   - If the custom key store cannot be found or is unreachable, a hard error is returned and the key is kept in state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
//   - If the key is already in PendingDeletion state, a warning is returned and the key is removed from state.
func (r *resourceAWSXKSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Delete]["+id+"]")
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
			msg := "Error deleting AWS XKS key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS XKS key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				tflog.Warn(ctx, details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS XKS key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				resp.Diagnostics.AddError(details, "")
			}
		}
	} else {
		_, err := r.client.DeleteByURL(ctx, keyID, common.URL_AWS_KEY+"/"+keyID)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				msg := "AWS XKS key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
				tflog.Warn(ctx, details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				msg := "Error deleting AWS XKS Key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				resp.Diagnostics.AddError(details, "")
				return
			}
		}
	}
	tflog.Debug(ctx, "[resource_aws_xks_key.go -> Delete][response:"+redactAWSResponse(response)+"]")
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

	// On create (no prior state), validate that the config is compatible with an unlinked key.
	if req.State.Raw.IsNull() {
		if plan.LocalHostParams != nil && !plan.LocalHostParams.Linked.ValueBool() {
			var invalid []string

			// More than one alias and tags cannot be used with an unlinked key.
			if !plan.AWSParam.IsNull() && !plan.AWSParam.IsUnknown() {
				xksP := extractXKSKeyAwsParam(ctx, plan.AWSParam, &resp.Diagnostics)
				if xksP != nil {
					if len(xksP.AWSKeyStoreCommonAwsParamTFSDK.Alias.Elements()) > 1 {
						invalid = append(invalid, "aws_param.alias (more than one alias)")
					}
					if !xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsNull() && !xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsUnknown() &&
						len(xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.Elements()) > 0 {
						invalid = append(invalid, "aws_param.tags")
					}
				}
			}

			// key_policy cannot be set on an unlinked key.
			if plan.KeyPolicy != nil {
				invalid = append(invalid, "key_policy")
			}

			// Rotation cannot be enabled on an unlinked key.
			if plan.EnableRotation != nil {
				invalid = append(invalid, "enable_rotation")
			}

			// Disabling the key requires the key to be linked.
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
				if len(xksP.AWSKeyStoreCommonAwsParamTFSDK.Alias.Elements()) > 1 {
					invalid = append(invalid, "aws_param.alias (more than one alias)")
				}
				if !xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsNull() && !xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.IsUnknown() &&
					len(xksP.AWSKeyStoreCommonAwsParamTFSDK.Tags.Elements()) > 0 {
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

	var changed []string

	if !plan.BypassPolicyLockoutSafetyCheck.IsNull() && !plan.BypassPolicyLockoutSafetyCheck.IsUnknown() &&
		plan.BypassPolicyLockoutSafetyCheck != state.BypassPolicyLockoutSafetyCheck {
		changed = append(changed, "bypass_policy_lockout_safety_check")
	}

	// Check immutable fields inside the local_hosted_params block.
	if plan.LocalHostParams != nil && state.LocalHostParams != nil {
		if plan.LocalHostParams.CustomKeyStoreID != state.LocalHostParams.CustomKeyStoreID {
			changed = append(changed, "local_hosted_params.custom_key_store_id")
		}
		if plan.LocalHostParams.SourceKeyID != state.LocalHostParams.SourceKeyID {
			changed = append(changed, "local_hosted_params.source_key_id")
		}
		if plan.LocalHostParams.SourceKeyTier != state.LocalHostParams.SourceKeyTier {
			changed = append(changed, "local_hosted_params.source_key_tier")
		}
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

// ImportState imports an existing AWS XKS key into Terraform state using its resource ID.
func (r *resourceAWSXKSKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setXKSKeyState populates the Terraform state for an AWS XKS key from an API response JSON string.
// In addition to the common top-level and aws_param fields, it refreshes all local_hosted_params
// fields from the API response so that drift in blocked, linked, custom_key_store_id,
// source_key_id (local_key_id), and source_key_tier (key_source) can be detected.
func (r *resourceAWSXKSKey) setXKSKeyState(ctx context.Context, response string, state *AWSXKSKeyTFSDK, diags *diag.Diagnostics) {
	setKeyStoreResourceCommonTopLevel(ctx, response, &state.AWSKeyStoreResourceCommonTFSDK, diags)
	state.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	if diags.HasError() {
		return
	}
	p := extractXKSKeyAwsParam(ctx, state.AWSParam, diags)
	if p == nil {
		p = &AWSXKSKeyAwsParamTFSDK{}
	}
	setAliases(response, &p.AWSKeyStoreCommonAwsParamTFSDK.Alias, diags)
	setKeyTags(ctx, response, &p.AWSKeyStoreCommonAwsParamTFSDK.Tags, diags)
	p.AWSKeyStoreCommonAwsParamTFSDK.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	p.AWSKeyStoreCommonAwsParamTFSDK.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_param.CustomKeyStoreId").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.CreationDate = types.StringValue(gjson.Get(response, "aws_param.CreationDate").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.AWSKeyStoreCommonAwsParamTFSDK.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.AWSKeyStoreCommonAwsParamTFSDK.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.KeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.AWSKeyStoreCommonAwsParamTFSDK.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.AWSKeyStoreCommonAwsParamTFSDK.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	policy := gjson.Get(response, "aws_param.Policy").String()
	if state.AWSParam.IsNull() || state.AWSParam.IsUnknown() ||
		p.AWSKeyStoreCommonAwsParamTFSDK.Policy.IsNull() || p.AWSKeyStoreCommonAwsParamTFSDK.Policy.IsUnknown() ||
		!getPoliciesAreEqual(ctx, policy, p.AWSKeyStoreCommonAwsParamTFSDK.Policy.ValueString(), diags) {
		p.AWSKeyStoreCommonAwsParamTFSDK.Policy = types.StringValue(policy)
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
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> unblockXKSKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> unblockXKSKey]["+id+"]")
	_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/unblock")
	if err != nil {
		msg := "Error unblocking AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
	} else {
		tflog.Info(ctx, fmt.Sprintf("[resource_aws_xks_key.go -> unblockXKSKey] key unblocked successfully. key_id: %s", keyID))
	}
}

// blockXKSKey blocks an AWS XKS key.
func (r *resourceAWSXKSKey) blockXKSKey(ctx context.Context, id string, keyID string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> blockXKSKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> blockXKSKey]["+id+"]")
	_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/block")
	if err != nil {
		msg := "Error blocking AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
	} else {
		tflog.Info(ctx, fmt.Sprintf("[resource_aws_xks_key.go -> blockXKSKey] key blocked successfully. key_id: %s", keyID))
	}
}

// linkXKSKey links an AWS XKS key with AWS if the planned linked state differs from current; unlink is not supported.
func (r *resourceAWSXKSKey) linkXKSKey(ctx context.Context, id string, plan *AWSXKSKeyTFSDK, keyJSON string, localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> linkXKSKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> linkXKSKey]["+id+"]")
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
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/link", payloadJSON)
			if err != nil {
				msg := "Error linking AWS XKS key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tflog.Info(ctx, fmt.Sprintf("[resource_aws_xks_key.go -> linkXKSKey] key linked successfully. key_id: %s", keyID))
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
