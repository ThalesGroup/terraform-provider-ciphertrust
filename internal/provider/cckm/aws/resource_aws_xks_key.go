package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
	"regexp"
	"strings"
)

var (
	_ resource.Resource              = &resourceAWSXKSKey{}
	_ resource.ResourceWithConfigure = &resourceAWSXKSKey{}
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
		Description: "Use this resource to create an AWS XKS key.",
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
			"alias": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Input parameter. Alias assigned to the the XKS key.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
							"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
						),
					),
				},
			},
			"bypass_policy_lockout_safety_check": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to bypass the key policy lockout safety check.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Computed:    true,
				Description: "Specifies a symmetric or asymmetric key and the encryption\\signing algorithms the key supports. Valid values: " + strings.Join(awsKeySpecs, ","),
				Validators:  []validator.String{stringvalidator.OneOf(awsKeySpecs...)},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description of the AWS key. Descriptions can be updated but not removed.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable or disable the key. Default is true.",
				Default:     booldefault.StaticBool(true),
			},
			"key_usage": schema.StringAttribute{
				Computed:    true,
				Description: "Specifies the intended use of the key. RSA key options: ENCRYPT_DECRYPT, SIGN_VERIFY. Default is ENCRYPT_DECRYPT. EC key options: SIGN_VERIFY. Default is SIGN_VERIFY. Symmetric key options: ENCRYPT_DECRYPT. Default is ENCRYPT_DECRYPT.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"ENCRYPT_DECRYPT",
						"SIGN_VERIFY",
						"GENERATE_VERIFY_MAC"}...),
				},
			},
			"origin": schema.StringAttribute{
				Computed: true,
				Optional: true,
				Description: "Source of the key material for the customer managed key.  Options: AWS_KMS, EXTERNAL, EXTERNAL_KEY_STORE, AWS_CLOUDHSM. " +
					"AWS_KMS will create a native AWS key and is the default for AWS native key creation. " +
					"EXTERNAL will create an external AWS key and is the default for import operations. " +
					"This parameter is not required for upload operations. " +
					"Origin is EXTERNAL_KEY_STORE for XKS/HYOK key and AWS_CLOUDHSM for key in CloudHSM key store.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AWS_KMS",
						"EXTERNAL",
						"EXTERNAL_KEY_STORE",
						"AWS_CLOUDHSM"}...),
				},
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Computed:    true,
				Optional:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Default:     int64default.StaticInt64(7),
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				Description: "A list of tags assigned to the XKS key.",
				ElementType: types.StringType,
			},
			//Read-Only Params
			"arn": schema.StringAttribute{
				Computed:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key ID.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "AWS cloud.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was created.",
			},
			"deletion_date": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key is scheduled for deletion.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the key is enabled.",
			},
			"encryption_algorithms": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Encryption algorithms of an asymmetric key",
			},
			"expiration_model": schema.StringAttribute{
				Computed:    true,
				Description: "Expiration model.",
			},
			"external_accounts": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that have access to this key.",
			},
			"key_admins": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Key ID.",
			},
			"key_manager": schema.StringAttribute{
				Computed:    true,
				Description: "Key manager.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Key material origin.",
			},
			"key_rotation_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if rotation is enabled in AWS for this key.",
			},
			"key_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key.",
			},
			"key_state": schema.StringAttribute{
				Computed:    true,
				Description: "Key state.",
			},
			"key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Key type.",
			},
			"key_users": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key name of the external key.",
			},
			"policy": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key policy.",
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
			"aws_xks_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "XKS key ID in AWS.",
			},
			"aws_custom_key_store_id": schema.StringAttribute{
				Computed:    true,
				Description: "Custom keystore ID in AWS.",
			},
		},
		Blocks: map[string]schema.Block{
			"key_policy": schema.ListNestedBlock{
				Description: "Key policy parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"external_accounts": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Other AWS accounts that can access to the key.",
						},
						"key_admins": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - users.",
						},
						"key_admins_roles": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - roles.",
						},
						"key_users": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key users - users.",
						},
						"key_users_roles": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key users - roles.",
						},
						"policy": schema.StringAttribute{
							Optional:    true,
							Description: "AWS key policy json.",
						},
						"policy_template": schema.StringAttribute{
							Optional:    true,
							Description: "CipherTrust policy template ID",
						},
					},
				},
			},
			"enable_rotation": schema.ListNestedBlock{
				Description: "Enable the key for scheduled rotation job.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"job_config_id": schema.StringAttribute{
							Required:    true,
							Description: "ID of the scheduler configuration job that will schedule the key rotation.",
						},
						"key_source": schema.StringAttribute{
							Required:    true,
							Description: "Key source from where the key will be uploaded. Currently, the only option is 'ciphertrust'.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"ciphertrust"}...),
							},
						},
						"disable_encrypt": schema.BoolAttribute{
							Optional:    true,
							Description: "Disable encryption on the old key.",
						},
					},
				},
			},
			"local_hosted_params": schema.ListNestedBlock{
				Description: "Parameters for a AWS XKS key.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"blocked": schema.BoolAttribute{
							Required:    true,
							Description: "Parameter to indicate if AWS XKS key is blocked for any data plane operation.",
						},
						"custom_key_store_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of the custom keystore where XKS key is to be created.",
						},
						"source_key_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of the source key for AWS XKS key.",
						},
						"source_key_tier": schema.StringAttribute{
							Optional:    true,
							Description: "Source key tier for AWS XKS key. Current option is local. Default is local.",
						},
						"linked": schema.BoolAttribute{
							Required:    true,
							Description: "Parameter to indicate if AWS XKS key is linked with AWS.",
						},
					},
				},
			},
		},
	}
}

func (r *resourceAWSXKSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Create]["+id+"]")
	var (
		plan     AWSXKSKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	awsParams := getXKSKeyCommonAWSParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	localHostedParamsJSON := getLocalHostedParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := CreateXKSKeyInputPayloadJSON{
		AwsParams:                        *awsParams,
		XKSKeyLocalHostedInputParamsJSON: *localHostedParamsJSON,
	}
	keyPolicy := getKeyPolicy(ctx, &plan.AWSKeyCommonTFSDK, &resp.Diagnostics)
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
		details := map[string]interface{}{"error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_XKS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS XKS key."
		details := map[string]interface{}{"payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.KeyID = plan.ID
	if gjson.Get(response, "linked_state").Bool() && len(plan.Alias.Elements()) > 1 {
		var diags diag.Diagnostics
		response = addAliases(ctx, r.client, id, &plan.AWSKeyCommonTFSDK, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if len(plan.EnableRotation.Elements()) != 0 {
		var diags diag.Diagnostics
		enableKeyRotationJob(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		enableDisableKey(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	keyID := gjson.Get(response, "id").String()
	plan.ID = types.StringValue(keyID)
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	var diags diag.Diagnostics
	r.setXKSKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_aws_xks_key.go -> Create][response:"+response)
}

func (r *resourceAWSXKSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Read]["+id+"]")
	var state AWSXKSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setXKSKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS XKS key, failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_xks_key.go -> Read][response:"+response)
}

func (r *resourceAWSXKSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Update]["+id+"]")
	var (
		plan  AWSXKSKeyTFSDK
		state AWSXKSKeyTFSDK
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
	plan.KeyID = types.StringValue(keyID)
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS XKS key. Failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	localHostedParamsJSON := getLocalHostedParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.blockUnblockXKSKey(ctx, id, &plan, response, localHostedParamsJSON, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.linkUnlinkXKSKey(ctx, id, &plan, response, localHostedParamsJSON, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS XKS key. Failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	updateAwsKeyCommon(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, &state.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS XKS key. Failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	if gjson.Get(response, "linked_state").Bool() {
		updateAliases(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		planTags := make(map[string]string, len(plan.Tags.Elements()))
		if len(plan.Tags.Elements()) != 0 {
			resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &planTags, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		updateTags(ctx, id, r.client, planTags, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS XKS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setXKSKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS XKS key, failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_xks_key.go -> Update][response:"+response)
}

func (r *resourceAWSXKSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_xks_key.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_xks_key.go -> Delete]["+id+"]")
	var state AWSXKSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Warn(ctx, msg, details)
		resp.Diagnostics.AddWarning(msg, apiDetail(details))
	}
	if gjson.Get(response, "linked_state").Bool() {
		keyState := gjson.Get(response, "aws_param.KeyState").String()
		if keyState == "PendingDeletion" {
			msg := "AWS XKS key is already pending deletion, it will be removed from state."
			details := map[string]interface{}{"key_id": keyID}
			tflog.Warn(ctx, msg, details)
			resp.Diagnostics.AddWarning(msg, apiDetail(details))
		}
		removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
		payload := ScheduleForDeletionJSON{
			Days: state.ScheduleForDeletionDays.ValueInt64(),
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error deleting AWS XKS key, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			resp.Diagnostics.AddError(msg, apiDetail(details))
			return
		}
		_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			msg := "Error deleting AWS XKS key."
			details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			resp.Diagnostics.AddError(msg, apiDetail(details))
		}
	} else {
		_, err := r.client.DeleteByURL(ctx, keyID, common.URL_AWS_KEY+"/"+keyID)
		if err != nil {
			msg := "Error deleting AWS XKS Key."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			resp.Diagnostics.AddError(msg, apiDetail(details))
			return
		}
	}
	tflog.Trace(ctx, "[resource_aws_xks_key.go -> Delete][response:"+response)
}

func (r *resourceAWSXKSKey) setXKSKeyState(ctx context.Context, response string, plan *AWSXKSKeyTFSDK, diags *diag.Diagnostics) {
	setCommonKeyState(ctx, response, &plan.AWSKeyCommonTFSDK, diags)
	plan.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	plan.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
	plan.AWSXKSKeyID = types.StringValue(gjson.Get(response, "aws_param.XksKeyConfiguration.Id").String())
	plan.CustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
	plan.KeySourceContainerID = types.StringValue(gjson.Get(response, "key_source_container_id").String())
	plan.KeySourceContainerName = types.StringValue(gjson.Get(response, "key_source_container_name").String())
	plan.Linked = types.BoolValue(gjson.Get(response, "linked_state").Bool())
	if plan.Linked.ValueBool() {
		plan.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
		setAliases(response, &plan.Alias, diags)
		setKeyTags(ctx, response, &plan.Tags, diags)
	} else {
		if len(plan.Alias.Elements()) == 0 {
			var aliases []attr.Value
			var d diag.Diagnostics
			plan.Alias, d = types.SetValue(types.StringType, aliases)
			if d.HasError() {
				diags.Append(d...)
			}
		}
		if len(plan.Tags.Elements()) == 0 {
			tags := make(map[string]string)
			var d diag.Diagnostics
			plan.Tags, d = types.MapValueFrom(ctx, types.StringType, tags)
			if d.HasError() {
				diags.Append(d...)
			}
		}
	}
	plan.Region = types.StringValue(gjson.Get(response, "region").String())
}

func (r *resourceAWSXKSKey) blockUnblockXKSKey(ctx context.Context, id string, plan *AWSXKSKeyTFSDK, keyJSON string, localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON, diags *diag.Diagnostics) {
	keyID := plan.ID.ValueString()
	planBlocked := localHostedParamsJSON.Blocked
	keyBlocked := gjson.Get(keyJSON, "blocked").Bool()
	if keyBlocked != planBlocked {
		if planBlocked {
			_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/block")
			if err != nil {
				msg := "Error blocking AWS XKS key."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				diags.AddError(msg, apiDetail(details))
				tflog.Error(ctx, msg, details)
			}
		} else {
			_, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/unblock")
			if err != nil {
				msg := "Error unblocking AWS XKS key."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				diags.AddError(msg, apiDetail(details))
				tflog.Error(ctx, msg, details)
			}
		}
	}
}

func (r *resourceAWSXKSKey) linkUnlinkXKSKey(ctx context.Context, id string, plan *AWSXKSKeyTFSDK, keyJSON string, localHostedParamsJSON *XKSKeyLocalHostedInputParamsJSON, diags *diag.Diagnostics) {
	keyID := gjson.Get(keyJSON, "id").String()
	planLinked := localHostedParamsJSON.LinkedState
	keyLinked := gjson.Get(keyJSON, "linked_state").Bool()
	if keyLinked != planLinked {
		if planLinked {
			awsParams := getXKSKeyCommonAWSParams(ctx, plan, diags)
			if diags.HasError() {
				return
			}
			payload := LinkXKSKeyAWSParamsJSON{
				AwsParams: *awsParams,
			}
			if plan.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
				payload.BypassPolicyLockoutSafetyCheck = plan.BypassPolicyLockoutSafetyCheck.ValueBoolPointer()
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error linking AWS XKS key, invalid data input."
				details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/link", payloadJSON)
			if err != nil {
				msg := "Error linking AWS XKS key."
				details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
		} else {
			msg := "Changing an AWS XKS key resource from linked to unlinked state is not supported."
			diags.AddError(msg, "")
		}
	}
}

func getLocalHostedParams(ctx context.Context, plan *AWSXKSKeyTFSDK, diags *diag.Diagnostics) *XKSKeyLocalHostedInputParamsJSON {
	var localHostedInputParams XKSKeyLocalHostedInputParamsJSON
	if !plan.LocalHostParams.IsNull() && len(plan.LocalHostParams.Elements()) != 0 {
		for _, v := range plan.LocalHostParams.Elements() {
			var planLocalHostedParams XKSKeyLocalHostedParamsTFSDK
			diags.Append(tfsdk.ValueAs(ctx, v, &planLocalHostedParams)...)
			if diags.HasError() {
				return nil
			}
			localHostedInputParams.Blocked = planLocalHostedParams.Blocked.ValueBool()
			localHostedInputParams.SourceKeyTier = planLocalHostedParams.SourceKeyTier.ValueString()
			localHostedInputParams.SourceKeyIdentifier = planLocalHostedParams.SourceKeyID.ValueString()
			localHostedInputParams.CustomKeyStoreID = planLocalHostedParams.CustomKeyStoreID.ValueString()
			localHostedInputParams.LinkedState = planLocalHostedParams.Linked.ValueBool()
		}
	}
	return &localHostedInputParams
}

func getXKSKeyCommonAWSParams(ctx context.Context, plan *AWSXKSKeyTFSDK, diags *diag.Diagnostics) *XKSKeyCommonAWSParamsJSON {
	var awsParams XKSKeyCommonAWSParamsJSON
	if plan.Description.ValueString() != "" {
		awsParams.Description = plan.Description.ValueStringPointer()
	}
	keyPolicy := getKeyPolicy(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return nil
	}
	if keyPolicy.Policy != nil {
		awsParams.Policy = keyPolicy.Policy
	}
	if len(plan.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, &plan.AWSKeyCommonTFSDK, diags)
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
	if len(plan.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(plan.Alias.Elements()))
		diags.Append(plan.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return nil
		}
		awsParams.Alias = aliases[0]
	}
	return &awsParams
}
