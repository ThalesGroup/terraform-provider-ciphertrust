package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var (
	_           resource.Resource              = &resourceAWSKey{}
	_           resource.ResourceWithConfigure = &resourceAWSKey{}
	awsKeySpecs                                = []string{"SYMMETRIC_DEFAULT",
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
	PolicyTemplateTagKey = "cckm_policy_template_id"
	LongAwsKeyOpSleep    = 20
	ShortAwsKeyOpSleep   = 5
	AwsValidToRegEx      = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
	AwsValidToFormatMsg  = "must conform to the following example 2024-07-03T14:24:00Z"
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
		Description: "Use this resource to create an AWS key.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region and AWS key identifier separated by a backslash.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "AWS region in which to create the AWS key.",
			},
			"alias": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Alias(es) of the key. To allow for key rotation changing or removing original aliases, all aliases already assigned to another key will be ignored.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
							"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
						),
					),
				},
			},
			"auto_rotate": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Enable AWS autorotation on the key. Default is false.",
				Default:     booldefault.StaticBool(false),
			},
			"auto_rotation_period_in_days": schema.Int64Attribute{
				Computed:    true,
				Optional:    true,
				Description: "Rotation period in days. Optional parameter for auto_rotate. Must be at least 90 days.",
				Validators: []validator.Int64{
					int64validator.AtLeast(90),
					int64validator.AlsoRequires(
						path.Expressions{
							path.MatchRoot("auto_rotate"),
						}...,
					),
				},
			},
			"bypass_policy_lockout_safety_check": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to bypass the key policy lockout safety check.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Optional:    true,
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
				Optional:    true,
				Computed:    true,
				Description: "Specifies the intended use of the key. RSA key options: ENCRYPT_DECRYPT, SIGN_VERIFY. Default is ENCRYPT_DECRYPT. EC key options: SIGN_VERIFY. Default is SIGN_VERIFY. Symmetric key options: ENCRYPT_DECRYPT. Default is ENCRYPT_DECRYPT.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"ENCRYPT_DECRYPT",
						"SIGN_VERIFY",
						"GENERATE_VERIFY_MAC"}...),
				},
			},
			"kms": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name or ID of the KMS to be used to create the key. Required unless replicating a multi-region key.",
			},
			"multi_region": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Creates or identifies a multi-region key.",
			},
			"origin": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Source of the key material. Options: AWS_KMS, EXTERNAL. AWS_KMS will create a native AWS key and is the default for AWS native key creation. EXTERNAL will create an external AWS key and is the default for import operations. This parameter is not required for upload operations.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AWS_KMS",
						"EXTERNAL"}...),
				},
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "Updates the primary region of a multi-region key.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Default:     int64default.StaticInt64(7),
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				Description: "A list of tags assigned to the AWS key.",
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
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the kms",
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
			"multi_region_key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Indicates if the key is the primary key or a replica key.",
			},
			"multi_region_primary_key": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"multi_region_replica_keys": schema.ListAttribute{
				Computed: true,
				ElementType: types.MapType{
					ElemType: types.StringType,
				},
			},
			"next_rotation_date": schema.StringAttribute{
				Computed:    true,
				Description: "Date when auto-rotation will happen next.",
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
			"replica_policy": schema.StringAttribute{
				Computed:    true,
				Description: "Replication policy.",
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
			"replicate_key": schema.ListNestedBlock{
				Description: "Replicate key parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust key ID of the key to replicate.",
						},
						"import_key_material": schema.BoolAttribute{
							Optional:    true,
							Description: "Import key material to a replicated external key.",
						},
						"key_expiration": schema.BoolAttribute{
							Optional:    true,
							Description: "Enable key expiration of the replicated key. Only applies to external keys.",
						},
						"make_primary": schema.BoolAttribute{
							Optional:    true,
							Description: "Update the primary key region to the replicated key's region following replication.",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date the key material of the replicated key expires. Only applies to external keys. Set as UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"upload_key": schema.ListNestedBlock{
				Description: "Key upload parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"source_key_identifier": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust key ID to upload to AWS.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "Enable key expiration. Default is false.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString("local"),
							Description: "Source key tier. Current option is 'local' only. Default is 'local'",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key expiry in UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z. Only valid if 'key_expiration' is true.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"import_key_material": schema.ListNestedBlock{
				Description: "Key import details.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"source_key_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the key created for key material.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString("local"),
							Description: "Source key tier. Current option is local. Default is local.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Description: "Enable key material expiration. Default is false.",
							Default:     booldefault.StaticBool(false),
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key material expiry in UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
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
		},
	}
}

func (r *resourceAWSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Create]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Create]["+uid+"]")
	var (
		plan     AWSKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(plan.ImportKeyMaterial.Elements()) != 0 {
		response = r.importKeyMaterial(ctx, uid, &plan, &resp.Diagnostics)
	} else if len(plan.UploadKey.Elements()) != 0 {
		response = r.uploadKey(ctx, uid, &plan, &resp.Diagnostics)
	} else if len(plan.ReplicateKey.Elements()) != 0 {
		response = r.replicateKey(ctx, uid, &plan, &resp.Diagnostics)
	} else {
		response = r.createKey(ctx, uid, &plan, &resp.Diagnostics)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
	if len(plan.Alias.Elements()) > 1 {
		var diags diag.Diagnostics
		response = addAliases(ctx, r.client, uid, &plan.AWSKeyCommonTFSDK, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if plan.AutoRotate.ValueBool() {
		var diags diag.Diagnostics
		r.enableDisableAutoRotation(ctx, uid, &plan, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if len(plan.EnableRotation.Elements()) != 0 {
		var diags diag.Diagnostics
		enableKeyRotationJob(ctx, uid, r.client, &plan.AWSKeyCommonTFSDK, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		enableDisableKey(ctx, uid, r.client, &plan.AWSKeyCommonTFSDK, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	kid := gjson.Get(response, "aws_param.KeyID").String()
	region := gjson.Get(response, "region").String()
	plan.ID = types.StringValue(encodeAWSKeyTerraformResourceID(region, kid))
	keyID := plan.KeyID.ValueString()
	var err error
	response, err = r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Warn(ctx, msg, details)
		resp.Diagnostics.AddWarning(msg, apiDetail(details))
	}
	var diags diag.Diagnostics
	r.setKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_aws_key.go -> Create][response:"+response)
}

func (r *resourceAWSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Read]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Read]["+uid+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS key, failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Read][response:"+response)
}

func (r *resourceAWSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Update]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Update]["+uid+"]")
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
	keyID := state.KeyID.ValueString()
	plan.KeyID = types.StringValue(keyID)
	response, err := r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	updateAwsKeyCommon(ctx, uid, r.client, &plan.AWSKeyCommonTFSDK, &state.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updateAliases(ctx, uid, r.client, &plan.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
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
	updateTags(ctx, uid, r.client, planTags, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.enableDisableAutoRotation(ctx, uid, &plan, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.PrimaryRegion.IsNull() && plan.PrimaryRegion != state.PrimaryRegion {
		_ = r.updatePrimaryRegion(ctx, uid, &plan, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	response, err = r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS key, failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Update][response:"+response)
}

func updateAwsKeyCommon(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	updateDescription(ctx, uid, client, plan, keyJSON, diags)
	if diags.HasError() {
		return
	}
	enableDisableKey(ctx, uid, client, plan, keyJSON, diags)
	if diags.HasError() {
		return
	}
	updateKeyPolicy(ctx, uid, client, plan, state, diags)
	if diags.HasError() {
		return
	}
	enableDisableKeyRotation(ctx, uid, client, plan, state, diags)
	if diags.HasError() {
		return
	}
}

func (r *resourceAWSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Delete]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Delete]["+uid+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Warn(ctx, msg, details)
		resp.Diagnostics.AddWarning(msg, apiDetail(details))
	}
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := "AWS key is already pending deletion, it will be removed from state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Warn(ctx, msg, details)
		resp.Diagnostics.AddWarning(msg, apiDetail(details))
	}
	removeKeyPolicyTemplateTag(ctx, uid, r.client, response, &resp.Diagnostics)
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting AWS key, invalid data input."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err = r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error deleting AWS XKS key."
		details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Delete][response:"+response)
}

func (r *resourceAWSKey) createKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKey]["+uid+"]")
	commonAwsParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams := r.getCommonAWSKeyCreateParams(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = plan.KMS.ValueString()
	payload := CreateAWSKeyPayloadJSON{
		CommonAWSKeyCreatePayloadJSON: *keyCreateParams,
		AWSParam: AWSKeyParamJSON{
			CommonAWSParamsJSON: *commonAwsParams,
			Origin:              plan.Origin.ValueString(),
		},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key, invalid data input."
		details := map[string]interface{}{"error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS key."
		details := map[string]interface{}{"payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> createKey][response:"+response)
	return response
}

func (r *resourceAWSKey) setKeyState(ctx context.Context, response string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) {
	setCommonKeyState(ctx, response, &plan.AWSKeyCommonTFSDK, diags)
	setAliases(response, &plan.Alias, diags)
	setKeyTags(ctx, response, &plan.Tags, diags)
	plan.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	plan.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	plan.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	if plan.KMS.ValueString() == "" {
		plan.KMS = types.StringValue(gjson.Get(response, "kms").String())
	}
	plan.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	plan.MultiRegionKeyType = types.StringValue(gjson.Get(response, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String())
	setMultiRegionConfiguration(ctx, response, &plan.MultiRegionPrimaryKey, &plan.MultiRegionReplicaKeys, diags)
	plan.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	plan.ReplicaPolicy = types.StringValue(gjson.Get(response, "replica_policy").String())
}

func setCommonKeyState(ctx context.Context, response string, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
	plan.ARN = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	plan.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	plan.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	plan.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	plan.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	plan.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	plan.EncryptionAlgorithms = flattenStringSliceJSON(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	plan.ExpirationModel = types.StringValue(gjson.Get(response, "").String())
	plan.ExternalAccounts = flattenStringSliceJSON(gjson.Get(response, "external_accounts").Array(), diags)
	plan.KeyAdmins = flattenStringSliceJSON(gjson.Get(response, "key_admins").Array(), diags)
	plan.KeyAdminsRoles = flattenStringSliceJSON(gjson.Get(response, "key_admins_roles").Array(), diags)
	plan.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	plan.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	plan.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	plan.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	plan.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	plan.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	plan.KeyUsers = flattenStringSliceJSON(gjson.Get(response, "key_users").Array(), diags)
	plan.KeyUsersRoles = flattenStringSliceJSON(gjson.Get(response, "key_users_roles").Array(), diags)
	setKeyLabels(ctx, response, plan.KeyID.ValueString(), &plan.Labels, diags)
	plan.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	plan.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	plan.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	plan.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	plan.Policy = types.StringValue(gjson.Get(response, "aws_param.Policy").String())
	setPolicyTemplateTag(ctx, response, &plan.PolicyTemplateTag, diags)
	plan.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	plan.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_to").String())
	plan.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	plan.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	plan.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}

func (r *resourceAWSKey) enableDisableAutoRotation(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableAutoRotation]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableAutoRotation]["+uid+"]")
	planAutoRotationEnabled := plan.AutoRotate.ValueBool()
	keyAutoRotationEnabled := gjson.Get(keyJSON, "aws_param.KeyRotationEnabled").Bool()
	keyID := plan.KeyID.ValueString()
	if keyAutoRotationEnabled != planAutoRotationEnabled {
		var response string
		if planAutoRotationEnabled {
			var payload EnableAutoRotationPayloadJSON
			if !plan.AutoRotationPeriodInDays.IsNull() && !plan.AutoRotationPeriodInDays.IsUnknown() {
				payload.RotationPeriodInDays = plan.AutoRotationPeriodInDays.ValueInt64Pointer()
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error enabling auto-rotation for AWS key, invalid data input."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			response, err = r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/enable-auto-rotation", payloadJSON)
			if err != nil {
				msg := "Error enabling auto-rotation for AWS key."
				details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
				diags.AddError(msg, apiDetail(details))
				tflog.Error(ctx, msg, details)
				return
			}
			numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / ShortAwsKeyOpSleep)
			nextRotationDate := gjson.Get(response, "aws_param.NextRotationDate").String()
			for retry := 0; retry < numRetries && nextRotationDate == ""; retry++ {
				time.Sleep(time.Duration(ShortAwsKeyOpSleep) * time.Second)
				response, err = r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
				if err != nil {
					msg := "Error enabling auto-rotation for AWS key, error reading key."
					details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
					tflog.Error(ctx, msg, details)
					diags.AddError(msg, apiDetail(details))
					return
				}
				nextRotationDate = gjson.Get(response, "aws_param.NextRotationDate").String()
				if nextRotationDate != "" {
					break
				}
			}
			if nextRotationDate != "" {
				msg := "Failed to confirm auto-rotation is configured. Consider extending provider configuration option 'aws_operation_timeout'."
				details := map[string]interface{}{"key_id": keyID}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
			}
			return
		} else {
			var err error
			response, err = r.client.PostNoData(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/disable-auto-rotation")
			if err != nil {
				msg := "Error disabling auto-rotation for AWS key."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				diags.AddError(msg, apiDetail(details))
				tflog.Error(ctx, msg, details)
				return
			}
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableAutoRotation][response:"+response)
	}
}

func enableKeyRotationJob(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	rotationParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &rotationParams, false)...)
		if diags.HasError() {
			return
		}
	}
	for _, params := range rotationParams {
		payload := AWSEnableKeyRotationJobPayloadJSON{
			JobConfigID:              params.JobConfigID.ValueString(),
			AutoRotateDisableEncrypt: params.AutoRotateDisableEncrypt.ValueBool(),
		}
		if params.AutoRotateKeySource.ValueString() != "" {
			payload.AutoRotateKeySource = params.AutoRotateKeySource.ValueStringPointer()
		}
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Failed to enable key rotation for AWS key, invalid data input."
			tflog.Error(ctx, msg, map[string]interface{}{"key_id": keyID, "error": err.Error()})
			diags.AddError(msg, err.Error())
			return
		}
		response, err := client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/enable-rotation-job", payloadJSON)
		if err != nil {
			msg := "Failed to enable key rotation for AWS key."
			tflog.Error(ctx, msg, map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()})
			diags.AddError(msg, err.Error())
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableKeyRotationJob][response:"+response)
	}
}

func disableKeyRotationJob(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	keyID := plan.KeyID.ValueString()
	response, err := client.PostNoData(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/disable-rotation-job")
	if err != nil {
		msg := "Error updating AWS key, failed to disable key rotation job for AWS key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		diags.AddError(msg, apiDetail(details))
		tflog.Error(ctx, msg, details)
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> disableKeyRotationJob][response:"+response)
}

func (r *resourceAWSKey) importKeyMaterial(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> importKeyMaterial]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> importKeyMaterial]["+uid+"]")
	var importMaterialPlan AWSKeyImportKeyMaterialTFSDK
	for _, v := range plan.ImportKeyMaterial.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &importMaterialPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	sourceKeyJSON := r.createKeyMaterial(ctx, uid, &importMaterialPlan, diags)
	sourceKeyID := gjson.Get(sourceKeyJSON, "id").String()
	if diags.HasError() {
		return ""
	}
	if plan.Origin.ValueString() == "" {
		plan.Origin = types.StringValue("EXTERNAL")
	}
	response := r.createKey(ctx, uid, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyID := gjson.Get(response, "id").String()
	payload := AWSKeyImportKeyPayloadJSON{
		SourceKeyID:   sourceKeyID,
		SourceKeyTier: importMaterialPlan.SourceKeyTier.ValueString(),
		KeyExpiration: importMaterialPlan.KeyExpiration.ValueBool(),
		ValidTo:       importMaterialPlan.ValidTo.String(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to import key material, invalid data input."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err = r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/import-material", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to import key material."
		details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> importKeyMaterial][response:"+response)
	return response
}

func (r *resourceAWSKey) uploadKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> UploadKeyAWS]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> UploadKeyAWS]["+uid+"]")
	keyCreateParams := r.getCommonAWSKeyCreateParams(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = plan.KMS.ValueString()
	awsParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	var uploadKeyPlan AWSUploadKeyTFSDK
	for _, uploadElement := range plan.UploadKey.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, uploadElement, &uploadKeyPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	uploadAWSParams := UploadAWSKeyParamJSON{
		CommonAWSParamsJSON: *awsParams,
		ValidTo:             uploadKeyPlan.ValidTo.ValueString(),
	}
	payload := UploadAWSKeyPayloadJSON{
		AWSParam:                      &uploadAWSParams,
		CommonAWSKeyCreatePayloadJSON: *keyCreateParams,
		SourceKeyIdentifier:           uploadKeyPlan.SourceKeyID.ValueString(),
		SourceKeyTier:                 uploadKeyPlan.SourceKeyTier.ValueString(),
		KeyExpiration:                 uploadKeyPlan.KeyExpiration.ValueBool(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to upload, invalid data input."
		details := map[string]interface{}{"error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, "api/v1/cckm/aws/upload-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to upload key."
		details := map[string]interface{}{"payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> uploadKey][response:"+response)
	return response
}

func (r *resourceAWSKey) replicateKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> replicateKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> replicateKey]["+uid+"]")
	commonParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyPolicy := getKeyPolicy(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	payload := CreateReplicaKeyPayloadJSON{
		AwsParams:        *commonParams,
		ExternalAccounts: keyPolicy.ExternalAccounts,
		KeyAdmins:        keyPolicy.KeyAdmins,
		KeyAdminsRoles:   keyPolicy.KeyAdminsRoles,
		KeyUsers:         keyPolicy.KeyUsers,
		KeyUsersRoles:    keyPolicy.KeyUsersRoles,
		PolicyTemplate:   keyPolicy.PolicyTemplate,
		ReplicaRegion:    plan.Region.ValueStringPointer(),
	}
	var replicateKeyPlan AWSReplicateKeyTFSDK
	for _, v := range plan.ReplicateKey.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &replicateKeyPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	keyID := replicateKeyPlan.KeyID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to replicate key, invalid data input."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/replicate-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to replicate key."
		details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	replicatedKeyID := gjson.Get(response, "id").String()
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / LongAwsKeyOpSleep)
	for retry := 0; retry < numRetries && keyState == "Creating"; retry++ {
		time.Sleep(time.Duration(LongAwsKeyOpSleep) * time.Second)
		//if err := setAuthToken(ctx, ctp); err != nil {
		//	return nil, err
		//}
		response, err = r.client.GetById(ctx, uid, replicatedKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Failed to replicate key, error reading key."
			details := map[string]interface{}{"key_id": replicatedKeyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
	}
	if keyState != "Enabled" {
		msg := "Failed to confirm AWS key has been replicated in given time. Consider extending provider configuration option 'aws_operation_timeout'."
		details := map[string]interface{}{"key_id": replicatedKeyID}
		tflog.Warn(ctx, msg, details)
		diags.AddWarning(msg, apiDetail(details))
	} else {
		if replicateKeyPlan.MakePrimary.ValueBool() {
			r.makePrimaryKey(ctx, uid, keyID, plan.Region.ValueString(), diags)
			if diags.HasError() {
				return ""
			}
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> replicateKey][response:"+response)
	return response
}

func (r *resourceAWSKey) makePrimaryKey(ctx context.Context, uid string, primaryKeyID string, region string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> makePrimaryKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> makePrimaryKey]["+uid+"]")
	payload := UpdatePrimaryRegionJSON{
		PrimaryRegion: &region,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error setting AWS primary key, invalid data input."
		details := map[string]interface{}{"primary key_id": primaryKeyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return
	}
	response, err := r.client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+primaryKeyID+"/update-primary-region", payloadJSON)
	if err != nil {
		msg := "Error setting AWS primary key."
		details := map[string]interface{}{"primary key_id": primaryKeyID, "payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> makePrimaryKey][response:"+response)
}

func enableDisableKey(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableKey]["+uid+"]")
	planEnable := plan.EnableKey.ValueBool()
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.KeyID.ValueString()
	if keyEnabled != planEnable {
		var (
			response string
			err      error
		)
		if planEnable {
			response, err = client.PostNoData(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/enable")
			if err != nil {
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				msg := "Error enabling AWS key"
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableKey][response:"+response)
		} else {
			response, err = client.PostNoData(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/disable")
			if err != nil {
				msg := "Error disabling AWS key."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
			}
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableKey][response:"+response)
	}
}

func addAliases(ctx context.Context, client *common.Client, uid string, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> addAliases]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> addAliases]["+uid+"]")
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
	if diags.HasError() {
		return ""
	}
	response := keyJSON
	keyID := plan.KeyID.ValueString()
	for i := 1; i < len(planAliases); i++ {
		alias := planAliases[i]
		payload := AddRemoveAliasPayloadJSON{
			Alias: alias,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating AWS key. Failed to add alias, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
		if err != nil {
			msg := "Error creating AWS key, failed to add alias."
			details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> addAliases][response:"+response)
	}
	return response
}

func updateAliases(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateAliases]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateAliases]["+uid+"]")
	var (
		keyAliases []string
		response   string
	)
	for _, a := range gjson.Get(keyJSON, "aws_param.Alias").Array() {
		alias := a.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		keyAliases = append(keyAliases, alias)
	}
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	if len(plan.Alias.Elements()) != 0 {
		diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
		if diags.HasError() {
			return
		}
	}
	keyID := plan.KeyID.ValueString()
	for _, planAlias := range planAliases {
		add := true
		for _, keyAlias := range keyAliases {
			if keyAlias == planAlias {
				add = false
				break
			}
		}
		if add {
			payload := AddRemoveAliasPayloadJSON{
				Alias: planAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating AWS key. Failed to add alias, invalid data input."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			response, err = client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to add alias."
				details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> updateAliases][response:"+response)
		}
	}

	// Remove aliases not in the plan but in the key
	for _, keyAlias := range keyAliases {
		if strings.Contains(keyAlias, "-rotated-") {
			// Dont delete these aliases
			continue
		}
		remove := true
		for _, planAlias := range planAliases {
			if planAlias == keyAlias {
				remove = false
				break
			}
		}
		if remove {
			payload := AddRemoveAliasPayloadJSON{
				Alias: keyAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating AWS key. Failed to remove alias, invalid data input."
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			response, err = client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/delete-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to remove alias."
				details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> updateAliases][response:"+response)
		}
	}
}

func updateDescription(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateDescription]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateDescription]["+uid+"]")
	var (
		keyDescription  string
		planDescription string
	)
	if gjson.Get(keyJSON, "aws_param.Description").Exists() && gjson.Get(keyJSON, "aws_param.Description").String() != "" {
		keyDescription = gjson.Get(keyJSON, "aws_param.Description").String()
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		planDescription = plan.Description.ValueString()
	}
	if planDescription == keyDescription {
		return
	}
	keyID := plan.KeyID.ValueString()
	payload := UpdateKeyDescriptionPayloadJSON{
		Description: plan.Description.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS key. Failed to update description, invalid data input."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return
	}
	response, err := client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/update-description", payloadJSON)
	if err != nil {
		msg := "Error updating AWS key, failed to update description."
		details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updateDescription][response:"+response)
}

func updateTags(ctx context.Context, uid string, client *common.Client, planTags map[string]string, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateTags]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateTags]["+uid+"]")
	var (
		addTagsPayload    AddTagsJSON
		removeTagsPayload RemoveTagsJSON
	)
	keyID := gjson.Get(keyJSON, "id").String()
	keyTags := make(map[string]string)
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != PolicyTemplateTagKey {
			keyTags[tagKey] = tagValue
		}
	}
	for keyTagKey, keyTagValue := range keyTags {
		found := false
		for planKey, planValue := range planTags {
			if planKey == keyTagKey && planValue == keyTagValue {
				found = true
				break
			}
		}
		if !found {
			t := keyTagKey
			removeTagsPayload.Tags = append(removeTagsPayload.Tags, &t)
		}
	}
	if len(removeTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove tags, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		response, err := client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove tags."
			details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> updateTags][response:"+response)
	}
	for planKey, planValue := range planTags {
		found := false
		for keyTagKey, keyTagValue := range keyTags {
			if planKey == keyTagKey && planValue == keyTagValue {
				found = true
				break
			}
		}
		if !found {
			t := AddTagPayloadJSON{
				TagKey:   planKey,
				TagValue: planValue,
			}
			addTagsPayload.Tags = append(addTagsPayload.Tags, t)
		}
	}
	if len(addTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(addTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to add tags, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		response, err := client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/add-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to add tags."
			details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> updateTags][response:"+response)
	}
}

func updateKeyPolicy(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateKeyPolicy]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateKeyPolicy]["+uid+"]")
	statePolicy := getKeyPolicy(ctx, state, diags)
	if diags.HasError() {
		return
	}
	planPolicyPayload := getKeyPolicy(ctx, plan, diags)
	if diags.HasError() {
		return
	}
	if planPolicyPayload.ExternalAccounts != statePolicy.ExternalAccounts ||
		planPolicyPayload.KeyAdmins != statePolicy.KeyAdmins ||
		planPolicyPayload.KeyAdminsRoles != statePolicy.KeyAdminsRoles ||
		planPolicyPayload.KeyUsers != statePolicy.KeyUsers ||
		planPolicyPayload.KeyUsersRoles != statePolicy.KeyUsersRoles ||
		planPolicyPayload.PolicyTemplate != statePolicy.PolicyTemplate ||
		planPolicyPayload.Policy != statePolicy.Policy {
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(planPolicyPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to update key policy, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		response, err := client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/policy", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to update key policy."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
		plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
		tflog.Trace(ctx, "[resource_aws_key.go -> updateKeyPolicy][response:"+response)
	}
}

func (r *resourceAWSKey) updatePrimaryRegion(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updatePrimaryRegion]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updatePrimaryRegion]["+uid+"]")
	planPrimaryRegion := plan.PrimaryRegion.ValueString()
	currentPrimaryRegion := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	if plan.PrimaryRegion.ValueString() == currentPrimaryRegion {
		return keyJSON
	}
	primaryKeyID := r.getPrimaryKeyID(ctx, uid, plan, diags)
	if diags.HasError() {
		return ""
	}
	r.makePrimaryKey(ctx, uid, primaryKeyID, plan.PrimaryRegion.ValueString(), diags)
	if diags.HasError() {
		return ""
	}
	// Refresh current key until primary region is the new region
	keyID := plan.KeyID.ValueString()
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / ShortAwsKeyOpSleep)
	var response string
	for retry := 0; retry < numRetries && currentPrimaryRegion != planPrimaryRegion; retry++ {
		time.Sleep(time.Duration(ShortAwsKeyOpSleep) * time.Second)
		var err error
		response, err = r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error updating AWS key, failed to read key."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		currentPrimaryRegion = gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	if currentPrimaryRegion != planPrimaryRegion {
		msg := "Error updating AWS key. Failed to confirm primary region is configured. Consider extending provider configuration option 'aws_operation_timeout'."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Warn(ctx, msg, details)
		diags.AddWarning(msg, apiDetail(details))
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updatePrimaryRegion][response:"+response)
	return response
}

func enableDisableKeyRotation(ctx context.Context, uid string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableKeyRotation]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableKeyRotation]["+uid+"]")
	planParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &planParams, false)...)
		if diags.HasError() {
			return
		}
	}
	stateParams := make([]AWSKeyEnableRotationTFSDK, 0, len(state.EnableRotation.Elements()))
	diags.Append(state.EnableRotation.ElementsAs(ctx, &stateParams, false)...)
	if diags.HasError() {
		return
	}
	if len(planParams) == 0 && len(stateParams) != 0 {
		disableKeyRotationJob(ctx, uid, client, plan, diags)
		if diags.HasError() {
			return
		}
	}
	if !reflect.DeepEqual(planParams, stateParams) {
		enableKeyRotationJob(ctx, uid, client, plan, diags)
		if diags.HasError() {
			return
		}
	}
}

func (r *resourceAWSKey) getCommonAWSParams(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) *CommonAWSParamsJSON {
	var awsParams CommonAWSParamsJSON
	if len(plan.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(plan.Alias.Elements()))
		diags.Append(plan.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return nil
		}
		awsParams.Alias = aliases[0]
	}
	if plan.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
		awsParams.BypassPolicyLockoutSafetyCheck = plan.BypassPolicyLockoutSafetyCheck.ValueBool()
	}
	if plan.CustomerMasterKeySpec.ValueString() != "" && plan.CustomerMasterKeySpec.ValueString() != types.StringNull().ValueString() {
		awsParams.CustomerMasterKeySpec = plan.CustomerMasterKeySpec.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		awsParams.Description = plan.Description.ValueString()
	}
	if plan.KeyUsage.ValueString() != "" && plan.KeyUsage.ValueString() != types.StringNull().ValueString() {
		awsParams.KeyUsage = plan.KeyUsage.ValueString()
	}
	if awsParams.KeyUsage == "" && awsParams.CustomerMasterKeySpec != "" {
		if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "ECC") {
			awsParams.KeyUsage = "SIGN_VERIFY"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "RSA") {
			awsParams.KeyUsage = "ENCRYPT_DECRYPT"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "HMAC") {
			awsParams.KeyUsage = "GENERATE_VERIFY_MAC"
		}
	}
	if plan.MultiRegion.ValueBool() != types.BoolNull().ValueBool() {
		awsParams.MultiRegion = plan.MultiRegion.ValueBool()
	}
	if len(plan.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, &plan.AWSKeyCommonTFSDK, diags)
		if diags.HasError() {
			return nil
		}
		awsParams.Tags = tags
	}
	if len(plan.KeyPolicy.Elements()) != 0 {
		for _, v := range plan.KeyPolicy.Elements() {
			var keyPolicy AWSKeyPolicyTFSDK
			diags.Append(tfsdk.ValueAs(ctx, v, &keyPolicy)...)
			if diags.HasError() {
				return nil
			}
			if !keyPolicy.Policy.IsNull() && len(keyPolicy.Policy.String()) != 0 {
				policy := keyPolicy.Policy.ValueString()
				awsParams.Policy = json.RawMessage(policy)
			}
		}
	}
	return &awsParams
}

func (r *resourceAWSKey) getCommonAWSKeyCreateParams(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) *CommonAWSKeyCreatePayloadJSON {
	var keyCreateParams CommonAWSKeyCreatePayloadJSON
	keyCreateParams.Region = plan.Region.ValueString()
	keyPolicyPlan := getKeyPolicy(ctx, plan, diags)
	if diags.HasError() {
		return nil
	}
	keyCreateParams.ExternalAccounts = keyPolicyPlan.ExternalAccounts
	keyCreateParams.KeyAdmins = keyPolicyPlan.KeyAdmins
	keyCreateParams.KeyAdminsRoles = keyPolicyPlan.KeyAdminsRoles
	keyCreateParams.KeyUsers = keyPolicyPlan.KeyUsers
	keyCreateParams.KeyUsersRoles = keyPolicyPlan.KeyUsersRoles
	keyCreateParams.PolicyTemplate = keyPolicyPlan.PolicyTemplate
	return &keyCreateParams
}

func getTagsParam(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) []AWSKeyParamTagJSON {
	if len(plan.Tags.Elements()) == 0 {
		return nil
	}
	tags := make(map[string]string, len(plan.Tags.Elements()))
	diags.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
	if diags.HasError() {
		return nil
	}
	var awsTags []AWSKeyParamTagJSON
	for k, v := range tags {
		key := k
		value := v
		tag := AWSKeyParamTagJSON{
			TagKey:   key,
			TagValue: value,
		}
		awsTags = append(awsTags, tag)
	}
	return awsTags
}

func getKeyPolicy(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) *KeyPolicyPayloadJSON {
	var keyPolicy KeyPolicyPayloadJSON
	if !plan.KeyPolicy.IsNull() && len(plan.KeyPolicy.Elements()) != 0 {
		for _, v := range plan.KeyPolicy.Elements() {
			var kp AWSKeyPolicyTFSDK
			diags.Append(tfsdk.ValueAs(ctx, v, &kp)...)
			if diags.HasError() {
				return nil
			}
			if !kp.ExternalAccounts.IsNull() && len(kp.ExternalAccounts.Elements()) != 0 {
				accounts := make([]string, 0, len(kp.ExternalAccounts.Elements()))
				diags.Append(kp.ExternalAccounts.ElementsAs(ctx, &accounts, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.ExternalAccounts = &accounts
			}
			if !kp.KeyAdmins.IsNull() && len(kp.KeyAdmins.Elements()) != 0 {
				keyAdmins := make([]string, 0, len(kp.KeyAdmins.Elements()))
				diags.Append(kp.KeyAdmins.ElementsAs(ctx, &keyAdmins, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyAdmins = &keyAdmins
			}
			if !kp.KeyAdminsRoles.IsNull() && len(kp.KeyAdminsRoles.Elements()) != 0 {
				keyAdminsRoles := make([]string, 0, len(kp.KeyAdminsRoles.Elements()))
				diags.Append(kp.KeyAdminsRoles.ElementsAs(ctx, &keyAdminsRoles, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyAdminsRoles = &keyAdminsRoles
			}
			if !kp.KeyUsers.IsNull() && len(kp.KeyUsers.Elements()) != 0 {
				keyUsers := make([]string, 0, len(kp.KeyUsers.Elements()))
				diags.Append(kp.KeyUsers.ElementsAs(ctx, &keyUsers, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyUsers = &keyUsers
			}
			if !kp.KeyUsersRoles.IsNull() && len(kp.KeyUsersRoles.Elements()) != 0 {
				keyUsersRoles := make([]string, 0, len(kp.KeyUsersRoles.Elements()))
				diags.Append(kp.KeyUsersRoles.ElementsAs(ctx, &keyUsersRoles, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyUsersRoles = &keyUsersRoles
			}
			if !kp.PolicyTemplate.IsNull() && len(kp.PolicyTemplate.String()) != 0 {
				keyPolicy.PolicyTemplate = kp.PolicyTemplate.ValueStringPointer()
			}
		}
	}
	return &keyPolicy
}

func flattenStringSliceJSON(jsonString []gjson.Result, diags *diag.Diagnostics) basetypes.ListValue {
	var values []attr.Value
	for _, item := range jsonString {
		values = append(values, types.StringValue(item.String()))
	}
	stringList, d := types.ListValue(types.StringType, values)
	if d.HasError() {
		diags.Append(d...)
	}
	return stringList
}

func setAliases(response string, stateAlias *types.Set, diags *diag.Diagnostics) {
	var aliases []attr.Value
	aliasesJSON := gjson.Get(response, "aws_param.Alias").Array()
	for _, item := range aliasesJSON {
		alias := item.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		aliases = append(aliases, types.StringValue(alias))
	}
	aliasSet, d := types.SetValue(types.StringType, aliases)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateAlias = aliasSet
}

func setPolicyTemplateTag(ctx context.Context, response string, statePolicyTemplateTag *types.Map, diags *diag.Diagnostics) {
	statePolicyTemplateTagMap := types.MapNull(types.StringType)
	tags := gjson.Get(response, "aws_param.Tags").Array()
	for _, tag := range tags {
		tagKey := gjson.Get(tag.String(), "TagKey").String()
		if tagKey == PolicyTemplateTagKey {
			tagValue := gjson.Get(tag.String(), "TagValue").String()
			elements := map[string]attr.Value{
				tagKey: types.StringValue(tagValue),
			}
			policyTemplateTagMap, d := types.MapValueFrom(ctx, types.StringType, elements)
			if d.HasError() {
				diags.Append(d...)
				return
			}
			statePolicyTemplateTagMap = policyTemplateTagMap
			break
		}
	}
	*statePolicyTemplateTag = statePolicyTemplateTagMap
}

func setKeyTags(ctx context.Context, response string, planTags *types.Map, diags *diag.Diagnostics) {
	tags := make(map[string]string)
	for _, tag := range gjson.Get(response, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != PolicyTemplateTagKey {
			tags[tagKey] = tagValue
		}
	}
	tagMap, d := types.MapValueFrom(ctx, types.StringType, tags)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*planTags = tagMap
}

func setKeyLabels(ctx context.Context, response string, keyID string, stateLabels *types.Map, diags *diag.Diagnostics) {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for key labels, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
	}
	labelMap, d := types.MapValueFrom(ctx, types.StringType, labels)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateLabels = labelMap
}

func setMultiRegionConfiguration(ctx context.Context, keyJSON string, stateMultiRegionPrimaryKey *types.Map, stateMultiRegionReplicaKeys *types.List, diags *diag.Diagnostics) {
	primaryKeyJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey")
	primaryKey := make(map[string]string)
	if len(primaryKeyJSON.Raw) != 0 {
		primaryKey["arn"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
		primaryKey["region"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	stateMultiRegionPrimaryKeyMap, d := types.MapValueFrom(ctx, types.StringType, primaryKey)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateMultiRegionPrimaryKey = stateMultiRegionPrimaryKeyMap
	replicaKeysJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array()
	var replicaKeys basetypes.ListValue
	var replicas []map[string]string
	for _, replicaKeyJSON := range replicaKeysJSON {
		primaryKey = map[string]string{
			"arn":    gjson.Get(replicaKeyJSON.Raw, "Arn").String(),
			"region": gjson.Get(replicaKeyJSON.Raw, "Region").String(),
		}
		replicas = append(replicas, primaryKey)
	}
	replicaKeys, d = types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, replicas)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	stateMultiRegionReplicaKeysList, d := replicaKeys.ToListValue(ctx)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateMultiRegionReplicaKeys = stateMultiRegionReplicaKeysList
}

func (r *resourceAWSKey) getPrimaryKeyID(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> getPrimaryKeyID]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> getPrimaryKeyID]["+uid+"]")
	keyID := plan.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Failed get primary key ID of AWS key " + keyID + ", error reading key."
		tflog.Error(ctx, msg, map[string]interface{}{"error": err.Error()})
		diags.AddError(msg, err.Error())
		return ""
	}
	primaryKeyRegion := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	primaryKeyARN := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
	primaryKeyArnParts := strings.Split(primaryKeyARN, ":")
	if len(primaryKeyArnParts) != 6 {
		msg := "Failed get primary key of AWS key, unexpected ARN format."
		details := map[string]interface{}{"key_id": keyID, "arn": primaryKeyARN}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	kidParts := strings.Split(primaryKeyArnParts[5], "/")
	if len(kidParts) != 2 {
		msg := "Failed get primary key of AWS key, unexpected ARN format."
		details := map[string]interface{}{"key_id": keyID, "arn": primaryKeyArnParts[5]}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kidParts[1])
	filters.Add("region", primaryKeyRegion)
	response, err = r.client.ListWithFilters(ctx, uid, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error reading AWS primary key."
		details := map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "Error reading AWS primary key."
		details := map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS primary key, failed to list just one key."
		details := map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	var primaryKeyID string
	for _, keyResourceJSON := range resources {
		primaryKeyID = gjson.Get(keyResourceJSON.Raw, "id").String()
	}
	return primaryKeyID
}

func (r *resourceAWSKey) createKeyMaterial(ctx context.Context, uid string, importMaterialPlan *AWSKeyImportKeyMaterialTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKeyMaterial]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKeyMaterial]["+uid+"]")
	var response string
	if importMaterialPlan.SourceKeyTier.ValueString() == "local" {
		payload := cm.CMKeyJSON{
			Name:      importMaterialPlan.SourceKeyName.ValueString(),
			Algorithm: "AES",
			Size:      256,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating CipherTrust key, invalid data input."
			details := map[string]interface{}{"error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, common.URL_KEY_MANAGEMENT, payloadJSON)
		if err != nil {
			msg := "Error creating CipherTrust key."
			details := map[string]interface{}{"payload": string(payloadJSON), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> createKeyMaterial][response:"+response)
	}
	return response
}

func apiDetail(details map[string]interface{}) string {
	str := ""
	for k, v := range details {
		if len(str) == 0 {
			str = fmt.Sprintf("%v=%v", k, v)
		} else {
			str = str + fmt.Sprintf("\n%v=%v", k, v)
		}
	}
	return str
}

//nolint:unused
func (r *resourceAWSKey) decodeKeyTerraformResourceID(resourceID string) (region string, kid string, err error) {
	idParts := strings.Split(resourceID, "\\")
	if len(idParts) == 1 {
		kid = idParts[0]
	} else if len(idParts) == 2 {
		region = idParts[0]
		kid = idParts[1]
	} else {
		err = fmt.Errorf("%s is not a valid aws key resource id", resourceID)
	}
	return
}

//nolint:unused
func (r *resourceAWSKey) getKeyByTerraformID(ctx context.Context, uid string, terraformID string, diags *diag.Diagnostics) string {
	region, kid, err := r.decodeKeyTerraformResourceID(terraformID)
	if err != nil {
		diags.AddError("Failed to decode terraform ID "+terraformID+".", err.Error())
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kid)
	filters.Add("region", region)
	response, err := r.client.ListWithFilters(ctx, uid, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Failed to read AWS key."
		details := map[string]interface{}{"kid": kid, "region": region, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "Failed read AWS key."
		details := map[string]interface{}{"kid": kid, "region": region}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS key, failed to list just one key."
		details := map[string]interface{}{"kid": kid, "region": region}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	var keyJSON string
	for _, keyResourceJSON := range resources {
		keyJSON = keyResourceJSON.String()
	}
	return keyJSON
}

func removeKeyPolicyTemplateTag(ctx context.Context, uid string, client *common.Client, keyJSON string, diags *diag.Diagnostics) {
	var policyTemplateID string
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		if tagKey == PolicyTemplateTagKey {
			policyTemplateID = tagKey
			break
		}
	}
	if policyTemplateID != "" {
		var removeTagsPayload RemoveTagsJSON
		keyID := gjson.Get(keyJSON, "id").String()
		tagKey := PolicyTemplateTagKey
		removeTagsPayload.Tags = append(removeTagsPayload.Tags, &tagKey)
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove policy template tag, invalid data input."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Warn(ctx, msg, details)
			diags.AddWarning(msg, apiDetail(details))
			return
		}
		_, err = client.PostDataV2(ctx, uid, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove policy template tag."
			details := map[string]interface{}{"key_id": keyID, "payload": string(payloadJSON), "error": err.Error()}
			tflog.Warn(ctx, msg, details)
			diags.AddWarning(msg, apiDetail(details))
		}
	}
}

func encodeAWSKeyTerraformResourceID(region, kid string) string {
	return region + "\\" + kid
}

func decodeAwsKeyResourceID(resourceID string) (region string, kid string, err error) {
	idParts := strings.Split(resourceID, "\\")
	if len(idParts) == 1 {
		kid = idParts[0]
	} else if len(idParts) == 2 {
		region = idParts[0]
		kid = idParts[1]
	} else {
		err = fmt.Errorf("%s is not a valid aws key resource id", resourceID)
	}
	return
}
