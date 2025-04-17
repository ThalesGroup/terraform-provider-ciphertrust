package cckm

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSKey{}
)

func NewDataSourceAWSKeys() datasource.DataSource {
	return &dataSourceAWSKey{}
}

func (d *dataSourceAWSKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

const (
	KeysURL = "api/v1/cckm/aws/keys"
)

type dataSourceAWSKey struct {
	client *common.Client
}

type AWSKey struct {
	AWSKeyTFSDK
}

func (d *dataSourceAWSKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key"
}
func (d *dataSourceAWSKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the AWS key by id.",
		Attributes: map[string]schema.Attribute{
			"region": schema.StringAttribute{
				Optional:    true,
				Description: "AWS region in which to create or replicate a key.",
			},
			"id": schema.StringAttribute{

				Optional: true,
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
				Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"SYMMETRIC_DEFAULT",
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
						"HMAC_512"}...),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description of the AWS key.",
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable the key. Default is true.",
				Computed:    true,
			},
			"key_usage": schema.StringAttribute{
				Optional:    true,
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
				Computed:    true,
				Optional:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			//Read-Only Params
			"arn": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
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
				Optional:    true,
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
							Description: "Enable key expiration. Default is false.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
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
							Description: "Source key tier. Current option is local. Default is local.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Description: "Enable key material expiration. Default is false.",
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

//nolint:unused
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

//nolint:unused
func (d *dataSourceAWSKey) listAwsKeys(ctx context.Context, uid string, filters url.Values, diags *diag.Diagnostics) string {

	response, err := d.client.ListWithFilters(ctx, uid, AWSKeysURL, filters)
	if err != nil {
		msg := "Failed to list 'ciphertrust_aws_key'."
		details := fmt.Sprintf("%v", filters)
		tflog.Error(ctx, msg)
		diags.AddError(msg, details)
		return ""
	}

	total := gjson.Get(response, "total").Int()
	if total != 1 {
		msg := "Failed list key, error listing single key."
		details := fmt.Sprintf("%v", filters)
		tflog.Error(ctx, msg)
		diags.AddError(msg, details)
	}
	resources := gjson.Get(response, "resources").Array()
	var keyJSON string
	for _, keyResourceJSON := range resources {
		keyJSON = keyResourceJSON.String()
	}
	return keyJSON
}

func (d *dataSourceAWSKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read start]")
	defer tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read end]")
	var state AWSKeyTFSDK
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	filters := url.Values{}

	if state.KeyID.ValueString() != "" {
		filters.Add("id", state.KeyID.ValueString())
	} else if state.ID.ValueString() != "" {
		region, kid, err := decodeAwsKeyResourceID(state.ID.ValueString())
		if err != nil {
			msg := "Error reading 'ciphertrust_aws_key' data source, failed to set resource state."
			resp.Diagnostics.AddError(msg, "")
		}
		filters.Add("region", region)
		filters.Add("keyid", kid)
	} else if state.ARN.ValueString() != "" {
		arnParts := strings.Split(state.ARN.ValueString(), ":")
		if len(arnParts) != 6 {
			msg := "unexpected arn format."
			tflog.Error(ctx, msg)
			resp.Diagnostics.AddError(msg, "")
		}

		kidParts := strings.Split(arnParts[5], "/")
		if len(kidParts) != 2 {
			msg := "unexpected arn format."
			tflog.Error(ctx, msg)
			resp.Diagnostics.AddError(msg, "")
		}
		filters.Add("region", arnParts[3])
		filters.Add("keyid", kidParts[1])

	} else {
		//  Make sure the set is not null or unknown first
		if !state.Alias.IsNull() && !state.Alias.IsUnknown() && len(state.Alias.Elements()) != 0 {

			if len(state.Alias.Elements()) != 0 {
				aliases := make([]string, 0, len(state.Alias.Elements()))
				resp.Diagnostics.Append(state.Alias.ElementsAs(ctx, &aliases, false)...)
				if resp.Diagnostics.HasError() {

					return
				}
				filters.Add("alias", aliases[0])
			}
		}

		if state.AWSKeyID.ValueString() != "" {
			filters.Add("keyid", state.AWSKeyID.ValueString())
		}

		if state.Region.ValueString() != "" {
			filters.Add("region", state.Region.ValueString())
		}

	}

	response := d.listAwsKeys(ctx, uid, filters, &diags)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	setKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading 'ciphertrust_aws_key' data source, failed to set resource state."
		resp.Diagnostics.AddError(msg, "")
		tflog.Error(ctx, msg)
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
