package cckm

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"net/url"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSXKSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSXKSKey{}
)

func NewDataSourceAWSXKSKeys() datasource.DataSource {
	return &dataSourceAWSXKSKey{}
}

func (d *dataSourceAWSXKSKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSXKSKey struct {
	client *common.Client
}

func (d *dataSourceAWSXKSKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_xks_key"
}
func (d *dataSourceAWSXKSKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the AWS XKS key by id.",
		Attributes: map[string]schema.Attribute{
			// Optional input parameters
			"region": schema.StringAttribute{
				Optional:    true,
				Description: "AWS region to which the key belongs.",
			},
			"id": schema.StringAttribute{
				Optional: true,
				Computed: true,
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
			"arn": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			// Read only parameters
			"custom_key_store_id": schema.StringAttribute{
				Computed:    true,
				Description: "Custom keystore ID in AWS.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Computed:    true,
				Description: "Key specification",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the AWS XKS key.",
			},
			"enable_key": schema.BoolAttribute{
				Computed:    true,
				Description: "Enable or disable the key.",
			},
			"key_usage": schema.StringAttribute{
				Computed:    true,
				Description: "Specifies the intended use of the key.",
			},
			"kms": schema.StringAttribute{
				Computed:    true,
				Description: "Name or ID of the KMS to be used to create the key.",
			},
			"origin": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key material.",
			},
			"tags": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "AWS XKS key ID.",
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
				Description: "AWS XKS key policy.",
			},
			"policy_template_tag": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS XKS key tag for an associated policy template.",
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
				Description: "CipherTrust Manager key ID which this key has been rotated to by a scheduled rotation job.",
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
			"source_key_tier": schema.StringAttribute{
				Computed:    true,
				Description: "Source key tier for AWS XKS key. Current option is local. Default is local.",
			},
			"kms_id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *dataSourceAWSXKSKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read]")
	var state AWSXKSKeyDataSourceTFSDK
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	filters := url.Values{}
	if state.KeyID.ValueString() != "" {
		filters.Add("id", state.KeyID.ValueString())
	} else if state.ID.ValueString() != "" {
		filters.Add("id", state.ID.ValueString())
	} else if state.ARN.ValueString() != "" {
		arnParts := strings.Split(state.ARN.ValueString(), ":")
		if len(arnParts) != 6 {
			msg := "Unexpected AWS ARN format."
			details := utils.ApiError(msg, map[string]interface{}{"arn": state.ARN.ValueString()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		kidParts := strings.Split(arnParts[5], "/")
		if len(kidParts) != 2 {
			msg := "Unexpected AWS ARN format, unable to extract AWS KID."
			details := utils.ApiError(msg, map[string]interface{}{"arn": state.ARN.ValueString()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		filters.Add("region", arnParts[3])
		filters.Add("keyid", kidParts[1])
	} else {
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
	response := listAwsKeys(ctx, id, d.client, filters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	d.setXKSKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	kid := gjson.Get(response, "id").String()
	state.ID = types.StringValue(kid)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (d *dataSourceAWSXKSKey) setXKSKeyState(ctx context.Context, response string, plan *AWSXKSKeyDataSourceTFSDK, diags *diag.Diagnostics) {
	setCustomKeyStoreKeyCommonState(ctx, response, &plan.AWSKeyStoreKeyDataSourceCommonTFSDK, diags)
	plan.AWSXKSKeyID = types.StringValue(gjson.Get(response, "aws_param.XksKeyConfiguration.Id").String())
	plan.SourceKeyTier = types.StringValue(gjson.Get(response, "key_source").String())
}

func setCustomKeyStoreKeyCommonState(ctx context.Context, response string, plan *AWSKeyStoreKeyDataSourceCommonTFSDK, diags *diag.Diagnostics) {
	setCommonKeyDataSourceState(ctx, response, &plan.AWSKeyDataSourceCommonTFSDK, diags)
	plan.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	plan.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_params.CustomKeyStoreId").String())
	plan.KMS = types.StringValue(gjson.Get(response, "kms").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	plan.CustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
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
