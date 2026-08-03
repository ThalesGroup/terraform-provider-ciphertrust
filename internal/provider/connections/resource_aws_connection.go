package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const notFoundError = "status: 404"

// awsDefaultCloudName and awsDefaultSTSEndpoints are the documented CM server defaults.
// When the user removes cloud_name or aws_sts_regional_endpoints from their Terraform config,
// the provider sends the explicit default value in the PATCH so CM resets the field.
// aws_region has no universal default and uses UseStateWhenClearingString() instead.
const awsDefaultCloudName = "aws"
const awsDefaultSTSEndpoints = "legacy"

var (
	_ resource.Resource                = &resourceCCKMAWSConnection{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAWSConnection{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMAWSConnection{}
)

func NewResourceCCKMAWSConnection() resource.Resource {
	return &resourceCCKMAWSConnection{}
}

type resourceCCKMAWSConnection struct {
	client *common.Client
}

func (r *resourceCCKMAWSConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_connection"
}

// Schema defines the schema for the resource.
func (r *resourceCCKMAWSConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The APIs in this section deal with connections to the AWS cloud. The following operations can be performed:\n* Create/Delete/Get/Update an AWS connection.\n* List all AWS connections.\n* Test an existing AWS connection.\n*Test a connection that hasn't been created yet by passing in the connection parameters.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
				Description:   "The developer account which owns this resource's application.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"application": schema.StringAttribute{
				Description:   "The application this resource belongs to.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Unique connection name",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"access_key_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				Description: "Key ID of the AWS user",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS IAM role ARN",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Specify AWS Role external ID",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			// aws_region: Optional+Computed. CM supports changing between valid regions but
			// has no mechanism to unset the value once configured (omission, null, and "" are
			// all treated as no-change by the PATCH endpoint). UseStateWhenClearingString()
			// preserves the existing value when the user removes this attribute from config
			// and emits a warning that clearing is unsupported. Updates between valid regions
			// are fully supported (CM accepts the new value).
			"aws_region": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given." +
					"Default values are: \n" +
					"for aws, default region will be \"us-east-1\" \n" +
					"for aws-us-gov, default region will be \"us-gov-east-1\" \n" +
					"for aws-cn, default region will be \"cn-north-1\"\n" +
					"Note: once set, this field cannot be cleared back to unset via Terraform " +
					"(the CM API provides no reset mechanism), but it can be updated to any valid region.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			// last_connection_ok/error/at: retain UseStateForUnknown() — these are Computed-only
			// status fields. Without the modifier the plan value is Unknown after an update,
			// causing "provider produced inconsistent result after apply" when CM hasn't run
			// a connectivity test yet (fields absent from response → null, but plan expects
			// the prior state value). UseStateForUnknown() preserves the prior value in the
			// plan, and the post-PATCH r.Exists() hydration overwrites it with the real value.
			// aws_sts_regional_endpoints: CM default is "legacy". When removed from config,
			// the provider sends the explicit default value in the PATCH so CM resets the field.
			// This differs from aws_region which has no universal default.
			"aws_sts_regional_endpoints": schema.StringAttribute{
				Optional: true,
				Description: "By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are: \n" +
					"legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com \n" +
					"regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region. \n",
				Validators: []validator.String{
					stringvalidator.OneOf("legacy", "regional"),
				},
			},
			// cloud_name: CM default is "aws". When removed from config, the provider sends
			// the explicit default value in the PATCH so CM resets the field. This differs
			// from aws_region which has no universal default.
			"cloud_name": schema.StringAttribute{
				Optional: true,
				Description: "Name of the cloud. Options are: \n" +
					"aws (default) \n" +
					"aws-us-gov \n" +
					"aws-cn",
				Validators: []validator.String{
					stringvalidator.OneOf("aws", "aws-us-gov", "aws-cn"),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},

			"iam_role_anywhere": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"anywhere_role_arn": schema.StringAttribute{
						Required:    true,
						Description: "Specify AWS IAM Anywhere Role ARN",
					},
					"certificate": schema.StringAttribute{
						Required:    true,
						Description: "Upload the external certificate for AWS IAM Anywhere Cloud connections. This option is used when \"role_anywhere\" is set to \"true\".",
					},
					"profile_arn": schema.StringAttribute{
						Required:    true,
						Description: "Specify AWS IAM Anywhere Profile ARN",
					},
					"trust_anchor_arn": schema.StringAttribute{
						Required:    true,
						Description: "Specify AWS IAM Anywhere Trust Anchor ARN",
					},
					"private_key": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "The private key associated with the certificate",
					},
				},
			},
			"is_role_anywhere": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) Set the parameter to true to create connections of type AWS IAM Anywhere with temporary credentials.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection.",
			},
			"products": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Array of the CipherTrust products associated with the connection. " +
					"Valid values are: cckm, ddc, cte, data discovery, backup/restore, logger, hsm_anchored_domain, csm. " +
					"Any other value is rejected by CipherTrust Manager with a 422 error. " +
					"Note: once set, this field cannot be cleared back to unset via Terraform. " +
					"The CM API silently ignores an empty products list on update; the prior value is preserved in state and a warning is emitted. " +
					"To remove all products, destroy and recreate the resource.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("cckm", "ddc", "cte", "data discovery", "backup/restore", "logger", "hsm_anchored_domain", "csm"),
					),
				},
			},
			"secret_access_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "Secret associated with the access key ID of the AWS user. Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). CipherTrust Manager never returns this value on GET, so Terraform cannot detect out-of-band rotation on its own; to resend a rotated secret, change `secret_access_key` and bump `secret_access_key_version` in the same apply.",
			},
			"secret_access_key_version": schema.Int64Attribute{
				Optional:    true,
				Description: "Arbitrary version number stored in state and used to trigger re-sending `secret_access_key` to CipherTrust Manager. Since `secret_access_key` is write-only, Terraform cannot detect a change in its value on its own; increment this on every apply where you want the current `secret_access_key` value re-sent.",
			},
			//common response parameters
			"uri": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
			"service": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"category": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"resource_url": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_ok": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"last_connection_error": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// ModifyPlan enforces the products-clear restriction at plan time (TFIN-479).
// The CM PATCH endpoint silently ignores an empty products list, so a transition
// from a non-empty list to null/[] would silently no-op and then cause perpetual
// drift on every subsequent plan. Block the operation with a clear diagnostic
// so the user understands they must destroy and recreate to remove products.
func (r *resourceCCKMAWSConnection) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Only relevant for updates (both state and plan are non-null).
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var state AWSConnectionModelTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan AWSConnectionModelTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Block: non-empty products → null/empty (clearing is unsupported by the CM API).
	if len(state.Products) > 0 && len(plan.Products) == 0 {
		resp.Diagnostics.AddError(
			"Cannot clear products: unsupported by CipherTrust Manager API",
			"CipherTrust Manager does not support clearing the products field once it has been "+
				"set (the PATCH endpoint silently ignores an empty list). "+
				"Remove this change from your configuration, or destroy and recreate the resource "+
				"to remove all products.",
		)
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCCKMAWSConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_aws_connection.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan AWSConnectionModelTFSDK
	var payload AWSConnectionModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// secret_access_key is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.SecretAccessKey is always
	// null here. req.Config is populated fresh from the HCL configuration on every RPC
	// (not derived from the nullified plan), so it reliably carries the actual value.
	var config AWSConnectionModelTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = plan.Name.ValueString()

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		payload.Description = plan.Description.ValueString()
	}
	if !plan.AccessKeyID.IsNull() && !plan.AccessKeyID.IsUnknown() {
		payload.AccessKeyID = plan.AccessKeyID.ValueString()
	}
	if !plan.AssumeRoleARN.IsNull() && !plan.AssumeRoleARN.IsUnknown() {
		payload.AssumeRoleARN = plan.AssumeRoleARN.ValueString()
	}
	if !plan.AssumeRoleExternalID.IsNull() && !plan.AssumeRoleExternalID.IsUnknown() {
		payload.AssumeRoleExternalID = plan.AssumeRoleExternalID.ValueString()
	}
	if !plan.AWSRegion.IsNull() && !plan.AWSRegion.IsUnknown() {
		payload.AWSRegion = plan.AWSRegion.ValueString()
	}
	// aws_sts_regional_endpoints: send explicit default when cleared so CM resets the field.
	// CM treats omission and empty string as no-op; the explicit default is the only reset mechanism.
	if !plan.AWSSTSRegionalEndpoints.IsNull() && !plan.AWSSTSRegionalEndpoints.IsUnknown() {
		payload.AWSSTSRegionalEndpoints = plan.AWSSTSRegionalEndpoints.ValueString()
	} else if plan.AWSSTSRegionalEndpoints.IsNull() {
		payload.AWSSTSRegionalEndpoints = awsDefaultSTSEndpoints
	}
	// cloud_name: same pattern — send explicit default when cleared.
	if !plan.CloudName.IsNull() && !plan.CloudName.IsUnknown() {
		payload.CloudName = plan.CloudName.ValueString()
	} else if plan.CloudName.IsNull() {
		payload.CloudName = awsDefaultCloudName
	}

	var varIAMRoleAnywhere IAMRoleAnywhereJSON
	if !reflect.DeepEqual((*IAMRoleAnywhereTFSDK)(nil), plan.IAMRoleAnywhere) {
		if plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != "" && plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.AnywhereRoleARN = plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString()
		}
		if plan.IAMRoleAnywhere.Certificate.ValueString() != "" && plan.IAMRoleAnywhere.Certificate.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.Certificate = plan.IAMRoleAnywhere.Certificate.ValueString()
		}
		if plan.IAMRoleAnywhere.ProfileARN.ValueString() != "" && plan.IAMRoleAnywhere.ProfileARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.ProfileARN = plan.IAMRoleAnywhere.ProfileARN.ValueString()
		}
		if plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != "" && plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.TrustAnchorARN = plan.IAMRoleAnywhere.TrustAnchorARN.ValueString()
		}
		if plan.IAMRoleAnywhere.PrivateKey.ValueString() != "" && plan.IAMRoleAnywhere.PrivateKey.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.PrivateKey = plan.IAMRoleAnywhere.PrivateKey.ValueString()
		}
		payload.IAMRoleAnywhere = &varIAMRoleAnywhere
	}

	if !plan.IsRoleAnywhere.IsNull() && !plan.IsRoleAnywhere.IsUnknown() {
		payload.IsRoleAnywhere = plan.IsRoleAnywhere.ValueBool()
	}

	if v := config.SecretAccessKey.ValueString(); v != "" {
		payload.SecretAccessKey = v
	}

	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	// Add meta to payload
	metaPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metaPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = metaPayload

	var productsArr []string
	for _, product := range plan.Products {
		productsArr = append(productsArr, product.ValueString())
	}
	payload.Products = productsArr

	// Backwards compatibility: fall back to environment variables when credentials are
	// omitted from HCL config. access_key_id is Computed, so its resolved value is written
	// back into plan/state to prevent perpetual plan diffs. secret_access_key is write-only
	// (never stored in state), so its resolved value is only used for this request's payload.
	// IAM Roles Anywhere connections authenticate via certificate/trust anchor, so CM
	// rejects the request outright if access_key_id/secret_access_key are non-null —
	// never apply this fallback for them.
	if !payload.IsRoleAnywhere {
		if payload.SecretAccessKey == "" {
			if v := os.Getenv("AWS_SECRET_ACCESS_KEY"); v != "" {
				payload.SecretAccessKey = v
			}
		}
		if payload.AccessKeyID == "" {
			if v := os.Getenv("AWS_ACCESS_KEY_ID"); v != "" {
				payload.AccessKeyID = v
				plan.AccessKeyID = types.StringValue(v)
			}
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating AWS Connection on CipherTrust Manager: ",
			"Could not create AWS Connection, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Category = types.StringValue(gjson.Get(response, "category").String())
	plan.Service = types.StringValue(gjson.Get(response, "service").String())
	plan.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())

	// Computed-only status fields — hydrate unconditionally; gjson returns zero value when absent
	plan.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	plan.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	plan.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	// access_key_id is Optional+Computed. When neither config nor the env-var fallback
	// supplied a value (e.g. iam_role_anywhere connections), plan still holds the Unknown
	// value from req.Plan.Get; resolve it to a known value before State.Set, or Terraform
	// rejects the apply with "provider returned invalid result object".
	if plan.AccessKeyID.IsUnknown() {
		if r := gjson.Get(response, "access_key_id"); r.Exists() {
			plan.AccessKeyID = types.StringValue(r.String())
		} else {
			plan.AccessKeyID = types.StringNull()
		}
	}

	if plan.Description.IsUnknown() {
		if r := gjson.Get(response, "description"); r.Exists() && r.Type != gjson.Null {
			plan.Description = types.StringValue(r.String())
		} else {
			plan.Description = types.StringNull()
		}
	}

	if plan.AssumeRoleARN.IsUnknown() {
		if r := gjson.Get(response, "assume_role_arn"); r.Exists() && r.Type != gjson.Null {
			plan.AssumeRoleARN = types.StringValue(r.String())
		} else {
			plan.AssumeRoleARN = types.StringNull()
		}
	}

	if plan.AssumeRoleExternalID.IsUnknown() {
		if r := gjson.Get(response, "assume_role_external_id"); r.Exists() && r.Type != gjson.Null {
			plan.AssumeRoleExternalID = types.StringValue(r.String())
		} else {
			plan.AssumeRoleExternalID = types.StringNull()
		}
	}

	// aws_region is Optional+Computed (Computed added for UseStateWhenClearingString()).
	// When the user omits aws_region from config, plan holds Unknown; resolve to a known
	// value from the CREATE response to prevent "provider returned invalid result object".
	if plan.AWSRegion.IsUnknown() {
		if r := gjson.Get(response, "aws_region"); r.Exists() && r.Type != gjson.Null && r.String() != "" {
			plan.AWSRegion = types.StringValue(r.String())
		} else {
			plan.AWSRegion = types.StringNull()
		}
	}

	// secret_access_key is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.SecretAccessKey = types.StringNull()

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_aws_connection.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCCKMAWSConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AWSConnectionModelTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_aws_connection.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_aws_connection.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"AWS Connection Not Found on CipherTrust Manager — State Preserved",
				fmt.Sprintf("The managed AWS connection %q was not found during refresh.\n\n"+
					"To prevent accidental data loss and key recreation, this connection has been kept in state.\n\n"+
					"Please verify if this is a transient cluster issue. If the connection was permanently deleted, "+
					"manually remove it from state: 'terraform state rm <resource-address>'",
					state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading AWS Connection on CipherTrust Manager: ",
			"Could not read AWS Connection id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Computed-only fields — always present in GET response; UseStateForUnknown keeps them stable
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Service = types.StringValue(gjson.Get(response, "service").String())
	state.Category = types.StringValue(gjson.Get(response, "category").String())
	state.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())

	// Computed-only status fields — hydrate unconditionally; gjson returns zero value when absent
	state.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	state.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	state.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	// Required / always-present user fields
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	// description: purely user-settable; CM only returns what was explicitly set.
	if r := gjson.Get(response, "description"); r.Exists() && r.Type != gjson.Null {
		state.Description = types.StringValue(r.String())
	} else {
		state.Description = types.StringNull()
	}
	// access_key_id: only hydrate from API when the user configured the field (prior state
	// is non-null). When null in state, the connection may carry credentials set via the
	// env-var fallback in Create(); reading them back would produce a spurious diff against
	// an HCL config that does not declare the field. When non-null, update from API to
	// surface drift; if absent from response, preserve prior state (CDSPaaS may not echo
	// credentials back in GET responses).
	if !state.AccessKeyID.IsNull() {
		if r := gjson.Get(response, "access_key_id"); r.Exists() {
			state.AccessKeyID = types.StringValue(r.String())
		}
	}
	if r := gjson.Get(response, "assume_role_arn"); r.Exists() && r.Type != gjson.Null {
		state.AssumeRoleARN = types.StringValue(r.String())
	} else {
		state.AssumeRoleARN = types.StringNull()
	}
	if r := gjson.Get(response, "assume_role_external_id"); r.Exists() && r.Type != gjson.Null {
		state.AssumeRoleExternalID = types.StringValue(r.String())
	} else {
		state.AssumeRoleExternalID = types.StringNull()
	}

	// aws_region, aws_sts_regional_endpoints, cloud_name: CM returns server defaults
	// (e.g. cloud_name="aws", aws_sts_regional_endpoints="legacy", aws_region="us-east-1")
	// even when the user did not configure them. Guard with IsNull to prevent perpetual
	// drift for users who never set these fields (same pattern as is_role_anywhere).
	// aws_region: UseStateWhenClearingString() handles the "clear" case at plan time.
	// Read() unconditionally observes the live CM value so drift is always visible.
	if r := gjson.Get(response, "aws_region"); r.Exists() && r.Type != gjson.Null && r.String() != "" {
		state.AWSRegion = types.StringValue(r.String())
	} else {
		state.AWSRegion = types.StringNull()
	}
	// aws_sts_regional_endpoints: !IsNull() guard removed. Default-suppression prevents
	// false drift for connections that never configured this field (CM always returns
	// "legacy" as a server default). When state was previously configured (non-null),
	// the live CM value is stored unconditionally so drift is visible.
	if r := gjson.Get(response, "aws_sts_regional_endpoints"); r.Exists() && r.Type != gjson.Null && r.String() != "" {
		apiVal := r.String()
		if apiVal == awsDefaultSTSEndpoints && state.AWSSTSRegionalEndpoints.IsNull() {
			state.AWSSTSRegionalEndpoints = types.StringNull()
		} else {
			state.AWSSTSRegionalEndpoints = types.StringValue(apiVal)
		}
	} else {
		state.AWSSTSRegionalEndpoints = types.StringNull()
	}
	// cloud_name: same default-suppression pattern. CM default is "aws".
	if r := gjson.Get(response, "cloud_name"); r.Exists() && r.Type != gjson.Null && r.String() != "" {
		apiVal := r.String()
		if apiVal == awsDefaultCloudName && state.CloudName.IsNull() {
			state.CloudName = types.StringNull()
		} else {
			state.CloudName = types.StringValue(apiVal)
		}
	} else {
		state.CloudName = types.StringNull()
	}

	// is_role_anywhere: CM always returns this field (default false).
	// Guard with IsNull() check: users who do not configure this attribute have null in state.
	// Writing false unconditionally for unconfigured users causes perpetual drift (null → false).
	if !state.IsRoleAnywhere.IsNull() {
		if r := gjson.Get(response, "is_role_anywhere"); r.Exists() {
			state.IsRoleAnywhere = types.BoolValue(r.Bool())
		} else {
			state.IsRoleAnywhere = types.BoolNull()
		}
	}

	// secret_access_key: write-only — never stored in state, so there is nothing to
	// hydrate or preserve here. state.SecretAccessKey is always null.

	// iam_role_anywhere: CM may return an empty block when not configured. Only populate state
	// when the anywhere_role_arn sub-field (Required) is non-empty, indicating a real configuration.
	if r := gjson.Get(response, "iam_role_anywhere"); r.Exists() && r.Type != gjson.Null {
		anywhereRoleARN := gjson.Get(response, "iam_role_anywhere.anywhere_role_arn").String()
		if anywhereRoleARN != "" {
			var nested IAMRoleAnywhereTFSDK
			nested.AnywhereRoleARN = types.StringValue(anywhereRoleARN)
			nested.Certificate = types.StringValue(gjson.Get(response, "iam_role_anywhere.certificate").String())
			nested.ProfileARN = types.StringValue(gjson.Get(response, "iam_role_anywhere.profile_arn").String())
			nested.TrustAnchorARN = types.StringValue(gjson.Get(response, "iam_role_anywhere.trust_anchor_arn").String())
			// private_key: write-only — absent from CM GET responses; preserve from prior state
			if state.IAMRoleAnywhere != nil {
				nested.PrivateKey = state.IAMRoleAnywhere.PrivateKey
			} else {
				nested.PrivateKey = types.StringNull()
			}
			state.IAMRoleAnywhere = &nested
		} else {
			state.IAMRoleAnywhere = nil
		}
	} else {
		state.IAMRoleAnywhere = nil
	}

	// labels map — guard with IsNull: Create() sends {} to CM when not configured,
	// so CM echoes back {} even for unconfigured users; IsNull guard prevents false drift.
	if !state.Labels.IsNull() {
		if r := gjson.Get(response, "labels"); r.Exists() && r.Type != gjson.Null {
			labelsMap := make(map[string]attr.Value)
			r.ForEach(func(key, value gjson.Result) bool {
				labelsMap[key.String()] = types.StringValue(value.String())
				return true
			})
			labelsVal, diags := types.MapValue(types.StringType, labelsMap)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			state.Labels = labelsVal
		} else {
			state.Labels = types.MapNull(types.StringType)
		}
	}

	// meta map — same IsNull guard as labels
	if !state.Meta.IsNull() {
		if r := gjson.Get(response, "meta"); r.Exists() && r.Type != gjson.Null {
			metaMap := make(map[string]attr.Value)
			r.ForEach(func(key, value gjson.Result) bool {
				metaMap[key.String()] = types.StringValue(value.String())
				return true
			})
			metaVal, diags := types.MapValue(types.StringType, metaMap)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			state.Meta = metaVal
		} else {
			state.Meta = types.MapNull(types.StringType)
		}
	}

	// products list — distinguish null (not configured) from empty (configured as [])
	if r := gjson.Get(response, "products"); r.Exists() && r.Type != gjson.Null {
		products := []types.String{}
		for _, v := range r.Array() {
			products = append(products, types.StringValue(v.String()))
		}
		state.Products = products
	} else {
		// If the user has explicitly configured products (state.Products is non-nil),
		// preserve the configured state value (e.g., empty slice []) when the API returns null.
		if state.Products == nil {
			state.Products = nil
		}
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCCKMAWSConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AWSConnectionModelTFSDK
	var state AWSConnectionModelTFSDK
	var payload AWSConnectionModelJSON
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_aws_connection.go -> Update][" + id + "]")

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Load prior state to detect a secret_access_key_version bump (see below).
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// secret_access_key is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Update() ever runs, so plan.SecretAccessKey is always
	// null here. req.Config is populated fresh from the HCL configuration on every RPC
	// (not derived from the nullified plan), so it reliably carries the actual value.
	var config AWSConnectionModelTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		payload.Description = plan.Description.ValueString()
	}
	if !plan.AccessKeyID.IsNull() && !plan.AccessKeyID.IsUnknown() {
		payload.AccessKeyID = plan.AccessKeyID.ValueString()
	}
	if !plan.AssumeRoleARN.IsNull() && !plan.AssumeRoleARN.IsUnknown() {
		payload.AssumeRoleARN = plan.AssumeRoleARN.ValueString()
	}
	if !plan.AssumeRoleExternalID.IsNull() && !plan.AssumeRoleExternalID.IsUnknown() {
		payload.AssumeRoleExternalID = plan.AssumeRoleExternalID.ValueString()
	}
	if !plan.AWSRegion.IsNull() && !plan.AWSRegion.IsUnknown() {
		payload.AWSRegion = plan.AWSRegion.ValueString()
	}
	// aws_sts_regional_endpoints: send explicit default when cleared so CM resets the field.
	// CM treats omission and empty string as no-op; the explicit default is the only reset mechanism.
	if !plan.AWSSTSRegionalEndpoints.IsNull() && !plan.AWSSTSRegionalEndpoints.IsUnknown() {
		payload.AWSSTSRegionalEndpoints = plan.AWSSTSRegionalEndpoints.ValueString()
	} else if plan.AWSSTSRegionalEndpoints.IsNull() {
		payload.AWSSTSRegionalEndpoints = awsDefaultSTSEndpoints
	}
	// cloud_name: same pattern — send explicit default when cleared.
	if !plan.CloudName.IsNull() && !plan.CloudName.IsUnknown() {
		payload.CloudName = plan.CloudName.ValueString()
	} else if plan.CloudName.IsNull() {
		payload.CloudName = awsDefaultCloudName
	}

	var varIAMRoleAnywhere IAMRoleAnywhereJSON
	if plan.IAMRoleAnywhere != nil && !reflect.DeepEqual(plan.IAMRoleAnywhere, state.IAMRoleAnywhere) {
		if plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != "" && plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.AnywhereRoleARN = plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString()
		}
		if plan.IAMRoleAnywhere.Certificate.ValueString() != "" && plan.IAMRoleAnywhere.Certificate.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.Certificate = plan.IAMRoleAnywhere.Certificate.ValueString()
		}
		if plan.IAMRoleAnywhere.ProfileARN.ValueString() != "" && plan.IAMRoleAnywhere.ProfileARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.ProfileARN = plan.IAMRoleAnywhere.ProfileARN.ValueString()
		}
		if plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != "" && plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.TrustAnchorARN = plan.IAMRoleAnywhere.TrustAnchorARN.ValueString()
		}
		if plan.IAMRoleAnywhere.PrivateKey.ValueString() != "" && plan.IAMRoleAnywhere.PrivateKey.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.PrivateKey = plan.IAMRoleAnywhere.PrivateKey.ValueString()
		}
		payload.IAMRoleAnywhere = &varIAMRoleAnywhere
	}

	// secret_access_key is write-only (never stored in state), so its own value can never be
	// diffed against a prior value — secret_access_key_version is the explicit, state-tracked
	// signal that the caller wants the current secret_access_key value re-sent to CM.
	if !plan.SecretAccessKeyVersion.Equal(state.SecretAccessKeyVersion) {
		payload.SecretAccessKey = config.SecretAccessKey.ValueString()
	}

	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	ApplyNullDeletes(labelsPayload, state.Labels.Elements())
	payload.Labels = labelsPayload

	// Add meta to payload
	metaPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metaPayload[k] = v.(types.String).ValueString()
	}
	ApplyNullDeletes(metaPayload, state.Meta.Elements())
	payload.Meta = metaPayload

	productsArr := []string{}
	for _, product := range plan.Products {
		productsArr = append(productsArr, product.ValueString())
	}
	payload.Products = productsArr

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Connection Update",
			err.Error(),
		)
		return
	}

	// Fix: use state.ID as the resource UUID (arg 1 → URL path); discard return value since we
	// do a GET read-back below to refresh all Computed fields correctly.
	_, err = r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_AWS_CONNECTION, payloadJSON, "id")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Error updating AWS Connection on CipherTrust Manager: ",
			"Could not update AWS Connection, unexpected error: "+err.Error(),
		)
		return
	}

	// GET read-back to refresh all Computed fields after PATCH
	readResponse, err := r.client.GetById(ctx, uuid.New().String(), plan.ID.ValueString(), common.URL_AWS_CONNECTION)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_aws_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading AWS Connection after update: ",
			"Could not read AWS Connection id: "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Refresh Computed fields from GET read-back
	plan.ID = types.StringValue(gjson.Get(readResponse, "id").String())
	plan.URI = types.StringValue(gjson.Get(readResponse, "uri").String())
	plan.Account = types.StringValue(gjson.Get(readResponse, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(readResponse, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(readResponse, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(readResponse, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(readResponse, "updatedAt").String())
	plan.Service = types.StringValue(gjson.Get(readResponse, "service").String())
	plan.Category = types.StringValue(gjson.Get(readResponse, "category").String())
	plan.ResourceURL = types.StringValue(gjson.Get(readResponse, "resource_url").String())
	// Computed-only status fields — hydrate unconditionally; gjson returns zero value when absent.
	// UseStateForUnknown() in schema ensures these remain stable in the plan.
	plan.LastConnectionOK = types.BoolValue(gjson.Get(readResponse, "last_connection_ok").Bool())
	plan.LastConnectionError = types.StringValue(gjson.Get(readResponse, "last_connection_error").String())
	plan.LastConnectionAt = types.StringValue(gjson.Get(readResponse, "last_connection_at").String())
	// aws_region: retain plan value — UseStateWhenClearingString() already handled clearing
	// at plan time; the post-PATCH value reflects the user's intent (either new region or
	// preserved old region). No CM read-back override needed.
	// cloud_name: when plan was null (user cleared), we sent the default to CM. Set plan to
	// null (matching config intent) rather than reading "aws" back from CM — avoids
	// "Provider produced inconsistent result" since plan was null but CM returns "aws".
	if plan.CloudName.IsNull() {
		// already null — keep it; the default was sent to CM successfully
	} else if r := gjson.Get(readResponse, "cloud_name"); r.Exists() && r.Type != gjson.Null {
		plan.CloudName = types.StringValue(r.String())
	}
	// aws_sts_regional_endpoints: same pattern as cloud_name.
	if plan.AWSSTSRegionalEndpoints.IsNull() {
		// already null — keep it; the default was sent to CM successfully
	} else if r := gjson.Get(readResponse, "aws_sts_regional_endpoints"); r.Exists() && r.Type != gjson.Null {
		plan.AWSSTSRegionalEndpoints = types.StringValue(r.String())
	}

	if plan.Description.IsUnknown() {
		if r := gjson.Get(readResponse, "description"); r.Exists() && r.Type != gjson.Null {
			plan.Description = types.StringValue(r.String())
		} else {
			plan.Description = types.StringNull()
		}
	}

	if plan.AssumeRoleARN.IsUnknown() {
		if r := gjson.Get(readResponse, "assume_role_arn"); r.Exists() && r.Type != gjson.Null {
			plan.AssumeRoleARN = types.StringValue(r.String())
		} else {
			plan.AssumeRoleARN = types.StringNull()
		}
	}

	if plan.AssumeRoleExternalID.IsUnknown() {
		if r := gjson.Get(readResponse, "assume_role_external_id"); r.Exists() && r.Type != gjson.Null {
			plan.AssumeRoleExternalID = types.StringValue(r.String())
		} else {
			plan.AssumeRoleExternalID = types.StringNull()
		}
	}

	// Optional fields retain plan values (user intent); Read() on next plan/refresh corrects API-side drift.

	// secret_access_key is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.SecretAccessKey = types.StringNull()

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_aws_connection.go -> Update][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCCKMAWSConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AWSConnectionModelTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_aws_connection.go -> Delete][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_aws_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// Resource already deleted out-of-band; treat as success.
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting AWS Connection",
			"Could not delete AWS Connection, unexpected error: "+err.Error(),
		)
		return
	}
}

// ApplyNullDeletes injects nil (JSON null) for keys present in prior state but absent from
// plan, so CM's merge-patch endpoint deletes them rather than leaving them unchanged.
func ApplyNullDeletes(payload map[string]interface{}, stateElements map[string]attr.Value) {
	for k := range stateElements {
		if _, exists := payload[k]; !exists {
			payload[k] = nil
		}
	}
}

func (d *resourceCCKMAWSConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	d.client = client
}
