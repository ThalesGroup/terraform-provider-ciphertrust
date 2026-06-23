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
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const notFoundError = "status: 404"

var (
	_ resource.Resource              = &resourceCCKMAWSConnection{}
	_ resource.ResourceWithConfigure = &resourceCCKMAWSConnection{}
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
				Description: "Key ID of the AWS user",
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Description: "AWS IAM role ARN",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "Specify AWS Role external ID",
			},
			"aws_region": schema.StringAttribute{
				Optional: true,
				Description: "AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given." +
					"Default values are: \n" +
					"for aws, default region will be \"us-east-1\" \n" +
					"for aws-us-gov, default region will be \"us-gov-east-1\" \n" +
					"for aws-cn, default region will be \"cn-north-1\"",
			},
			"aws_sts_regional_endpoints": schema.StringAttribute{
				Optional: true,
				Description: "By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are: \n" +
					"legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com \n" +
					"regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region. \n",
			},
			"cloud_name": schema.StringAttribute{
				Optional: true,
				Description: "Name of the cloud. Options are: \n" +
					"aws (default) \n" +
					"aws-us-gov \n" +
					"aws-cn",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description about the connection",
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
				Description: "Set the parameter to true to create connections of type AWS IAM Anywhere with temporary credentials.",
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
				Description: "Array of the CipherTrust products associated with the connection",
			},
			"secret_access_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Secret associated with the access key ID of the AWS user",
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

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCCKMAWSConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan AWSConnectionModelTFSDK
	var payload AWSConnectionModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.Name = common.TrimString(plan.Name.String())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.AccessKeyID.ValueString() != "" && plan.AccessKeyID.ValueString() != types.StringNull().ValueString() {
		payload.AccessKeyID = common.TrimString(plan.AccessKeyID.String())
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}
	if plan.AWSRegion.ValueString() != "" && plan.AWSRegion.ValueString() != types.StringNull().ValueString() {
		payload.AWSRegion = common.TrimString(plan.AWSRegion.String())
	}
	if plan.AWSSTSRegionalEndpoints.ValueString() != "" && plan.AWSSTSRegionalEndpoints.ValueString() != types.StringNull().ValueString() {
		payload.AWSSTSRegionalEndpoints = common.TrimString(plan.AWSSTSRegionalEndpoints.String())
	}
	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = common.TrimString(plan.CloudName.String())
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

	if plan.SecretAccessKey.ValueString() != "" && plan.SecretAccessKey.ValueString() != types.StringNull().ValueString() {
		payload.SecretAccessKey = common.TrimString(plan.SecretAccessKey.String())
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

	// Backwards compatability
	if payload.SecretAccessKey == "" {
		payload.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if payload.AccessKeyID == "" {
		payload.AccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Create]["+id+"]")
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

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_connection.go -> Create]["+id+"]")
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_connection.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_connection.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// Intentional: a 404 on an AWS connection reliably indicates out-of-band deletion.
			// Terraform should plan re-creation.
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Read]["+id+"]")
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
	// Use r.Exists() to surface drift when the value changes vs config.
	if r := gjson.Get(response, "description"); r.Exists() {
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
	if r := gjson.Get(response, "assume_role_arn"); r.Exists() {
		state.AssumeRoleARN = types.StringValue(r.String())
	} else {
		state.AssumeRoleARN = types.StringNull()
	}
	if r := gjson.Get(response, "assume_role_external_id"); r.Exists() {
		state.AssumeRoleExternalID = types.StringValue(r.String())
	} else {
		state.AssumeRoleExternalID = types.StringNull()
	}

	// aws_region, aws_sts_regional_endpoints, cloud_name: CM returns server defaults
	// (e.g. cloud_name="aws", aws_sts_regional_endpoints="legacy", aws_region="us-east-1")
	// even when the user did not configure them. Guard with IsNull to prevent perpetual
	// drift for users who never set these fields (same pattern as is_role_anywhere).
	if !state.AWSRegion.IsNull() {
		if r := gjson.Get(response, "aws_region"); r.Exists() {
			state.AWSRegion = types.StringValue(r.String())
		} else {
			state.AWSRegion = types.StringNull()
		}
	}
	if !state.AWSSTSRegionalEndpoints.IsNull() {
		if r := gjson.Get(response, "aws_sts_regional_endpoints"); r.Exists() {
			state.AWSSTSRegionalEndpoints = types.StringValue(r.String())
		} else {
			state.AWSSTSRegionalEndpoints = types.StringNull()
		}
	}
	if !state.CloudName.IsNull() {
		if r := gjson.Get(response, "cloud_name"); r.Exists() {
			state.CloudName = types.StringValue(r.String())
		} else {
			state.CloudName = types.StringNull()
		}
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

	// secret_access_key: write-only — CM never returns it in GET responses.
	// state.SecretAccessKey retains the value loaded by req.State.Get above; no API hydration needed.

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
		state.Products = nil
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_connection.go -> Update]["+id+"]")

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Load prior state to preserve write-only fields absent from CM GET responses.
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.AccessKeyID.ValueString() != "" && plan.AccessKeyID.ValueString() != types.StringNull().ValueString() {
		payload.AccessKeyID = common.TrimString(plan.AccessKeyID.String())
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}
	if plan.AWSRegion.ValueString() != "" && plan.AWSRegion.ValueString() != types.StringNull().ValueString() {
		payload.AWSRegion = common.TrimString(plan.AWSRegion.String())
	}
	if plan.AWSSTSRegionalEndpoints.ValueString() != "" && plan.AWSSTSRegionalEndpoints.ValueString() != types.StringNull().ValueString() {
		payload.AWSSTSRegionalEndpoints = common.TrimString(plan.AWSSTSRegionalEndpoints.String())
	}
	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = common.TrimString(plan.CloudName.String())
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

	if plan.SecretAccessKey.ValueString() != "" && plan.SecretAccessKey.ValueString() != types.StringNull().ValueString() {
		payload.SecretAccessKey = common.TrimString(plan.SecretAccessKey.String())
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

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Connection Update",
			err.Error(),
		)
		return
	}

	// Fix: use plan.ID as the resource UUID (arg 1 → URL path); discard return value since we
	// do a GET read-back below to refresh all Computed fields correctly.
	_, err = r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_AWS_CONNECTION, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating AWS Connection on CipherTrust Manager: ",
			"Could not update AWS Connection, unexpected error: "+err.Error(),
		)
		return
	}

	// GET read-back to refresh all Computed fields after PATCH
	readResponse, err := r.client.GetById(ctx, uuid.New().String(), plan.ID.ValueString(), common.URL_AWS_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Update]["+id+"]")
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
	// Computed-only status fields — hydrate unconditionally; gjson returns zero value when absent
	plan.LastConnectionOK = types.BoolValue(gjson.Get(readResponse, "last_connection_ok").Bool())
	plan.LastConnectionError = types.StringValue(gjson.Get(readResponse, "last_connection_error").String())
	plan.LastConnectionAt = types.StringValue(gjson.Get(readResponse, "last_connection_at").String())
	// Optional fields retain plan values (user intent); Read() on next plan/refresh corrects API-side drift.

	// Preserve write-only field: secret_access_key is never returned by CM GET responses.
	// When not present in the HCL config, plan.SecretAccessKey is null; restore from prior
	// state so the key is not silently lost after an update that doesn't re-supply the secret.
	if plan.SecretAccessKey.IsNull() || plan.SecretAccessKey.ValueString() == "" {
		plan.SecretAccessKey = state.SecretAccessKey
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_connection.go -> Update]["+id+"]")
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_connection.go -> Delete]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
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
