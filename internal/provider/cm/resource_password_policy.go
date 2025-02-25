package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMPasswordPolicy{}
	_ resource.ResourceWithConfigure = &resourceCMPasswordPolicy{}
)

func NewResourceCMPasswordPolicy() resource.Resource {
	return &resourceCMPasswordPolicy{}
}

type resourceCMPasswordPolicy struct {
	client *common.Client
}

func (r *resourceCMPasswordPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password_policy"
}

// Schema defines the schema for the resource.
func (r *resourceCMPasswordPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_name": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: " The name for the custom password policy.",
			},
			"failed_logins_lockout_thresholds": schema.ListAttribute{
				Optional:    true,
				Description: "List of lockout durations in minutes for failed login attempts. For example, with input of [0, 5, 30], the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, the third and subsequent failed login attempts will lockout for 30 minutes. Set an empty array '[]' to disable the user account lockout.List of lockout durations in minutes for failed login attempts. For example, with input of [0, 5, 30], the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, the third and subsequent failed login attempts will lockout for 30 minutes. Set an empty array '[]' to disable the user account lockout.",
				ElementType: types.Int64Type,
			},
			"inclusive_max_total_length": schema.Int64Attribute{
				Optional:    true,
				Description: "The maximum length of the password. Value 0 is ignored.",
			},
			"inclusive_min_digits": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum number of digits.",
			},
			"inclusive_min_lower_case": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum number of lower cases.",
			},
			"inclusive_min_other": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum number of other characters.",
			},
			"inclusive_min_total_length": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum length of the password. Value 0 is ignored.",
			},
			"inclusive_min_upper_case": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum number of upper cases.",
			},
			"password_change_min_days": schema.Int64Attribute{
				Optional:    true,
				Description: "The minimum period in days between password changes. Value 0 is ignored.",
			},
			"password_history_threshold": schema.Int64Attribute{
				Optional:    true,
				Description: "Determines the number of past passwords a user cannot reuse. Even with value 0, the user will not be able to change their password to the same password.",
			},
			"password_lifetime": schema.Int64Attribute{
				Optional:    true,
				Description: "The maximum lifetime of the password in days. Value 0 is ignored.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPasswordPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_password_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMPasswordPolicyTFSDK
	var payload CMPasswordPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var passwordPolicyName string
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		passwordPolicyName = plan.Name.ValueString()
	} else {
		passwordPolicyName = "global"
	}

	var thresholds []int64
	for _, int := range plan.FailedLoginsLockoutThresholds {
		thresholds = append(thresholds, int.ValueInt64())
	}
	payload.FailedLoginsLockoutThresholds = thresholds

	if plan.InclusiveMaxTotalLength.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMaxTotalLength = plan.InclusiveMaxTotalLength.ValueInt64()
	}
	if plan.InclusiveMinDigits.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMinDigits = plan.InclusiveMinDigits.ValueInt64()
	}
	if plan.InclusiveMinLowerCase.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMinLowerCase = plan.InclusiveMinLowerCase.ValueInt64()
	}
	if plan.InclusiveMinOther.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMinOther = plan.InclusiveMinOther.ValueInt64()
	}
	if plan.InclusiveMinTotalLength.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMinTotalLength = plan.InclusiveMinTotalLength.ValueInt64()
	}
	if plan.InclusiveMinUpperCase.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.InclusiveMinUpperCase = plan.InclusiveMinUpperCase.ValueInt64()
	}
	if plan.PasswordChangeMinDays.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.PasswordChangeMinDays = plan.PasswordChangeMinDays.ValueInt64()
	}
	if plan.PasswordHistoryThreshold.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.PasswordHistoryThreshold = plan.PasswordHistoryThreshold.ValueInt64()
	}
	if plan.PasswordLifetime.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.PasswordLifetime = plan.PasswordLifetime.ValueInt64()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_password_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Password Policy Update",
			err.Error(),
		)
		return
	}

	var response string
	responseUPD, errUPD := r.client.UpdateDataV2(
		ctx,
		passwordPolicyName,
		common.URL_CM_PASSWORD_POLICY,
		payloadJSON)
	tflog.Debug(ctx, "[resource_password_policy.go -> Create][Payload and URL]"+
		common.URL_CM_PASSWORD_POLICY+"/"+passwordPolicyName+
		string(payloadJSON))
	if errUPD != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+errUPD.Error()+" [resource_password_policy.go -> Create]["+id+"]")
		if strings.Contains(errUPD.Error(), "404") {
			var payloadMarshal CMPasswordPolicyJSON
			errUnmarshal := json.Unmarshal(payloadJSON, &payloadMarshal)
			if errUnmarshal != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+errUnmarshal.Error()+" [resource_password_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Unable to unmarshal payload JSON",
					errUnmarshal.Error(),
				)
				return
			}
			payloadMarshal.Name = passwordPolicyName

			payloadMarshalJSON, errMarshal := json.Marshal(payloadMarshal)
			if errMarshal != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+errMarshal.Error()+" [resource_password_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: Password Policy Update",
					errMarshal.Error(),
				)
				return
			}

			responseCreate, errCreate := r.client.PostDataV2(
				ctx,
				id,
				common.URL_CM_PASSWORD_POLICY,
				payloadMarshalJSON)
			if errCreate != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+errCreate.Error()+" [resource_password_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Error creating User's password policy on CipherTrust Manager: ",
					"Could not create User's password policy, unexpected error: "+errCreate.Error(),
				)
			} else {
				response = responseCreate
			}
		} else {
			resp.Diagnostics.AddError(
				"Error patching User's password policy on CipherTrust Manager: ",
				"Could not patch User's password policy, unexpected error: "+errUPD.Error(),
			)
			return
		}
	} else {
		response = responseUPD
	}

	tflog.Debug(ctx, "[resource_password_policy.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_password_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMPasswordPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMPasswordPolicyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_CM_PASSWORD_POLICY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_password_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading User's password policy from CipherTrust Manager: ",
			"Could not read User's password policy: unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "policy_name").String())
	state.InclusiveMaxTotalLength = types.Int64Value(gjson.Get(response, "inclusive_max_total_length").Int())
	state.InclusiveMinDigits = types.Int64Value(gjson.Get(response, "inclusive_min_digits").Int())
	state.InclusiveMinLowerCase = types.Int64Value(gjson.Get(response, "inclusive_min_lower_case").Int())
	state.InclusiveMinOther = types.Int64Value(gjson.Get(response, "inclusive_min_other").Int())
	state.InclusiveMinTotalLength = types.Int64Value(gjson.Get(response, "inclusive_min_total_length").Int())
	state.InclusiveMinUpperCase = types.Int64Value(gjson.Get(response, "inclusive_min_upper_case").Int())
	state.PasswordChangeMinDays = types.Int64Value(gjson.Get(response, "password_change_min_days").Int())
	state.PasswordHistoryThreshold = types.Int64Value(gjson.Get(response, "password_history_threshold").Int())
	state.PasswordLifetime = types.Int64Value(gjson.Get(response, "password_lifetime").Int())

	thresholdsData := gjson.Get(response, "failed_logins_lockout_thresholds").Array()
	var thresholds []types.Int64
	for _, threshold := range thresholdsData {
		thresholds = append(thresholds, types.Int64Value(threshold.Int()))
	}
	state.FailedLoginsLockoutThresholds = thresholds

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_password_policy.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPasswordPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Unsupported Operation")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPasswordPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	var state CMPasswordPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s", r.client.CipherTrustURL, common.URL_CM_PASSWORD_POLICY+"/"+state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", id, url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_password_policy.go -> Delete]["+id+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting User's password policy",
			"Could not delete User's password policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMPasswordPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
