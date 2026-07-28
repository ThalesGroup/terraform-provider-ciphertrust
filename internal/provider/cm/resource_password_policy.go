package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                   = &resourceCMPasswordPolicy{}
	_ resource.ResourceWithConfigure      = &resourceCMPasswordPolicy{}
	_ resource.ResourceWithValidateConfig = &resourceCMPasswordPolicy{}
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

func (r *resourceCMPasswordPolicy) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_password_policy", resp)
	if resp.Diagnostics.HasError() {
		return
	}

	var config CMPasswordPolicyTFSDK
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var digits, lower, upper, other, minLength int64

	if !config.InclusiveMinDigits.IsNull() && !config.InclusiveMinDigits.IsUnknown() {
		digits = config.InclusiveMinDigits.ValueInt64()
	}
	if !config.InclusiveMinLowerCase.IsNull() && !config.InclusiveMinLowerCase.IsUnknown() {
		lower = config.InclusiveMinLowerCase.ValueInt64()
	}
	if !config.InclusiveMinUpperCase.IsNull() && !config.InclusiveMinUpperCase.IsUnknown() {
		upper = config.InclusiveMinUpperCase.ValueInt64()
	}
	if !config.InclusiveMinOther.IsNull() && !config.InclusiveMinOther.IsUnknown() {
		other = config.InclusiveMinOther.ValueInt64()
	}
	if !config.InclusiveMinTotalLength.IsNull() && !config.InclusiveMinTotalLength.IsUnknown() {
		minLength = config.InclusiveMinTotalLength.ValueInt64()
	}

	sum := digits + lower + upper + other
	if minLength > 0 && sum > minLength {
		resp.Diagnostics.AddError(
			"Invalid password complexity configuration",
			fmt.Sprintf("The sum of inclusive complexity rules (%d) (digits: %d, lower-case: %d, upper-case: %d, other: %d) cannot exceed inclusive_min_total_length (%d).",
				sum, digits, lower, upper, other, minLength),
		)
	}
}

// Schema defines the schema for the resource.
func (r *resourceCMPasswordPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CipherTrust Manager user password policy (failed-login lockout thresholds, password complexity rules, password lifetime, and password history). **Only available on CipherTrust Manager — not supported on CDSPaaS, where password policy is managed by the platform.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"policy_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
				Description: "(Immutable) The name for the custom password policy. Changing this field in place is not supported — it would silently target a different policy on CipherTrust Manager.",
			},
			"failed_logins_lockout_thresholds": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "List of lockout durations in minutes for failed login attempts. For example, with input of [0, 5, 30], the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, the third and subsequent failed login attempts will lockout for 30 minutes. Set an empty array '[]' to disable the user account lockout.",
				ElementType: types.Int64Type,
			},
			"inclusive_max_total_length": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The maximum length of the password. Setting 0 is ignored by CipherTrust Manager once a non-zero value is set; the provider will preserve the active server value in state to prevent perpetual plan drift.",
			},
			"inclusive_min_digits": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The minimum number of digits.",
			},
			"inclusive_min_lower_case": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The minimum number of lower cases.",
			},
			"inclusive_min_other": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The minimum number of other characters.",
			},
			"inclusive_min_total_length": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					modifiers.UseStateWhenZeroInt64(),
				},
				Description: "The minimum length of the password. Setting 0 is ignored by CipherTrust Manager once a non-zero value is set; the provider will preserve the active server value in state to prevent perpetual plan drift.",
			},
			"inclusive_min_upper_case": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The minimum number of upper cases.",
			},
			"password_change_min_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The minimum period in days between password changes. Setting 0 is ignored by CipherTrust Manager once a non-zero value is set; the provider will preserve the active server value in state to prevent perpetual plan drift.",
			},
			"password_history_threshold": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Determines the number of past passwords a user cannot reuse. Even with value 0, the user will not be able to change their password to the same password.",
			},
			"password_lifetime": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The maximum lifetime of the password in days. Setting 0 is ignored by CipherTrust Manager once a non-zero value is set; the provider will preserve the active server value in state to prevent perpetual plan drift.",
			},
			"password_expiry_notification_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The number of days before password expiration to send a notification.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPasswordPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_password_policy.go -> Create][" + id + "]")

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

	if !plan.FailedLoginsLockoutThresholds.IsNull() && !plan.FailedLoginsLockoutThresholds.IsUnknown() {
		var thresholds []int64
		var listVals []types.Int64
		diags := plan.FailedLoginsLockoutThresholds.ElementsAs(ctx, &listVals, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, int := range listVals {
			thresholds = append(thresholds, int.ValueInt64())
		}
		payload.FailedLoginsLockoutThresholds = &thresholds
	}

	if !plan.InclusiveMaxTotalLength.IsNull() && !plan.InclusiveMaxTotalLength.IsUnknown() {
		v := plan.InclusiveMaxTotalLength.ValueInt64()
		payload.InclusiveMaxTotalLength = &v
	}
	if !plan.InclusiveMinDigits.IsNull() && !plan.InclusiveMinDigits.IsUnknown() {
		v := plan.InclusiveMinDigits.ValueInt64()
		payload.InclusiveMinDigits = &v
	}
	if !plan.InclusiveMinLowerCase.IsNull() && !plan.InclusiveMinLowerCase.IsUnknown() {
		v := plan.InclusiveMinLowerCase.ValueInt64()
		payload.InclusiveMinLowerCase = &v
	}
	if !plan.InclusiveMinOther.IsNull() && !plan.InclusiveMinOther.IsUnknown() {
		v := plan.InclusiveMinOther.ValueInt64()
		payload.InclusiveMinOther = &v
	}
	if !plan.InclusiveMinTotalLength.IsNull() && !plan.InclusiveMinTotalLength.IsUnknown() {
		v := plan.InclusiveMinTotalLength.ValueInt64()
		payload.InclusiveMinTotalLength = &v
	}
	if !plan.InclusiveMinUpperCase.IsNull() && !plan.InclusiveMinUpperCase.IsUnknown() {
		v := plan.InclusiveMinUpperCase.ValueInt64()
		payload.InclusiveMinUpperCase = &v
	}
	if !plan.PasswordChangeMinDays.IsNull() && !plan.PasswordChangeMinDays.IsUnknown() {
		v := plan.PasswordChangeMinDays.ValueInt64()
		payload.PasswordChangeMinDays = &v
	}
	if !plan.PasswordHistoryThreshold.IsNull() && !plan.PasswordHistoryThreshold.IsUnknown() {
		v := plan.PasswordHistoryThreshold.ValueInt64()
		payload.PasswordHistoryThreshold = &v
	}
	if !plan.PasswordLifetime.IsNull() && !plan.PasswordLifetime.IsUnknown() {
		v := plan.PasswordLifetime.ValueInt64()
		payload.PasswordLifetime = &v
	}
	if !plan.PasswordExpiryNotificationDays.IsNull() && !plan.PasswordExpiryNotificationDays.IsUnknown() {
		v := plan.PasswordExpiryNotificationDays.ValueInt64()
		payload.PasswordExpiryNotificationDays = &v
	}

	if passwordPolicyName != "global" {
		_, errRead := r.client.ReadDataByParam(ctx, id, passwordPolicyName, common.URL_CM_PASSWORD_POLICY)
		if errRead == nil {
			resp.Diagnostics.AddError(
				"Resource Already Exists",
				fmt.Sprintf("A password policy named '%s' already exists on CipherTrust Manager. Please choose a different name or import the existing resource.", passwordPolicyName),
			)
			return
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_password_policy.go -> Create][" + id + "]")
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
	r.client.Log.Debug("[resource_password_policy.go -> Create][Payload and URL]" +
		common.URL_CM_PASSWORD_POLICY + "/" + passwordPolicyName +
		string(payloadJSON))
	if errUPD != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + errUPD.Error() + " [resource_password_policy.go -> Create][" + id + "]")
		if strings.Contains(errUPD.Error(), "404") {
			var payloadMarshal CMPasswordPolicyJSON
			errUnmarshal := json.Unmarshal(payloadJSON, &payloadMarshal)
			if errUnmarshal != nil {
				r.client.Log.Debug(common.ERR_METHOD_END + errUnmarshal.Error() + " [resource_password_policy.go -> Create][" + id + "]")
				resp.Diagnostics.AddError(
					"Unable to unmarshal payload JSON",
					errUnmarshal.Error(),
				)
				return
			}
			payloadMarshal.Name = passwordPolicyName

			payloadMarshalJSON, errMarshal := json.Marshal(payloadMarshal)
			if errMarshal != nil {
				r.client.Log.Debug(common.ERR_METHOD_END + errMarshal.Error() + " [resource_password_policy.go -> Create][" + id + "]")
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
				r.client.Log.Debug(common.ERR_METHOD_END + errCreate.Error() + " [resource_password_policy.go -> Create][" + id + "]")
				resp.Diagnostics.AddError(
					"Error creating User's password policy on CipherTrust Manager: ",
					"Could not create User's password policy, unexpected error: "+errCreate.Error(),
				)
				return
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

	r.client.Log.Debug("[resource_password_policy.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_password_policy.go -> Create][" + id + "]")

	plan.ID = types.StringValue(passwordPolicyName)
	plan.Name = types.StringValue(passwordPolicyName)

	if !plan.InclusiveMaxTotalLength.IsNull() {
		if r := gjson.Get(response, "inclusive_max_total_length"); r.Exists() {
			plan.InclusiveMaxTotalLength = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMaxTotalLength = types.Int64Null()
		}
	}
	if !plan.InclusiveMinDigits.IsNull() {
		if r := gjson.Get(response, "inclusive_min_digits"); r.Exists() {
			plan.InclusiveMinDigits = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMinDigits = types.Int64Null()
		}
	}
	if !plan.InclusiveMinLowerCase.IsNull() {
		if r := gjson.Get(response, "inclusive_min_lower_case"); r.Exists() {
			plan.InclusiveMinLowerCase = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMinLowerCase = types.Int64Null()
		}
	}
	if !plan.InclusiveMinOther.IsNull() {
		if r := gjson.Get(response, "inclusive_min_other"); r.Exists() {
			plan.InclusiveMinOther = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMinOther = types.Int64Null()
		}
	}
	if !plan.InclusiveMinTotalLength.IsNull() {
		if r := gjson.Get(response, "inclusive_min_total_length"); r.Exists() {
			plan.InclusiveMinTotalLength = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMinTotalLength = types.Int64Null()
		}
	}
	if !plan.InclusiveMinUpperCase.IsNull() {
		if r := gjson.Get(response, "inclusive_min_upper_case"); r.Exists() {
			plan.InclusiveMinUpperCase = types.Int64Value(r.Int())
		} else {
			plan.InclusiveMinUpperCase = types.Int64Null()
		}
	}
	if !plan.PasswordChangeMinDays.IsNull() {
		if r := gjson.Get(response, "password_change_min_days"); r.Exists() {
			plan.PasswordChangeMinDays = types.Int64Value(r.Int())
		} else {
			plan.PasswordChangeMinDays = types.Int64Null()
		}
	}
	if !plan.PasswordHistoryThreshold.IsNull() {
		if r := gjson.Get(response, "password_history_threshold"); r.Exists() {
			plan.PasswordHistoryThreshold = types.Int64Value(r.Int())
		} else {
			plan.PasswordHistoryThreshold = types.Int64Null()
		}
	}
	if !plan.PasswordLifetime.IsNull() {
		if r := gjson.Get(response, "password_lifetime"); r.Exists() {
			plan.PasswordLifetime = types.Int64Value(r.Int())
		} else {
			plan.PasswordLifetime = types.Int64Null()
		}
	}
	if !plan.PasswordExpiryNotificationDays.IsNull() {
		if r := gjson.Get(response, "password_expiry_notification_days"); r.Exists() {
			plan.PasswordExpiryNotificationDays = types.Int64Value(r.Int())
		} else {
			plan.PasswordExpiryNotificationDays = types.Int64Null()
		}
	}

	result := gjson.Get(response, "failed_logins_lockout_thresholds")
	if !result.Exists() {
		plan.FailedLoginsLockoutThresholds = types.ListNull(types.Int64Type)
	} else {
		thresholds := []attr.Value{}
		result.ForEach(func(_, v gjson.Result) bool {
			thresholds = append(thresholds, types.Int64Value(v.Int()))
			return true
		})
		listValue, listDiags := types.ListValue(types.Int64Type, thresholds)
		resp.Diagnostics.Append(listDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.FailedLoginsLockoutThresholds = listValue
	}

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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_password_policy.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_password_policy.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_CM_PASSWORD_POLICY)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"Password Policy Not Found — State Preserved",
				"The Password Policy resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_password_policy.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading User's password policy from CipherTrust Manager: ",
			"Could not read User's password policy: unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "policy_name").String())

	if r := gjson.Get(response, "inclusive_max_total_length"); r.Exists() {
		state.InclusiveMaxTotalLength = types.Int64Value(r.Int())
	} else {
		state.InclusiveMaxTotalLength = types.Int64Null()
	}
	if r := gjson.Get(response, "inclusive_min_digits"); r.Exists() {
		state.InclusiveMinDigits = types.Int64Value(r.Int())
	} else {
		state.InclusiveMinDigits = types.Int64Null()
	}
	if r := gjson.Get(response, "inclusive_min_lower_case"); r.Exists() {
		state.InclusiveMinLowerCase = types.Int64Value(r.Int())
	} else {
		state.InclusiveMinLowerCase = types.Int64Null()
	}
	if r := gjson.Get(response, "inclusive_min_other"); r.Exists() {
		state.InclusiveMinOther = types.Int64Value(r.Int())
	} else {
		state.InclusiveMinOther = types.Int64Null()
	}
	if r := gjson.Get(response, "inclusive_min_total_length"); r.Exists() {
		state.InclusiveMinTotalLength = types.Int64Value(r.Int())
	} else {
		state.InclusiveMinTotalLength = types.Int64Null()
	}
	if r := gjson.Get(response, "inclusive_min_upper_case"); r.Exists() {
		state.InclusiveMinUpperCase = types.Int64Value(r.Int())
	} else {
		state.InclusiveMinUpperCase = types.Int64Null()
	}
	if r := gjson.Get(response, "password_change_min_days"); r.Exists() {
		state.PasswordChangeMinDays = types.Int64Value(r.Int())
	} else {
		state.PasswordChangeMinDays = types.Int64Null()
	}
	if r := gjson.Get(response, "password_history_threshold"); r.Exists() {
		state.PasswordHistoryThreshold = types.Int64Value(r.Int())
	} else {
		state.PasswordHistoryThreshold = types.Int64Null()
	}
	if r := gjson.Get(response, "password_lifetime"); r.Exists() {
		state.PasswordLifetime = types.Int64Value(r.Int())
	} else {
		state.PasswordLifetime = types.Int64Null()
	}
	if r := gjson.Get(response, "password_expiry_notification_days"); r.Exists() {
		state.PasswordExpiryNotificationDays = types.Int64Value(r.Int())
	} else {
		state.PasswordExpiryNotificationDays = types.Int64Null()
	}

	result := gjson.Get(response, "failed_logins_lockout_thresholds")
	if !result.Exists() {
		state.FailedLoginsLockoutThresholds = types.ListNull(types.Int64Type)
	} else {
		thresholds := []attr.Value{}
		result.ForEach(func(_, v gjson.Result) bool {
			thresholds = append(thresholds, types.Int64Value(v.Int()))
			return true
		})
		listValue, listDiags := types.ListValue(types.Int64Type, thresholds)
		resp.Diagnostics.Append(listDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.FailedLoginsLockoutThresholds = listValue
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPasswordPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_password_policy.go -> Update][" + id + "]")

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

	if !plan.FailedLoginsLockoutThresholds.IsNull() && !plan.FailedLoginsLockoutThresholds.IsUnknown() {
		var listVals []types.Int64
		diags := plan.FailedLoginsLockoutThresholds.ElementsAs(ctx, &listVals, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		// make ensures a non-nil slice even when listVals is empty.
		// A nil slice via append(&nil) marshals as null; a non-nil empty slice marshals as [],
		// which CM interprets as "clear the lockout list".
		thresholds := make([]int64, 0, len(listVals))
		for _, v := range listVals {
			thresholds = append(thresholds, v.ValueInt64())
		}
		payload.FailedLoginsLockoutThresholds = &thresholds
	}

	if !plan.InclusiveMaxTotalLength.IsNull() && !plan.InclusiveMaxTotalLength.IsUnknown() {
		v := plan.InclusiveMaxTotalLength.ValueInt64()
		payload.InclusiveMaxTotalLength = &v
	}
	if !plan.InclusiveMinDigits.IsNull() && !plan.InclusiveMinDigits.IsUnknown() {
		v := plan.InclusiveMinDigits.ValueInt64()
		payload.InclusiveMinDigits = &v
	}
	if !plan.InclusiveMinLowerCase.IsNull() && !plan.InclusiveMinLowerCase.IsUnknown() {
		v := plan.InclusiveMinLowerCase.ValueInt64()
		payload.InclusiveMinLowerCase = &v
	}
	if !plan.InclusiveMinOther.IsNull() && !plan.InclusiveMinOther.IsUnknown() {
		v := plan.InclusiveMinOther.ValueInt64()
		payload.InclusiveMinOther = &v
	}
	if !plan.InclusiveMinTotalLength.IsNull() && !plan.InclusiveMinTotalLength.IsUnknown() {
		v := plan.InclusiveMinTotalLength.ValueInt64()
		payload.InclusiveMinTotalLength = &v
	}
	if !plan.InclusiveMinUpperCase.IsNull() && !plan.InclusiveMinUpperCase.IsUnknown() {
		v := plan.InclusiveMinUpperCase.ValueInt64()
		payload.InclusiveMinUpperCase = &v
	}
	if !plan.PasswordChangeMinDays.IsNull() && !plan.PasswordChangeMinDays.IsUnknown() {
		v := plan.PasswordChangeMinDays.ValueInt64()
		payload.PasswordChangeMinDays = &v
	}
	if !plan.PasswordHistoryThreshold.IsNull() && !plan.PasswordHistoryThreshold.IsUnknown() {
		v := plan.PasswordHistoryThreshold.ValueInt64()
		payload.PasswordHistoryThreshold = &v
	}
	if !plan.PasswordLifetime.IsNull() && !plan.PasswordLifetime.IsUnknown() {
		v := plan.PasswordLifetime.ValueInt64()
		payload.PasswordLifetime = &v
	}
	if !plan.PasswordExpiryNotificationDays.IsNull() && !plan.PasswordExpiryNotificationDays.IsUnknown() {
		v := plan.PasswordExpiryNotificationDays.ValueInt64()
		payload.PasswordExpiryNotificationDays = &v
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_password_policy.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Password Policy Update",
			err.Error(),
		)
		return
	}

	responseUPD, errUPD := r.client.UpdateDataV2(
		ctx,
		passwordPolicyName,
		common.URL_CM_PASSWORD_POLICY,
		payloadJSON)
	r.client.Log.Debug("[resource_password_policy.go -> Update][Payload and URL]" +
		common.URL_CM_PASSWORD_POLICY + "/" + passwordPolicyName +
		string(payloadJSON))
	if errUPD != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + errUPD.Error() + " [resource_password_policy.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Error patching User's password policy on CipherTrust Manager: ",
			"Could not patch User's password policy, unexpected error: "+errUPD.Error(),
		)
		return
	}

	r.client.Log.Debug("[resource_password_policy.go -> Update Output][" + responseUPD + "]")

	plan.ID = types.StringValue(passwordPolicyName)
	plan.Name = types.StringValue(passwordPolicyName)

	if r := gjson.Get(responseUPD, "inclusive_max_total_length"); r.Exists() {
		plan.InclusiveMaxTotalLength = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMaxTotalLength = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "inclusive_min_digits"); r.Exists() {
		plan.InclusiveMinDigits = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMinDigits = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "inclusive_min_lower_case"); r.Exists() {
		plan.InclusiveMinLowerCase = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMinLowerCase = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "inclusive_min_other"); r.Exists() {
		plan.InclusiveMinOther = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMinOther = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "inclusive_min_total_length"); r.Exists() {
		plan.InclusiveMinTotalLength = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMinTotalLength = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "inclusive_min_upper_case"); r.Exists() {
		plan.InclusiveMinUpperCase = types.Int64Value(r.Int())
	} else {
		plan.InclusiveMinUpperCase = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "password_change_min_days"); r.Exists() {
		plan.PasswordChangeMinDays = types.Int64Value(r.Int())
	} else {
		plan.PasswordChangeMinDays = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "password_history_threshold"); r.Exists() {
		plan.PasswordHistoryThreshold = types.Int64Value(r.Int())
	} else {
		plan.PasswordHistoryThreshold = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "password_lifetime"); r.Exists() {
		plan.PasswordLifetime = types.Int64Value(r.Int())
	} else {
		plan.PasswordLifetime = types.Int64Null()
	}
	if r := gjson.Get(responseUPD, "password_expiry_notification_days"); r.Exists() {
		plan.PasswordExpiryNotificationDays = types.Int64Value(r.Int())
	} else {
		plan.PasswordExpiryNotificationDays = types.Int64Null()
	}

	thresholdsResult := gjson.Get(responseUPD, "failed_logins_lockout_thresholds")
	if !thresholdsResult.Exists() {
		plan.FailedLoginsLockoutThresholds = types.ListNull(types.Int64Type)
	} else {
		thresholds := []attr.Value{}
		thresholdsResult.ForEach(func(_, v gjson.Result) bool {
			thresholds = append(thresholds, types.Int64Value(v.Int()))
			return true
		})
		listValue, listDiags := types.ListValue(types.Int64Type, thresholds)
		resp.Diagnostics.Append(listDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.FailedLoginsLockoutThresholds = listValue
	}
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_password_policy.go -> Update][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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
	if state.Name.ValueString() != "global" {
		url := fmt.Sprintf("%s/%s", r.client.CipherTrustURL, common.URL_CM_PASSWORD_POLICY+"/"+state.Name.ValueString())
		output, err := r.client.DeleteByID(ctx, "DELETE", id, url, nil)
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_password_policy.go -> Delete][" + id + "][" + output + "]")
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				return
			}
			resp.Diagnostics.AddError(
				"Error Deleting User's password policy",
				"Could not delete User's password policy, unexpected error: "+err.Error(),
			)
			return
		}
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
