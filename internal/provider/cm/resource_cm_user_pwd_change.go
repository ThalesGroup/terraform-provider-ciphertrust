package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &resourceCMPwdChange{}
	_ resource.ResourceWithConfigure = &resourceCMPwdChange{}
)

func NewResourceCMPwdChange() resource.Resource {
	return &resourceCMPwdChange{}
}

type resourceCMPwdChange struct {
	client common.CMClient
}

func (r *resourceCMPwdChange) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_user_password_change"
}

// Schema defines the schema for the resource.
func (r *resourceCMPwdChange) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Changes the password of a CipherTrust Manager (or CDSPaaS) local user. This is a write-only, one-shot action modeled as a resource: applying it changes the password immediately, `terraform destroy` does not revert it, and updates are not supported — to change the password again, delete and recreate this resource with new values. Credential fields are never read back from CipherTrust Manager and are preserved from prior state across `terraform plan`/`refresh`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"username": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Username of the CipherTrust Manager user whose password is being changed.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"password": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true, // never written to state (requires Terraform ≥ 1.11) — matches ciphertrust_user.password
				Description: "(Immutable) Current password for the user.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"new_password": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true, // never written to state (requires Terraform ≥ 1.11) — matches ciphertrust_user.password
				Description: "(Immutable) New password to set for the user.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"auth_domain": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) Authentication domain of the user whose password is being changed.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"password_hint": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) Optional hint for the new password.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPwdChange) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.GetLog().Trace(common.MSG_METHOD_START + "[resource_cm_user_pwd_change.go -> Create][" + id + "]")

	var plan CMPwdChangeTFSDK
	var payload CMPwdChangeJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password and new_password are WriteOnly: the framework nulls them from PlannedState
	// before Create() runs, so plan.Password/plan.NewPassword are always null here.
	// req.Config is populated fresh from the HCL config and always carries the actual values.
	var config CMPwdChangeTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Username = plan.Username.ValueString()
	payload.Password = config.Password.ValueString()
	payload.NewPassword = config.NewPassword.ValueString()
	if !plan.AuthDomain.IsNull() && !plan.AuthDomain.IsUnknown() {
		payload.AuthDomain = plan.AuthDomain.ValueString()
	}
	if !plan.PasswordHint.IsNull() && !plan.PasswordHint.IsUnknown() {
		payload.PasswordHint = plan.PasswordHint.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.GetLog().Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_user_pwd_change.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Change user password",
			err.Error(),
		)
		return
	}

	_, err = r.client.PatchDataBootstrap(ctx, id, common.URL_CHANGE_USER_PWD, payloadJSON)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "authentication failed") || strings.Contains(errStr, "invalid credentials") || strings.Contains(errStr, "401") {
			r.client.GetLog().Debug("[resource_cm_user_pwd_change.go -> Create] Password change failed with auth error, verifying if password has already been changed")
			if c, ok := r.client.(*common.Client); ok {
				// Shallow copy the client and update password with planned new_password
				verifyClient := *c
				verifyClient.AuthData.Password = plan.NewPassword.ValueString()

				// Attempt login verification with new credentials
				_, verifyErr := verifyClient.SignIn(ctx, id)
				if verifyErr == nil {
					r.client.GetLog().Debug("[resource_cm_user_pwd_change.go -> Create] Verification login with new password succeeded! Reconstructing state.")

					// Query existing users list to fetch the target user_id
					usersJSON, listErr := verifyClient.GetByIdBootstrap(ctx, id, "", common.URL_USER_MANAGEMENT)
					if listErr == nil {
						var userRecords []gjson.Result
						if gjson.Get(usersJSON, "resources").Exists() {
							userRecords = gjson.Get(usersJSON, "resources").Array()
						} else {
							parsed := gjson.Parse(usersJSON)
							if parsed.IsArray() {
								userRecords = parsed.Array()
							} else {
								userRecords = []gjson.Result{parsed}
							}
						}

						var foundUser bool
						var targetUserID string
						for _, userRec := range userRecords {
							uName := userRec.Get("username").String()
							if strings.EqualFold(uName, plan.Username.ValueString()) {
								targetUserID = userRec.Get("user_id").String()
								if targetUserID == "" {
									targetUserID = userRec.Get("id").String()
								}
								foundUser = true
								break
							}
						}

						if foundUser && targetUserID != "" {
							r.client.GetLog().Debug("[resource_cm_user_pwd_change.go -> Create] Successfully found user_id: " + targetUserID + ". Reconstructing state.")
							plan.ID = types.StringValue(targetUserID)
							diags = resp.State.Set(ctx, plan)
							resp.Diagnostics.Append(diags...)
							return
						}
					}
				} else {
					r.client.GetLog().Debug("[resource_cm_user_pwd_change.go -> Create] Verification login with new password failed: " + verifyErr.Error())
				}
			}
		}

		r.client.GetLog().Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_user_pwd_change.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error changing user password on CipherTrust Manager: ",
			"Could not change user password, unexpected error: "+err.Error(),
		)
		return
	}

	// Fetch the actual user_id from the user list endpoint since the successful
	// password change PATCH response (HTTP 204 No Content) has an empty body.
	usersJSON, listErr := r.client.GetByIdBootstrap(ctx, id, "", common.URL_USER_MANAGEMENT)
	var targetUserID string
	if listErr == nil {
		var userRecords []gjson.Result
		if gjson.Get(usersJSON, "resources").Exists() {
			userRecords = gjson.Get(usersJSON, "resources").Array()
		} else {
			parsed := gjson.Parse(usersJSON)
			if parsed.IsArray() {
				userRecords = parsed.Array()
			} else {
				userRecords = []gjson.Result{parsed}
			}
		}

		for _, userRec := range userRecords {
			uName := userRec.Get("username").String()
			if strings.EqualFold(uName, plan.Username.ValueString()) {
				targetUserID = userRec.Get("user_id").String()
				if targetUserID == "" {
					targetUserID = userRec.Get("id").String()
				}
				break
			}
		}
	}

	if targetUserID == "" {
		// Fallback to generating a unique UUID so the resource ID is never empty or null.
		targetUserID = uuid.New().String()
	}

	plan.ID = types.StringValue(targetUserID)

	r.client.GetLog().Trace(common.MSG_METHOD_END + "[resource_cm_user_pwd_change.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMPwdChange) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.GetLog().Trace(common.MSG_METHOD_START + "[resource_cm_user_pwd_change.go -> Read][" + id + "]")
	defer r.client.GetLog().Trace(common.MSG_METHOD_END + "[resource_cm_user_pwd_change.go -> Read][" + id + "]")

	var state CMPwdChangeTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Verify the underlying user still exists via the user management endpoint.
	// state.ID holds the CM user_id stored during Create(). If it is non-empty,
	// perform a GET to detect 404 (user deleted out-of-band).
	if !state.ID.IsNull() && !state.ID.IsUnknown() && state.ID.ValueString() != "" {
		response, err := r.client.GetByIdBootstrap(ctx, id, state.ID.ValueString(), common.URL_USER_MANAGEMENT)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				resp.Diagnostics.AddWarning(
					"User Password Change Not Found — State Preserved",
					"The User Password Change resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
				)
				return
			}
			r.client.GetLog().Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_user_pwd_change.go -> Read][" + id + "]")
			resp.Diagnostics.AddError(
				"Error Reading CipherTrust User Password Change",
				"Could not read user "+state.ID.ValueString()+": "+err.Error(),
			)
			return
		}

		// Hydrate the server-assigned user_id from GET response (Computed-only).
		state.ID = types.StringValue(gjson.Get(response, "user_id").String())
	}

	// All credential and input-only fields (password, new_password, username,
	// auth_domain, password_hint) are write-only — CM does not return them in
	// GET responses. They are preserved from prior state automatically.

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPwdChange) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.client.GetLog().Trace(common.MSG_METHOD_START + "[resource_cm_user_pwd_change.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_cm_user_password_change does not support updates. To change the password again, delete and recreate this resource.",
	)
	r.client.GetLog().Trace(common.MSG_METHOD_END + "[resource_cm_user_pwd_change.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPwdChange) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *resourceCMPwdChange) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(common.CMClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected common.CMClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
