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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMUser{}
	_ resource.ResourceWithConfigure = &resourceCMUser{}
)

func NewResourceCMUser() resource.Resource {
	return &resourceCMUser{}
}

type resourceCMUser struct {
	client *common.Client
}

func (r *resourceCMUser) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

// Schema defines the schema for the resource.
func (r *resourceCMUser) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"user_id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"username": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Username of the user.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"nickname": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Effectively immutable) Display name / nickname of the user. CM's PATCH /api/v1/usermgmt/users/{id} silently ignores changes to this field (HTTP 200, value unchanged). Set at creation time only; changing this attribute on an existing resource will produce a plan-time error. Destroy and recreate to change nickname.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"email": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Users full name",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"password": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
			"is_domain_user": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "(Immutable) Set to true if user is a domain user. Removing this attribute from config after setting it to true also triggers the immutability error — destroy and recreate to change.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"prevent_ui_login": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"password_change_required": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"user_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Information that can be stored with the user.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMUser) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMUserTFSDK
	var loginFlags UserLoginFlagsJSON
	var payload CMUserJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.UserName = common.TrimString(plan.UserName.ValueString())
	payload.Password = common.TrimString(plan.Password.ValueString())

	if plan.PreventUILogin.ValueBool() != types.BoolNull().ValueBool() {
		loginFlags.PreventUILogin = plan.PreventUILogin.ValueBool()
		payload.LoginFlags = loginFlags
	}

	if common.TrimString(plan.Email.ValueString()) != "" && common.TrimString(plan.Email.ValueString()) != types.StringNull().ValueString() {
		payload.Email = common.TrimString(plan.Email.ValueString())
	}

	if common.TrimString(plan.Name.ValueString()) != "" && common.TrimString(plan.Name.ValueString()) != types.StringNull().ValueString() {
		payload.Name = common.TrimString(plan.Name.ValueString())
	}

	if common.TrimString(plan.Nickname.ValueString()) != "" && common.TrimString(plan.Nickname.ValueString()) != types.StringNull().ValueString() {
		payload.Nickname = common.TrimString(plan.Nickname.ValueString())
	}

	if plan.IsDomainUser.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsDomainUser = plan.IsDomainUser.ValueBool()
	}

	if plan.PasswordChangeRequired.ValueBool() != types.BoolNull().ValueBool() {
		payload.PasswordChangeRequired = plan.PasswordChangeRequired.ValueBool()
	}

	if len(plan.Metadata.Elements()) != 0 {
		metadata := make(map[string]string, len(plan.Metadata.Elements()))
		resp.Diagnostics.Append(plan.Metadata.ElementsAs(ctx, &metadata, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if len(plan.Metadata.Elements()) != 0 {
		metadata := make(map[string]string, len(plan.Metadata.Elements()))
		resp.Diagnostics.Append(plan.Metadata.ElementsAs(ctx, &metadata, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		payload.Metadata = stringsToRawJSON(metadata)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: User Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_USER_MANAGEMENT, payloadJSON, "user_id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating user on CipherTrust Manager: ",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}

	plan.UserID = types.StringValue(response)
	plan.ID = types.StringValue(response)

	userResponse, err := r.client.GetById(ctx, response, response, common.URL_USER_MANAGEMENT)
	if err == nil {
		var user CMUserJSON
		if json.Unmarshal([]byte(userResponse), &user) == nil {
			if gj := gjson.Get(userResponse, "name"); gj.Exists() {
				plan.Name = types.StringValue(gj.String())
			} else {
				plan.Name = types.StringNull()
			}
			if gj := gjson.Get(userResponse, "nickname"); gj.Exists() {
				plan.Nickname = types.StringValue(gj.String())
			} else {
				plan.Nickname = types.StringNull()
			}
			if gj := gjson.Get(userResponse, "email"); gj.Exists() {
				plan.Email = types.StringValue(gj.String())
			} else {
				plan.Email = types.StringNull()
			}
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMUser) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMUserTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	userResponse, err := r.client.GetById(ctx, state.ID.ValueString(), state.ID.ValueString(), common.URL_USER_MANAGEMENT)
	tflog.Trace(ctx, userResponse)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddWarning(
				"CipherTrust User Not Found",
				"The CipherTrust User resource was not found on CipherTrust Manager (HTTP 404). It may have been deleted outside of Terraform. Removing it from state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust User",
			"Could not read CipherTrust user ID "+state.UserID.ValueString()+": "+err.Error(),
		)
		return
	}

	var user CMUserJSON
	if err := json.Unmarshal([]byte(userResponse), &user); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust User",
			"Could not parse CipherTrust user response: "+err.Error(),
		)
		return
	}

	// For optional+computed fields with defaults, preserve the config/plan value
	// if the API auto-populates them with values matching other fields
	// This prevents drift when user doesn't explicitly set these fields

	if gj := gjson.Get(userResponse, "email"); gj.Exists() {
		state.Email = types.StringValue(gj.String())
	} else {
		state.Email = types.StringNull()
	}
	state.UserName = types.StringValue(user.UserName)
	state.UserID = types.StringValue(user.UserID)
	state.ID = types.StringValue(user.UserID)
	if gj := gjson.Get(userResponse, "is_domain_user"); gj.Exists() {
		state.IsDomainUser = types.BoolValue(gj.Bool())
	}
	// else: CM omits this key for local users; preserve state instead of resetting to false.
	state.PasswordChangeRequired = types.BoolValue(user.PasswordChangeRequired)
	state.PreventUILogin = types.BoolValue(user.LoginFlags.PreventUILogin)

	if gj := gjson.Get(userResponse, "name"); gj.Exists() {
		state.Name = types.StringValue(gj.String())
	} else {
		state.Name = types.StringNull()
	}

	if gj := gjson.Get(userResponse, "nickname"); gj.Exists() {
		state.Nickname = types.StringValue(gj.String())
	} else {
		state.Nickname = types.StringNull()
	}
	if !state.Metadata.IsNull() {
		metaResult := gjson.Get(userResponse, "user_metadata")
		if !metaResult.Exists() {
			state.Metadata = types.MapNull(types.StringType)
		} else if len(metaResult.Map()) == 0 {
			state.Metadata = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			metaMap := make(map[string]string, len(metaResult.Map()))
			for k, v := range metaResult.Map() {
				if v.Type == gjson.String {
					metaMap[k] = v.String()
				} else {
					metaMap[k] = v.Raw
				}
			}
			var metaDiags diag.Diagnostics
			state.Metadata, metaDiags = types.MapValueFrom(ctx, types.StringType, metaMap)
			resp.Diagnostics.Append(metaDiags...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMUser) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Update]["+id+"]")

	var plan CMUserTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state CMUserTFSDK
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = state.ID
	plan.UserID = state.UserID

	// Write-only preservation: if the user removed password from config, preserve
	// the prior value rather than sending "" to CM.
	if plan.Password.IsNull() || plan.Password.IsUnknown() {
		plan.Password = state.Password
	}

	var loginFlags UserLoginFlagsJSON
	var payload CMUserJSON
	loginFlags.PreventUILogin = plan.PreventUILogin.ValueBool()

	// Only include optional string fields in the PATCH payload when they have
	// a non-empty value. Omitting them lets the API preserve existing values.
	if email := common.TrimString(plan.Email.ValueString()); email != "" {
		payload.Email = email
	}
	if name := common.TrimString(plan.Name.ValueString()); name != "" {
		payload.Name = name
	}
	// nickname is effectively immutable — CM's PATCH silently ignores this field.
	// ImmutableString() in the schema prevents plan-time changes from reaching Update().
	// Omit from payload to avoid sending a field that CM will discard.
	// Only include password in the update if it has changed
	if plan.Password.ValueString() != state.Password.ValueString() {
		payload.Password = common.TrimString(plan.Password.ValueString())
	}

	payload.IsDomainUser = plan.IsDomainUser.ValueBool()
	payload.LoginFlags = loginFlags
	payload.PasswordChangeRequired = plan.PasswordChangeRequired.ValueBool()

	// Three-branch metadata payload builder.
	//
	// CM's PATCH endpoint merges user_metadata instead of replacing it:
	//   - Omitting the field: CM preserves all existing keys unchanged.
	//   - Sending {"user_metadata": {}}: CM no-ops (merge of empty = no change).
	//   - Sending {"user_metadata": null}: CM rejects with HTTP 422.
	//   - Sending {"user_metadata": {"key": null}}: CM deletes that key.
	//
	// Consequence: both full clear and partial key removal require explicit
	// per-key nulls. Keys absent from the plan but present in state must be
	// sent as json.RawMessage("null").
	//
	// Note: state.Metadata is types.Map — use ElementsAs, NOT json.Unmarshal
	// (the group resource's json.Unmarshal-from-string pattern applies only to
	// types.String metadata fields in resource_cm_group.go).
	switch {
	case !plan.Metadata.IsNull() && !plan.Metadata.IsUnknown():
		// New/updated or partial-removal metadata.
		// Compute the diff between state and plan:
		//   - Surviving keys (in plan): send their string values.
		//   - Deleted keys (in state but absent from plan): send json null.
		planMeta := make(map[string]string, len(plan.Metadata.Elements()))
		resp.Diagnostics.Append(plan.Metadata.ElementsAs(ctx, &planMeta, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Start with surviving keys.
		metaPayload := stringsToRawJSON(planMeta)

		// Null out deleted keys (present in state but absent from plan).
		if !state.Metadata.IsNull() && !state.Metadata.IsUnknown() {
			stateMeta := make(map[string]string, len(state.Metadata.Elements()))
			resp.Diagnostics.Append(state.Metadata.ElementsAs(ctx, &stateMeta, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			for k := range stateMeta {
				if _, exists := planMeta[k]; !exists {
					metaPayload[k] = json.RawMessage("null")
				}
			}
		}
		payload.Metadata = metaPayload

	case plan.Metadata.IsNull() && !state.Metadata.IsNull():
		// Plan clears metadata entirely; state shows keys were previously set.
		// Send {"key": null} for each existing key to trigger per-key deletion.
		existing := make(map[string]string, len(state.Metadata.Elements()))
		resp.Diagnostics.Append(state.Metadata.ElementsAs(ctx, &existing, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(existing) > 0 {
			nullMap := make(map[string]json.RawMessage, len(existing))
			for k := range existing {
				nullMap[k] = json.RawMessage("null")
			}
			payload.Metadata = nullMap
		}
	// default: both plan and state are null, or plan is unknown — nothing to send.
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: User Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_USER_MANAGEMENT, payloadJSON, "user_id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating user on CipherTrust Manager: ",
			"Could not update user, unexpected error: "+err.Error(),
		)
		return
	}
	plan.UserID = types.StringValue(response)

	userResponse, err := r.client.GetById(ctx, plan.ID.ValueString(), plan.ID.ValueString(), common.URL_USER_MANAGEMENT)
	if err == nil {
		var user CMUserJSON
		if json.Unmarshal([]byte(userResponse), &user) == nil {
			if gj := gjson.Get(userResponse, "name"); gj.Exists() {
				plan.Name = types.StringValue(gj.String())
			} else {
				plan.Name = types.StringNull()
			}
			// nickname: preserve the plan value — do NOT overwrite from GET response.
			// CM's PATCH does not persist nickname changes; overwriting plan.Nickname with the
			// GET-returned (old) value would conflict with Terraform's planned value and trip the
			// framework's post-apply consistency check. Since ImmutableString() blocks plan-time
			// changes, plan.Nickname already equals state.Nickname here; preserving it is correct.
			if gj := gjson.Get(userResponse, "email"); gj.Exists() {
				plan.Email = types.StringValue(gj.String())
			} else {
				plan.Email = types.StringNull()
			}
			// Post-PATCH read-back is plan-aware to prevent {} → null oscillation.
			//
			// Clearing case (plan null): regardless of whether CM returns absent or {},
			// write MapNull so state matches config intent. The per-key null PATCH above
			// attempted to clear all keys; if it succeeded CM returns absent or {}; if
			// it silently no-oped (transient CM error), we write MapNull anyway and the
			// residual CM data becomes invisible until state.Metadata becomes non-null
			// again. This is an accepted residual risk (see Change Summary).
			//
			// Non-null plan: re-read from CM authoritatively via the three-branch pattern.
			// Writing CM's actual post-PATCH value (not the plan value) prevents state
			// drift when CM silently ignores a key value.
			if plan.Metadata.IsNull() {
				plan.Metadata = types.MapNull(types.StringType)
			} else {
				metaResult := gjson.Get(userResponse, "user_metadata")
				if !metaResult.Exists() {
					plan.Metadata = types.MapNull(types.StringType)
				} else if len(metaResult.Map()) == 0 {
					plan.Metadata = types.MapValueMust(types.StringType, map[string]attr.Value{})
				} else {
					metaMap := make(map[string]string, len(metaResult.Map()))
					for k, v := range metaResult.Map() {
						if v.Type == gjson.String {
							metaMap[k] = v.String()
						} else {
							metaMap[k] = v.Raw
						}
					}
					var metaDiags diag.Diagnostics
					plan.Metadata, metaDiags = types.MapValueFrom(ctx, types.StringType, metaMap)
					resp.Diagnostics.Append(metaDiags...)
					if resp.Diagnostics.HasError() {
						return
					}
				}
			}
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMUser) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMUserTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_USER_MANAGEMENT, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Delete]["+state.UserID.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			// Resource was already deleted outside of Terraform — desired state achieved.
			resp.Diagnostics.AddWarning(
				"CipherTrust User Not Found on Delete",
				"The CipherTrust User resource returned HTTP 404 during deletion. It was likely removed outside of Terraform. Treating as successfully deleted.",
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust User",
			"Could not delete user, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMUser) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
