package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	resp.TypeName = req.ProviderTypeName + "_cm_user"
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
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"nickname": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"email": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"full_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"password": schema.StringAttribute{
				Optional: true,
			},
			"is_domain_user": schema.BoolAttribute{
				Optional: true,
			},
			"prevent_ui_login": schema.BoolAttribute{
				Optional: true,
			},
			"password_change_required": schema.BoolAttribute{
				Optional: true,
			},
			"created_at":             schema.StringAttribute{Computed: true},
			"updated_at":             schema.StringAttribute{Computed: true},
			"last_login":             schema.StringAttribute{Computed: true},
			"logins_count":           schema.Int64Attribute{Computed: true},
			"certificate_subject_dn": schema.StringAttribute{Computed: true},
			"failed_logins_count":    schema.Int64Attribute{Computed: true},
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

	payload.UserName = common.TrimString(plan.UserName.String())
	payload.Password = common.TrimString(plan.Password.String())

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

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: User Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_USER_MANAGEMENT, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating user on CipherTrust Manager: ",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}

	plan.UserID = types.StringValue(gjson.Get(response, "user_id").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.UserName = types.StringValue(gjson.Get(response, "username").String())
	plan.Nickname = types.StringValue(gjson.Get(response, "nickname").String())
	plan.Email = types.StringValue(gjson.Get(response, "email").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "created_at").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updated_at").String())
	plan.LastLogin = types.StringValue(gjson.Get(response, "last_login").String())
	plan.LoginsCount = types.Int64Value(gjson.Get(response, "logins_count").Int())
	plan.CertificateDN = types.StringValue(gjson.Get(response, "certificate_subject_dn").String())
	plan.FailedLoginsCount = types.Int64Value(gjson.Get(response, "failed_logins_count").Int())

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
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.UserID.ValueString(), common.URL_USER_MANAGEMENT)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading User on CipherTrust Manager: ",
			"Could not read User Data : ,"+state.UserID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.UserID = types.StringValue(gjson.Get(response, "user_id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.UserName = types.StringValue(gjson.Get(response, "username").String())
	state.Nickname = types.StringValue(gjson.Get(response, "nickname").String())
	state.Email = types.StringValue(gjson.Get(response, "email").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "created_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updated_at").String())
	state.LastLogin = types.StringValue(gjson.Get(response, "last_login").String())
	state.LoginsCount = types.Int64Value(gjson.Get(response, "logins_count").Int())
	state.CertificateDN = types.StringValue(gjson.Get(response, "certificate_subject_dn").String())
	state.FailedLoginsCount = types.Int64Value(gjson.Get(response, "failed_logins_count").Int())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMUser) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CMUserTFSDK
	var loginFlags UserLoginFlagsJSON
	var payload CMUserJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	loginFlags.PreventUILogin = plan.PreventUILogin.ValueBool()

	payload.Email = common.TrimString(plan.Email.String())
	payload.Name = common.TrimString(plan.Name.String())
	payload.Nickname = common.TrimString(plan.Nickname.String())
	payload.UserName = common.TrimString(plan.UserName.String())
	payload.Password = common.TrimString(plan.Password.String())
	payload.IsDomainUser = plan.IsDomainUser.ValueBool()
	payload.LoginFlags = loginFlags
	payload.PasswordChangeRequired = plan.PasswordChangeRequired.ValueBool()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+plan.UserID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: User Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		plan.UserID.ValueString(),
		common.URL_USER_MANAGEMENT,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+plan.UserID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating user on CipherTrust Manager: ",
			"Could not update user, unexpected error: "+err.Error(),
		)
		return
	}
	plan.UserID = types.StringValue(response)
	plan.UserID = types.StringValue(gjson.Get(response, "user_id").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.UserName = types.StringValue(gjson.Get(response, "username").String())
	plan.Nickname = types.StringValue(gjson.Get(response, "nickname").String())
	plan.Email = types.StringValue(gjson.Get(response, "email").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "created_at").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updated_at").String())
	plan.LastLogin = types.StringValue(gjson.Get(response, "last_login").String())
	plan.LoginsCount = types.Int64Value(gjson.Get(response, "logins_count").Int())
	plan.CertificateDN = types.StringValue(gjson.Get(response, "certificate_subject_dn").String())
	plan.FailedLoginsCount = types.Int64Value(gjson.Get(response, "failed_logins_count").Int())

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
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_USER_MANAGEMENT, state.UserID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.UserID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Delete]["+state.UserID.ValueString()+"]["+output+"]")
	if err != nil {
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
