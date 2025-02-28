package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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
			},
			"nickname": schema.StringAttribute{
				Optional: true,
			},
			"email": schema.StringAttribute{
				Optional: true,
			},
			"full_name": schema.StringAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Required: true,
			},
			"is_domain_user": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"prevent_ui_login": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"password_change_required": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
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

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMUser) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// var state tfsdkCMUserModel
	// diags := req.State.Get(ctx, &state)
	// resp.Diagnostics.Append(diags...)
	// if resp.Diagnostics.HasError() {
	// 	return
	// }

	// users, err := r.client.GetAll(ctx, state.UserID.ValueString(), URL_USER_MANAGEMENT)
	// tflog.Trace(ctx, users)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error Reading CipherTrust User",
	// 		"Could not read CipherTrust user ID "+state.UserID.ValueString()+": "+err.Error(),
	// 	)
	// 	return
	// }

	// userJSON := make(map[string]interface{})
	// errJsonUnmarshall := json.Unmarshal([]byte(users), &userJSON)
	// if errJsonUnmarshall != nil {
	// 	log.Fatal(errJsonUnmarshall)
	// }

	// state.Email = userJSON["email"].(basetypes.StringValue)
	// state.Name = userJSON["name"].(basetypes.StringValue)
	// state.Nickname = userJSON["nickname"].(basetypes.StringValue)
	// state.UserName = userJSON["username"].(basetypes.StringValue)
	// state.UserID = userJSON["user_id"].(basetypes.StringValue)

	// diags = resp.State.Set(ctx, &state)
	// resp.Diagnostics.Append(diags...)
	// if resp.Diagnostics.HasError() {
	// 	return
	// }
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

	response, err := r.client.UpdateData(ctx, plan.UserID.ValueString(), common.URL_USER_MANAGEMENT, payloadJSON, "user_id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+plan.UserID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating user on CipherTrust Manager: ",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}
	plan.UserID = types.StringValue(response)
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
