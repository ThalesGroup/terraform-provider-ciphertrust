package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMPwdChange{}
	_ resource.ResourceWithConfigure = &resourceCMPwdChange{}
)

func NewResourceCMPwdChange() resource.Resource {
	return &resourceCMPwdChange{}
}

type resourceCMPwdChange struct {
	client *common.CMClientBootstrap
}

func (r *resourceCMPwdChange) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_user_password_change"
}

// Schema defines the schema for the resource.
func (r *resourceCMPwdChange) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"username": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Username of the CipherTrust Manager user whose password is being changed.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"password": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Current password for the user.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"new_password": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) New password to set for the user.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"auth_domain": schema.StringAttribute{
				Optional:    true,
				Description: "Authentication domain of the user whose password is being changed. Changing this value forces replacement of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"password_hint": schema.StringAttribute{
				Optional:    true,
				Description: "Optional hint for the new password. Changing this value forces replacement of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPwdChange) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user_pwd_change.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMPwdChangeTFSDK
	var payload CMPwdChangeJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Username = plan.Username.ValueString()
	payload.Password = plan.Password.ValueString()
	payload.NewPassword = plan.NewPassword.ValueString()
	if !plan.AuthDomain.IsNull() && !plan.AuthDomain.IsUnknown() {
		payload.AuthDomain = plan.AuthDomain.ValueString()
	}
	if !plan.PasswordHint.IsNull() && !plan.PasswordHint.IsUnknown() {
		payload.PasswordHint = plan.PasswordHint.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user_pwd_change.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Change user password",
			err.Error(),
		)
		return
	}

	response, err := r.client.PatchDataBootstrap(ctx, id, common.URL_CHANGE_USER_PWD, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user_pwd_change.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error changing user password on CipherTrust Manager: ",
			"Could not change user password, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_cm_user_pwd_change.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user_pwd_change.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMPwdChange) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Intentionally empty. ciphertrust_cm_user_password_change is a one-shot action
	// resource: it triggers a CM password change and has no retrievable state.
	// The CM API provides no GET endpoint for password-change records.
	//
	// User-visible consequence: after the initial `terraform apply`, subsequent
	// `terraform plan` runs will always show no changes — even if the password
	// was changed or reset in CM outside of Terraform. This is a known,
	// intentional limitation documented in TFIN-DD-015.
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPwdChange) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user_pwd_change.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_cm_user_password_change does not support updates. To change the password again, delete and recreate this resource.",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user_pwd_change.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPwdChange) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *resourceCMPwdChange) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.CMClientBootstrap)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
