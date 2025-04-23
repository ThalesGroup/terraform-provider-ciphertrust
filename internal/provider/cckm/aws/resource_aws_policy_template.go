package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
	"reflect"
	"strings"
)

var (
	_ resource.Resource              = &resourceAWSPolicyTemplate{}
	_ resource.ResourceWithConfigure = &resourceAWSPolicyTemplate{}
)

func NewResourceAWSPolicyTemplate() resource.Resource {
	return &resourceAWSPolicyTemplate{}
}

type resourceAWSPolicyTemplate struct {
	client *common.Client
}

func (r *resourceAWSPolicyTemplate) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_policy_template"
}

func (r *resourceAWSPolicyTemplate) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = client
}

func (r *resourceAWSPolicyTemplate) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create an AWS key policy that can be used by multiple AWS keys.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The AWS account which owns this resource.",
			},
			"auto_push": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "On update, automatically push policy changes. Must be set to true if 'is_verified' is true.",
				Default:     booldefault.StaticBool(false),
			},
			"is_verified": schema.BoolAttribute{
				Computed:    true,
				Description: "If tre, the policy template has been applied.",
			},
			"external_accounts": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that can access to the key.",
			},
			"key_admins": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_users": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"kms": schema.StringAttribute{
				Optional:    true,
				Description: "Name or ID of the KMS to which the template belongs.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "A name for the template.",
			},
			"policy": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "AWS key policy json.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(
						path.Expressions{
							path.MatchRoot("external_accounts"),
							path.MatchRoot("key_admins"),
							path.MatchRoot("key_admins_roles"),
							path.MatchRoot("key_users"),
							path.MatchRoot("key_users_roles"),
						}...,
					),
				},
			},
		},
	}
}

func (r *resourceAWSPolicyTemplate) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_policy_template -> Create]["+id+"]")
	var plan AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyPolicyParams := r.getKeyPolicyParamsJSON(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := PolicyTemplatePayloadJSON{
		AccountID:           plan.AccountID.ValueString(),
		Kms:                 plan.Kms.ValueString(),
		Name:                plan.Name.ValueString(),
		KeyPolicyParamsJSON: *keyPolicyParams,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		details := map[string]interface{}{"error": err.Error()}
		msg := "Error creating AWS key policy template, invalid data input."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		details := map[string]interface{}{"payload": string(payloadJSON), "error": err.Error()}
		msg := "Error creating AWS key policy template."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	var diags diag.Diagnostics
	r.setPolicyTemplateState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceAWSPolicyTemplate) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_policy_template -> Read]["+id+"]")
	var state AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, templateID, common.URL_AWS_POLICY_TEMPLATES)
	if err != nil {
		details := map[string]interface{}{"template id": templateID, "error": err.Error()}
		msg := "Error reading AWS key policy template."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setPolicyTemplateState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		details := map[string]interface{}{"template id": templateID}
		msg := "Error reading AWS key policy template."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceAWSPolicyTemplate) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_policy_template -> Update]["+id+"]")
	var plan AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID := plan.ID.ValueString()
	var state AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyPolicyParams := r.getKeyPolicyParamsJSON(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := PolicyTemplatePayloadJSON{
		AccountID:           plan.AccountID.ValueString(),
		Kms:                 plan.Kms.ValueString(),
		Name:                plan.Name.ValueString(),
		KeyPolicyParamsJSON: *keyPolicyParams,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		details := map[string]interface{}{"template id": templateID, "error": err.Error()}
		msg := "Error updating AWS key policy template, invalid data input."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err := r.client.UpdateDataV2(ctx, templateID, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		details := map[string]interface{}{"template id": templateID, "payload": string(payloadJSON), "error": err.Error()}
		msg := "Error updating AWS key policy template."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setPolicyTemplateState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		details := map[string]interface{}{"template id": templateID}
		msg := "Error updating AWS key policy template, failed to set resource state."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceAWSPolicyTemplate) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_policy_template -> Delete]["+id+"]")
	var state AWSKeyPolicyTemplateTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	templateID := state.ID.ValueString()
	_, err := r.client.DeleteByURL(ctx, templateID, common.URL_AWS_POLICY_TEMPLATES+"/"+templateID)
	if err != nil {
		if strings.Contains(err.Error(), "has one or more key associated") {
			msg := "AWS policy template " + templateID + " has one or more keys associated with it so it can't be deleted. This includes keys scheduled for deletion."
			tflog.Warn(ctx, msg, map[string]interface{}{"error": err.Error()})
			resp.Diagnostics.AddWarning(msg, err.Error())
		} else {
			msg := "Error deleting AWS policy template " + templateID + "."
			tflog.Error(ctx, msg, map[string]interface{}{"error": err.Error()})
			resp.Diagnostics.AddError(msg, err.Error())
		}
	}
}

func (r *resourceAWSPolicyTemplate) getKeyPolicyParamsJSON(ctx context.Context, plan *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) *KeyPolicyParamsJSON {
	var keyPolicyParams KeyPolicyParamsJSON
	if !plan.ExternalAccounts.IsNull() && len(plan.ExternalAccounts.Elements()) != 0 {
		accounts := make([]string, 0, len(plan.ExternalAccounts.Elements()))
		diags.Append(plan.ExternalAccounts.ElementsAs(ctx, &accounts, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.ExternalAccounts = &accounts
	}
	if !plan.KeyAdmins.IsNull() && len(plan.KeyAdmins.Elements()) != 0 {
		keyAdmins := make([]string, 0, len(plan.KeyAdmins.Elements()))
		diags.Append(plan.KeyAdmins.ElementsAs(ctx, &keyAdmins, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyAdmins = &keyAdmins
	}
	if !plan.KeyAdminsRoles.IsNull() && len(plan.KeyAdminsRoles.Elements()) != 0 {
		keyAdminsRoles := make([]string, 0, len(plan.KeyAdminsRoles.Elements()))
		diags.Append(plan.KeyAdminsRoles.ElementsAs(ctx, &keyAdminsRoles, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyAdminsRoles = &keyAdminsRoles
	}
	if !plan.KeyUsers.IsNull() && len(plan.KeyUsers.Elements()) != 0 {
		keyUsers := make([]string, 0, len(plan.KeyUsers.Elements()))
		diags.Append(plan.KeyUsers.ElementsAs(ctx, &keyUsers, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyUsers = &keyUsers
	}
	if !plan.KeyUsersRoles.IsNull() && len(plan.KeyUsersRoles.Elements()) != 0 {
		keyUsersRoles := make([]string, 0, len(plan.KeyUsersRoles.Elements()))
		diags.Append(plan.KeyUsersRoles.ElementsAs(ctx, &keyUsersRoles, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyUsersRoles = &keyUsersRoles
	}
	if !plan.Policy.IsUnknown() && len(plan.Policy.String()) != 0 {
		policy := plan.Policy.ValueString()
		policyBytes := json.RawMessage(policy)
		keyPolicyParams.Policy = &policyBytes
	}
	return &keyPolicyParams
}

func (r *resourceAWSPolicyTemplate) setPolicyTemplateState(ctx context.Context, response string, state *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) {
	state.AutoPush = types.BoolValue(gjson.Get(response, "AutoPush").Bool())
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	externalAccounts := gjson.Get(response, "external_accounts").Array()
	if len(externalAccounts) != 0 {
		state.ExternalAccounts = flattenStringSliceJSON(externalAccounts, diags)
	}
	state.IsVerified = types.BoolValue(gjson.Get(response, "is_verified").Bool())
	keyAdmins := gjson.Get(response, "key_admins").Array()
	if len(keyAdmins) != 0 {
		state.KeyAdmins = flattenStringSliceJSON(keyAdmins, diags)
	}
	keyAdminsRoles := gjson.Get(response, "key_admins_roles").Array()
	if len(keyAdminsRoles) != 0 {
		state.KeyAdminsRoles = flattenStringSliceJSON(keyAdminsRoles, diags)
	}
	keyUsers := gjson.Get(response, "key_users").Array()
	if len(keyUsers) != 0 {
		state.KeyUsers = flattenStringSliceJSON(keyUsers, diags)
	}
	keyUsersRoles := gjson.Get(response, "key_users_roles").Array()
	if len(keyUsersRoles) != 0 {
		state.KeyUsersRoles = flattenStringSliceJSON(keyUsersRoles, diags)
	}
	policy := gjson.Get(response, "policy").String()
	equivalent, err := jsonBytesEqual([]byte(policy), []byte(state.Policy.ValueString()))
	if err != nil {
		msg := "Error comparing state and plan 'ciphertrust_aws_policy_template.policy' of " + state.Name.ValueString() + "."
		details := map[string]interface{}{"error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return
	}
	if !equivalent {
		state.Policy = types.StringValue(gjson.Get(response, "policy").String())
	}
}

func jsonBytesEqual(a []byte, b []byte) (bool, error) {
	var j, j2 interface{}
	if len(a) != len(b) {
		return false, nil
	}
	if len(a) == 0 && len(b) == 0 {
		return true, nil
	}
	if err := json.Unmarshal(a, &j); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false, err
	}
	return reflect.DeepEqual(j2, j), nil
}
