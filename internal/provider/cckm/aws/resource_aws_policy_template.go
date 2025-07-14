package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
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
)

var (
	_ resource.Resource                = &resourceAWSPolicyTemplate{}
	_ resource.ResourceWithConfigure   = &resourceAWSPolicyTemplate{}
	_ resource.ResourceWithImportState = &resourceAWSPolicyTemplate{}
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
		Description: "Use this resource to create and managa AWS key policy templates that can be used by multiple AWS keys.",
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
				Description: "(Updatable) On update, automatically push policy changes. Must be set to true if 'is_verified' is true.",
				Default:     booldefault.StaticBool(false),
			},
			"is_verified": schema.BoolAttribute{
				Computed:    true,
				Description: "If true, the policy template has been applied.",
			},
			"external_accounts": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "(Updatable) Other AWS accounts that can access to the key.",
			},
			"key_admins": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "(Updatable) Key administrators - users.",
			},
			"key_admins_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "(Updatable) Key administrators - roles.",
			},
			"key_users": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "(Updatable) Key users - users.",
			},
			"key_users_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "(Updatable) Key users - roles.",
			},
			"kms": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name or ID of the KMS to which the template belongs.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "A name for the template.",
			},
			"policy": schema.StringAttribute{
				Computed: true,
				Optional: true,
				Description: "(Updatable) AWS key policy json. 'policy' is mutually exclusive to all other policy parameters. " +
					"If no policy parameters are specified the default policy is created.",
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
	keyPolicyParams := r.getCreatePolicyTemplateParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Policy.IsUnknown() && len(plan.Policy.String()) != 0 {
		if keyPolicyParams == nil {
			keyPolicyParams = new(KeyPolicyParamsJSON)
		}
		policy := plan.Policy.ValueString()
		policyBytes := json.RawMessage(policy)
		keyPolicyParams.Policy = &policyBytes
	}
	if keyPolicyParams == nil {
		msg := "Error creating AWS key policy template, invalid data input."
		tflog.Error(ctx, msg)
		resp.Diagnostics.AddError(msg, "")
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
		msg := "Error creating AWS key policy template, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		msg := "Error creating AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template.go -> Create]["+id+"]")
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
		msg := "Error reading AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_policy_template.go -> Read][response:"+response)
	r.setPolicyTemplateState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.AutoPush.IsUnknown() || state.AutoPush.IsNull() {
		// terraform import
		state.AutoPush = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceAWSPolicyTemplate) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_policy_template.go -> ImportState]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_policy_template.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
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

	response, err := r.client.GetById(ctx, id, templateID, common.URL_AWS_POLICY_TEMPLATES)
	if err != nil {
		msg := "Error reading AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_policy_template.go -> Update][response:"+response)

	keyPolicyParams := r.getUpdatePolicyTemplateParams(ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if keyPolicyParams.Policy == nil && keyPolicyParams.ExternalAccounts == nil &&
		keyPolicyParams.KeyAdmins == nil && keyPolicyParams.KeyAdminsRoles == nil &&
		keyPolicyParams.KeyUsers == nil && keyPolicyParams.KeyUsersRoles == nil {
		// terraform import can lead to this
		tflog.Trace(ctx, "[resource_aws_policy_template.go -> Update][nothing to update")
		r.setPolicyTemplateState(ctx, response, &plan, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		return
	}

	payload := KeyPolicyTemplateUpdatePayloadJSON{
		KeyPolicyParamsJSON: *keyPolicyParams,
	}
	if !plan.AutoPush.IsUnknown() && !plan.AutoPush.IsNull() {
		payload.AutoPush = plan.AutoPush.ValueBool()
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS key policy template, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.UpdateDataV2(ctx, templateID, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		msg := "Error updating AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	r.setPolicyTemplateState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
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
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			msg := "Error deleting AWS policy template " + templateID + "."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
		}
	}
}

func (r *resourceAWSPolicyTemplate) getCreatePolicyTemplateParams(ctx context.Context, plan *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) *KeyPolicyParamsJSON {
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

func (r *resourceAWSPolicyTemplate) getUpdatePolicyTemplateParams(ctx context.Context, plan *AWSKeyPolicyTemplateTFSDK, state *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) *KeyPolicyParamsJSON {
	var keyPolicyParams KeyPolicyParamsJSON
	emptySlice := []string{}
	if !plan.ExternalAccounts.IsNull() && len(plan.ExternalAccounts.Elements()) != 0 {
		accounts := make([]string, 0, len(plan.ExternalAccounts.Elements()))
		diags.Append(plan.ExternalAccounts.ElementsAs(ctx, &accounts, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.ExternalAccounts = &accounts
	} else if len(state.ExternalAccounts.Elements()) != 0 {
		keyPolicyParams.ExternalAccounts = &emptySlice
	}
	if !plan.KeyAdmins.IsNull() && len(plan.KeyAdmins.Elements()) != 0 {
		keyAdmins := make([]string, 0, len(plan.KeyAdmins.Elements()))
		diags.Append(plan.KeyAdmins.ElementsAs(ctx, &keyAdmins, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyAdmins = &keyAdmins
	} else if len(state.KeyAdmins.Elements()) != 0 {
		keyPolicyParams.KeyAdmins = &emptySlice
	}
	if !plan.KeyAdminsRoles.IsNull() && len(plan.KeyAdminsRoles.Elements()) != 0 {
		keyAdminsRoles := make([]string, 0, len(plan.KeyAdminsRoles.Elements()))
		diags.Append(plan.KeyAdminsRoles.ElementsAs(ctx, &keyAdminsRoles, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyAdminsRoles = &keyAdminsRoles
	} else if len(state.KeyAdminsRoles.Elements()) != 0 {
		keyPolicyParams.KeyAdminsRoles = &emptySlice
	}
	if !plan.KeyUsers.IsNull() && len(plan.KeyUsers.Elements()) != 0 {
		keyUsers := make([]string, 0, len(plan.KeyUsers.Elements()))
		diags.Append(plan.KeyUsers.ElementsAs(ctx, &keyUsers, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyUsers = &keyUsers
	} else if len(state.KeyUsers.Elements()) != 0 {
		keyPolicyParams.KeyUsers = &emptySlice
	}
	if !plan.KeyUsersRoles.IsNull() && len(plan.KeyUsersRoles.Elements()) != 0 {
		keyUsersRoles := make([]string, 0, len(plan.KeyUsersRoles.Elements()))
		diags.Append(plan.KeyUsersRoles.ElementsAs(ctx, &keyUsersRoles, false)...)
		if diags.HasError() {
			return nil
		}
		keyPolicyParams.KeyUsersRoles = &keyUsersRoles
	} else if len(state.KeyUsersRoles.Elements()) != 0 {
		keyPolicyParams.KeyUsersRoles = &emptySlice
	}
	if !plan.Policy.IsUnknown() && len(plan.Policy.String()) != 0 {
		policy := plan.Policy.ValueString()
		policyBytes := json.RawMessage(policy)
		keyPolicyParams.Policy = &policyBytes
	}
	return &keyPolicyParams
}

func (r *resourceAWSPolicyTemplate) setPolicyTemplateState(ctx context.Context, response string, state *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) {
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Kms = types.StringValue(gjson.Get(response, "kms").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	externalAccounts := gjson.Get(response, "external_accounts").Array()
	if len(externalAccounts) != 0 {
		state.ExternalAccounts = utils.StringSliceJSONToSetValue(externalAccounts, diags)
	}
	state.IsVerified = types.BoolValue(gjson.Get(response, "is_verified").Bool())
	keyAdmins := gjson.Get(response, "key_admins").Array()
	if len(keyAdmins) != 0 {
		state.KeyAdmins = utils.StringSliceJSONToSetValue(keyAdmins, diags)
	}
	keyAdminsRoles := gjson.Get(response, "key_admins_roles").Array()
	if len(keyAdminsRoles) != 0 {
		state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(keyAdminsRoles, diags)
	}
	keyUsers := gjson.Get(response, "key_users").Array()
	if len(keyUsers) != 0 {
		state.KeyUsers = utils.StringSliceJSONToSetValue(keyUsers, diags)
	}
	keyUsersRoles := gjson.Get(response, "key_users_roles").Array()
	if len(keyUsersRoles) != 0 {
		state.KeyUsersRoles = utils.StringSliceJSONToSetValue(keyUsersRoles, diags)
	}
	equivalent := getPoliciesAreEqual(ctx, gjson.Get(response, "policy").String(), state.Policy.ValueString(), diags)
	if !equivalent {
		state.Policy = types.StringValue(gjson.Get(response, "policy").String())
	}
}

func getPoliciesAreEqual(ctx context.Context, policy string, planPolicy string, diags *diag.Diagnostics) bool {
	p, err := normalizePolicy(policy)
	if err != nil {
		tflog.Error(ctx, err.Error())
	} else {
		policy = p
	}
	planPolicy = strings.TrimSpace(planPolicy)
	p, err = normalizePolicy(planPolicy)
	if err != nil {
		tflog.Error(ctx, err.Error())
	} else {
		planPolicy = p
	}
	equivalent, err := policyBytesEqual([]byte(policy), []byte(planPolicy))
	if err != nil {
		msg := "Error comparing state and plan key policy'."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return false
	}
	return equivalent
}

func normalizePolicy(jsonString interface{}) (string, error) {
	var j interface{}
	if jsonString == nil {
		return "", nil
	}
	s, ok := jsonString.(string)
	if !ok {
		return "", fmt.Errorf("error normalizing AWS key policy, invalid string data input")
	}
	if s == "" {
		return "", nil
	}
	err := json.Unmarshal([]byte(s), &j)
	if err != nil {
		return s, err
	}
	bytes, _ := json.Marshal(j)
	return string(bytes[:]), nil
}

func policyBytesEqual(a []byte, b []byte) (bool, error) {
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
