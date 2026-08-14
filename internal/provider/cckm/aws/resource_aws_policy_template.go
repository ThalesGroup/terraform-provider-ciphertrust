package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		Description: "Use this resource to create and manage AWS key policy templates that can be used by multiple AWS keys.",
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
				Description: "(Immutable) AWS account used to create the key policy.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"auto_push": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "On update, automatically push policy changes. Must be set to true if 'is_verified' is true.",
				Default:     booldefault.StaticBool(false),
			},
			"is_verified": schema.BoolAttribute{
				Computed:    true,
				Description: "If true, the policy template has been applied.",
			},
			"external_accounts": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "AWS accounts that can use this key. External accounts are mutually exclusive to policy. If no policy parameters are specified the default policy is created.",
			},
			"key_admins": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_users": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"kms_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) ID of the KMS to which the template belongs. 'account_id', 'external_accounts' or 'kms_id' must be provided.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the KMS to which the template belongs.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Name for the policy template.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"policy": schema.StringAttribute{
				Computed: true,
				Optional: true,
				Description: "AWS key policy json. 'policy' is mutually exclusive to all other policy parameters. " +
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

// Create creates a new AWS key policy template in CipherTrust Manager and sets Terraform state.
func (r *resourceAWSPolicyTemplate) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_policy_template.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_policy_template.go -> Create][" + id + "]")
	var plan AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyPolicyParams := r.getCreatePolicyTemplateParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := PolicyTemplatePayloadJSON{
		AccountID: plan.AccountID.ValueString(),
		KmsID:     plan.KmsID.ValueString(),
		Name:      plan.Name.ValueString(),
	}
	if keyPolicyParams != nil {
		payload.KeyPolicyParamsJSON = *keyPolicyParams
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key policy template, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		msg := "Error creating AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_policy_template.go -> Create][response:" + redactAWSResponse(response) + "]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	var diags diag.Diagnostics
	r.setPolicyTemplateState(response, &plan, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an AWS key policy template by fetching it from CipherTrust Manager.
// If the policy template is not found (HTTP 404) an error is returned and state is preserved.
// The resource is only removed from state on "terraform destroy" or when removed from config.
func (r *resourceAWSPolicyTemplate) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_policy_template.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_policy_template.go -> Read][" + id + "]")
	var state AWSKeyPolicyTemplateTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID := state.ID.ValueString()
	response := getAwsPolicyTemplate(ctx, id, r.client, templateID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.setPolicyTemplateState(response, &state, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.AutoPush.IsUnknown() || state.AutoPush.IsNull() {
		// terraform import
		state.AutoPush = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies plan changes to an AWS key policy template and optionally pushes changes to associated keys.
func (r *resourceAWSPolicyTemplate) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_policy_template.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_policy_template.go -> Update][" + id + "]")

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
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_policy_template.go -> Update][get response:" + redactAWSResponse(response) + "]")

	keyPolicyParams := r.getUpdatePolicyTemplateParams(ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if keyPolicyParams != nil {
		if keyPolicyParams.Policy == nil && keyPolicyParams.ExternalAccounts == nil &&
			keyPolicyParams.KeyAdmins == nil && keyPolicyParams.KeyAdminsRoles == nil &&
			keyPolicyParams.KeyUsers == nil && keyPolicyParams.KeyUsersRoles == nil {
			// terraform import can lead to this
			r.client.Log.Debug("[resource_aws_policy_template.go -> Update][nothing to update]")
			r.setPolicyTemplateState(response, &plan, &plan, &resp.Diagnostics)
			resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
			return
		}
	}

	var payload KeyPolicyTemplateUpdatePayloadJSON
	if keyPolicyParams != nil {
		payload.KeyPolicyParamsJSON = *keyPolicyParams
	}
	if !plan.AutoPush.IsUnknown() && !plan.AutoPush.IsNull() {
		payload.AutoPush = plan.AutoPush.ValueBool()
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS key policy template, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.UpdateDataV2(ctx, templateID, common.URL_AWS_POLICY_TEMPLATES, payloadJSON)
	if err != nil {
		msg := "Error updating AWS key policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template id": templateID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_policy_template.go -> Update][response:" + redactAWSResponse(response) + "]")

	r.setPolicyTemplateState(response, &plan, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes an AWS key policy template from CipherTrust Manager if no keys are associated with it.
// If the template is not found (HTTP 404) when destroy runs, a warning is emitted and the resource is
// removed from state rather than returning an error.
func (r *resourceAWSPolicyTemplate) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_policy_template.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_policy_template.go -> Delete][" + id + "]")
	var state AWSKeyPolicyTemplateTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID := state.ID.ValueString()
	getAwsPolicyTemplate(ctx, id, r.client, templateID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if resp.Diagnostics.WarningsCount() > 0 {
		// 404 - already gone, nothing to delete
		return
	}
	_, err := r.client.DeleteByURL(ctx, templateID, common.URL_AWS_POLICY_TEMPLATES+"/"+templateID)
	if err != nil {
		if strings.Contains(err.Error(), "has one or more key associated") {
			msg := "AWS policy template " + templateID + " has one or more keys associated with it so it can't be deleted. This includes keys scheduled for deletion."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
			r.client.Log.Warn(details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			msg := "Error deleting AWS policy template " + templateID + "."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
		}
	}
}

// ImportState imports an existing AWS key policy template into Terraform state using its resource ID.
func (r *resourceAWSPolicyTemplate) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_policy_template.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_policy_template.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getCreatePolicyTemplateParams builds the key policy parameters payload for creating a new policy template.
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

// getUpdatePolicyTemplateParams builds the key policy parameters payload for updating an existing policy template, clearing removed fields.
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

// setPolicyTemplateState populates Terraform state for an AWS key policy template from an API response JSON string.
// planned is the prior state or plan model used to preserve explicit empty-set values when the API returns no data for
// a field. If planned has an explicit empty set (not null) for a field and the API returns empty, state is set to an
// empty set rather than null, preventing "Provider produced inconsistent result after apply" errors.
func (r *resourceAWSPolicyTemplate) setPolicyTemplateState(response string, state *AWSKeyPolicyTemplateTFSDK, planned *AWSKeyPolicyTemplateTFSDK, diags *diag.Diagnostics) {
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.KmsID = types.StringValue(gjson.Get(response, "kms").String())
	state.KmsName = types.StringValue(gjson.Get(response, "kms_name").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	externalAccounts := gjson.Get(response, "external_accounts").Array()
	if len(externalAccounts) != 0 {
		state.ExternalAccounts = utils.StringSliceJSONToSetValue(externalAccounts, diags)
	} else {
		state.ExternalAccounts = emptyOrNullSet(planned.ExternalAccounts)
	}
	state.IsVerified = types.BoolValue(gjson.Get(response, "is_verified").Bool())
	keyAdmins := gjson.Get(response, "key_admins").Array()
	if len(keyAdmins) != 0 {
		state.KeyAdmins = utils.StringSliceJSONToSetValue(keyAdmins, diags)
	} else {
		state.KeyAdmins = emptyOrNullSet(planned.KeyAdmins)
	}
	keyAdminsRoles := gjson.Get(response, "key_admins_roles").Array()
	if len(keyAdminsRoles) != 0 {
		state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(keyAdminsRoles, diags)
	} else {
		state.KeyAdminsRoles = emptyOrNullSet(planned.KeyAdminsRoles)
	}
	keyUsers := gjson.Get(response, "key_users").Array()
	if len(keyUsers) != 0 {
		state.KeyUsers = utils.StringSliceJSONToSetValue(keyUsers, diags)
	} else {
		state.KeyUsers = emptyOrNullSet(planned.KeyUsers)
	}
	keyUsersRoles := gjson.Get(response, "key_users_roles").Array()
	if len(keyUsersRoles) != 0 {
		state.KeyUsersRoles = utils.StringSliceJSONToSetValue(keyUsersRoles, diags)
	} else {
		state.KeyUsersRoles = emptyOrNullSet(planned.KeyUsersRoles)
	}
	equivalent := getPoliciesAreEqual(r.client, gjson.Get(response, "policy").String(), state.Policy.ValueString(), diags)
	if !equivalent {
		state.Policy = types.StringValue(gjson.Get(response, "policy").String())
	}
}

// emptyOrNullSet returns an empty Set of string if planned was an explicit empty set (not null), or SetNull otherwise.
// This preserves the distinction between an omitted field (null) and an explicitly cleared field ([]).
func emptyOrNullSet(planned types.Set) types.Set {
	if !planned.IsNull() {
		return types.SetValueMust(types.StringType, []attr.Value{})
	}
	return types.SetNull(types.StringType)
}

// getPoliciesAreEqual reports whether two AWS key policy JSON strings are semantically equal after normalisation.
func getPoliciesAreEqual(client *common.Client, policy string, planPolicy string, diags *diag.Diagnostics) bool {
	p, err := normalizePolicy(policy)
	if err != nil {
		client.Log.Error(err.Error())
	} else {
		policy = p
	}
	planPolicy = strings.TrimSpace(planPolicy)
	p, err = normalizePolicy(planPolicy)
	if err != nil {
		client.Log.Error(err.Error())
	} else {
		planPolicy = p
	}
	equivalent, err := policyBytesEqual([]byte(policy), []byte(planPolicy))
	if err != nil {
		msg := "Error comparing state and plan key policy'."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		client.Log.Error(details)
		diags.AddError(details, "")
		return false
	}
	return equivalent
}

// normalizePolicy marshals a JSON policy string to a canonical form, returning an empty string for nil or empty input.
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

// policyBytesEqual reports whether two JSON policy byte slices are deeply equal after unmarshalling.
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
