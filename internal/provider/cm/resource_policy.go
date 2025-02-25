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
	_ resource.Resource              = &resourceCMPolicy{}
	_ resource.ResourceWithConfigure = &resourceCMPolicy{}
)

func NewResourceCMPolicy() resource.Resource {
	return &resourceCMPolicy{}
}

type resourceCMPolicy struct {
	client *common.Client
}

func (r *resourceCMPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policies"
}

// Schema defines the schema for the resource.
func (r *resourceCMPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"actions": schema.ListAttribute{
				Optional:    true,
				Description: "Action attribute of an operation is a string, in the form of VerbResource e.g. CreateKey, or VerbWithResource e.g. EncryptWithKey",
				ElementType: types.StringType,
			},
			"allow": schema.BoolAttribute{
				Optional:    true,
				Description: "Allow is the effect of the policy, either to allow the actions or to deny the actions.",
			},
			"conditions": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Conditions are rules for matching the other attributes of the operation",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"negate": schema.BoolAttribute{
							Optional: true,
						},
						"op": schema.StringAttribute{
							Optional: true,
						},
						"path": schema.StringAttribute{
							Optional: true,
						},
						"values": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
			"effect": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies the effect of the policy, either to allow or to deny.",
			},
			"include_descendant_accounts": schema.BoolAttribute{
				Optional:    true,
				Description: "When false, only the resources in the principal's account can be accessed if the policy allows it.",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "This is the name of the policy.",
			},
			"resources": schema.ListAttribute{
				Optional:    true,
				Description: "Resources is a list of URI strings, which must be in URI format.",
				ElementType: types.StringType,
			},
			"uri":        schema.StringAttribute{Computed: true},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMPolicyTFSDK
	var payload CMPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var actions []string
	for _, str := range plan.Actions {
		actions = append(actions, str.ValueString())
	}
	payload.Actions = actions

	if plan.Allow.ValueBool() != types.BoolNull().ValueBool() {
		payload.Allow = plan.Allow.ValueBool()
	}

	var conditions []CMPolicyConditionJSON
	for _, condition := range plan.Conditions {
		var conditionJSON CMPolicyConditionJSON
		if condition.Negate.ValueBool() != types.BoolNull().ValueBool() {
			conditionJSON.Negate = condition.Negate.ValueBool()
		}
		if condition.Op.ValueString() != "" && condition.Op.ValueString() != types.StringNull().ValueString() {
			conditionJSON.Op = condition.Op.ValueString()
		}
		if condition.Path.ValueString() != "" && condition.Path.ValueString() != types.StringNull().ValueString() {
			conditionJSON.Path = condition.Path.ValueString()
		}
		var values []string
		for _, str := range condition.Values {
			values = append(values, str.ValueString())
		}
		conditionJSON.Values = values

		conditions = append(conditions, conditionJSON)
	}
	payload.Conditions = conditions

	if plan.Effect.ValueString() != "" && plan.Effect.ValueString() != types.StringNull().ValueString() {
		payload.Effect = plan.Effect.ValueString()
	}

	if plan.IncludeDescendantAccounts.ValueBool() != types.BoolNull().ValueBool() {
		payload.IncludeDescendantAccounts = plan.IncludeDescendantAccounts.ValueBool()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	var resources []string
	for _, str := range plan.Resources {
		resources = append(resources, str.ValueString())
	}
	payload.Resources = resources

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		plan.Name.ValueString(),
		common.URL_CM_POLICIES,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating policy on CipherTrust Manager: ",
			"Could not create policy "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	tflog.Debug(ctx, "[resource_policy.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMPolicyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_POLICIES)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Policy on CipherTrust Manager: ",
			"Could not read CM Policy : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	arrResources := gjson.Get(response, "resources").Array()
	var resources []types.String
	for _, resource := range arrResources {
		resources = append(resources, types.StringValue(resource.String()))
	}
	state.Resources = resources

	arrActions := gjson.Get(response, "actions").Array()
	var actions []types.String
	for _, action := range arrActions {
		actions = append(actions, types.StringValue(action.String()))
	}
	state.Actions = actions

	state.Allow = types.BoolValue(gjson.Get(response, "allow").Bool())
	state.Effect = types.StringValue(gjson.Get(response, "effect").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Updating Policy is not supported", "Unsupported Operation")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_POLICIES, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CM Policy",
			"Could not delete policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
