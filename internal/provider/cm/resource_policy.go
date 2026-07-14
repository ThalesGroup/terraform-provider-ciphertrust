package cm

import (
	"strings"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &resourceCMPolicy{}
	_ resource.ResourceWithConfigure      = &resourceCMPolicy{}
	_ resource.ResourceWithValidateConfig = &resourceCMPolicy{}
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

func (r *resourceCMPolicy) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_policies", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CipherTrust Manager admin policy: an allow/deny rule that authorizes a set of actions (e.g. CreateKey, EncryptWithKey) with optional conditional clauses. **Only available on CipherTrust Manager — not supported on CDSPaaS, where authorization is managed by the platform.**",
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
				Computed:    true,
				Default:     stringdefault.StaticString("deny"),
				Description: "Specifies the effect of the policy. Possible values are 'allow', 'deny', 'obligate_on_allow', and 'obligate_on_deny'. Default is 'deny'.",
			},
			"include_descendant_accounts": schema.BoolAttribute{
				Optional:    true,
				Description: "When false, only the resources in the principal's account can be accessed if the policy allows it.",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) This is the name of the policy.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"resources": schema.ListAttribute{
				Optional:    true,
				Description: "Resources is a list of URI strings, which must be in URI format.",
				ElementType: types.StringType,
			},
			"uri": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Create]["+id+"]")

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

	if !plan.Allow.IsNull() && !plan.Allow.IsUnknown() {
		v := plan.Allow.ValueBool()
		payload.Allow = &v
	}

	var conditions []CMPolicyConditionJSON
	for _, condition := range plan.Conditions {
		var conditionJSON CMPolicyConditionJSON
		if !condition.Negate.IsNull() && !condition.Negate.IsUnknown() {
			v := condition.Negate.ValueBool()
			conditionJSON.Negate = &v
		}
		if !condition.Op.IsNull() && !condition.Op.IsUnknown() {
			conditionJSON.Op = condition.Op.ValueString()
		}
		if !condition.Path.IsNull() && !condition.Path.IsUnknown() {
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

	if !plan.Effect.IsNull() && !plan.Effect.IsUnknown() {
		v := plan.Effect.ValueString()
		payload.Effect = &v
	}

	if !plan.IncludeDescendantAccounts.IsNull() && !plan.IncludeDescendantAccounts.IsUnknown() {
		v := plan.IncludeDescendantAccounts.ValueBool()
		payload.IncludeDescendantAccounts = &v
	}

	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		v := plan.Name.ValueString()
		payload.Name = &v
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
		id,
		common.URL_CM_POLICIES,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating policy on CipherTrust Manager: ",
			"Could not create policy, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_policy.go -> Create Output]["+response+"]")

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	// effect is Optional+Computed with Default="deny" — always hydrate.
	if r := gjson.Get(response, "effect"); r.Exists() {
		plan.Effect = types.StringValue(r.String())
	} else {
		plan.Effect = types.StringNull()
	}

	// Optional-only fields: only hydrate from API response when user configured them.
	// CM may return server-assigned defaults; setting them when plan had null causes
	// a plan-consistency error ("was null, but now <value>").
	if !plan.Name.IsNull() {
		if r := gjson.Get(response, "name"); r.Exists() {
			plan.Name = types.StringValue(r.String())
		} else {
			plan.Name = types.StringNull()
		}
	}

	if !plan.Allow.IsNull() {
		if r := gjson.Get(response, "allow"); r.Exists() {
			plan.Allow = types.BoolValue(r.Bool())
		} else {
			plan.Allow = types.BoolNull()
		}
	}

	if !plan.IncludeDescendantAccounts.IsNull() {
		if r := gjson.Get(response, "include_descendant_accounts"); r.Exists() {
			plan.IncludeDescendantAccounts = types.BoolValue(r.Bool())
		} else {
			plan.IncludeDescendantAccounts = types.BoolNull()
		}
	}

	if plan.Resources != nil {
		rResources := gjson.Get(response, "resources")
		if !rResources.Exists() {
			plan.Resources = nil
		} else {
			var respResources []types.String
			for _, res := range rResources.Array() {
				respResources = append(respResources, types.StringValue(res.String()))
			}
			plan.Resources = respResources
		}
	}

	if plan.Actions != nil {
		rActions := gjson.Get(response, "actions")
		if !rActions.Exists() {
			plan.Actions = nil
		} else {
			var respActions []types.String
			for _, act := range rActions.Array() {
				respActions = append(respActions, types.StringValue(act.String()))
			}
			plan.Actions = respActions
		}
	}

	if plan.Conditions != nil {
		rConditions := gjson.Get(response, "conditions")
		if !rConditions.Exists() {
			plan.Conditions = nil
		} else {
			var respConditions []CMPolicyConditionTFSDK
			for _, c := range rConditions.Array() {
				var cond CMPolicyConditionTFSDK
				if nr := c.Get("negate"); nr.Exists() {
					cond.Negate = types.BoolValue(nr.Bool())
				} else {
					cond.Negate = types.BoolNull()
				}
				if or_ := c.Get("op"); or_.Exists() {
					cond.Op = types.StringValue(or_.String())
				} else {
					cond.Op = types.StringNull()
				}
				if pr := c.Get("path"); pr.Exists() {
					cond.Path = types.StringValue(pr.String())
				} else {
					cond.Path = types.StringNull()
				}
				rVals := c.Get("values")
				if !rVals.Exists() {
					cond.Values = nil
				} else {
					var vals []types.String
					for _, v := range rVals.Array() {
						vals = append(vals, types.StringValue(v.String()))
					}
					cond.Values = vals
				}
				respConditions = append(respConditions, cond)
			}
			plan.Conditions = respConditions
		}
	}

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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_POLICIES)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Read]["+id+"]")
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"Policy Not Found",
				"Policy "+state.ID.ValueString()+" was not found on CipherTrust Manager (HTTP 404). "+
					"It may have been deleted outside of Terraform. Removing it from state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading CM Policy on CipherTrust Manager: ",
			"Could not read CM Policy: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	// effect is Optional+Computed with Default="deny" — always hydrate unconditionally.
	if r := gjson.Get(response, "effect"); r.Exists() {
		state.Effect = types.StringValue(r.String())
	} else {
		state.Effect = types.StringNull()
	}

	// Optional-only fields: only hydrate when prior state is non-null (i.e. user configured
	// the field). CM may return server-assigned defaults; overwriting state when the user
	// never configured the field creates perpetual drift (state=<value> vs config=null).
	if !state.Name.IsNull() {
		if r := gjson.Get(response, "name"); r.Exists() {
			state.Name = types.StringValue(r.String())
		} else {
			state.Name = types.StringNull()
		}
	}

	if !state.Allow.IsNull() {
		if r := gjson.Get(response, "allow"); r.Exists() {
			state.Allow = types.BoolValue(r.Bool())
		} else {
			state.Allow = types.BoolNull()
		}
	}

	if !state.IncludeDescendantAccounts.IsNull() {
		if r := gjson.Get(response, "include_descendant_accounts"); r.Exists() {
			state.IncludeDescendantAccounts = types.BoolValue(r.Bool())
		} else {
			state.IncludeDescendantAccounts = types.BoolNull()
		}
	}

	if state.Resources != nil {
		rResources := gjson.Get(response, "resources")
		if !rResources.Exists() {
			state.Resources = nil
		} else {
			var respResources []types.String
			for _, res := range rResources.Array() {
				respResources = append(respResources, types.StringValue(res.String()))
			}
			state.Resources = respResources
		}
	}

	if state.Actions != nil {
		rActions := gjson.Get(response, "actions")
		if !rActions.Exists() {
			state.Actions = nil
		} else {
			var respActions []types.String
			for _, act := range rActions.Array() {
				respActions = append(respActions, types.StringValue(act.String()))
			}
			state.Actions = respActions
		}
	}

	if state.Conditions != nil {
		rConditions := gjson.Get(response, "conditions")
		if !rConditions.Exists() {
			state.Conditions = nil
		} else {
			var respConditions []CMPolicyConditionTFSDK
			for _, c := range rConditions.Array() {
				var cond CMPolicyConditionTFSDK
				if nr := c.Get("negate"); nr.Exists() {
					cond.Negate = types.BoolValue(nr.Bool())
				} else {
					cond.Negate = types.BoolNull()
				}
				if or_ := c.Get("op"); or_.Exists() {
					cond.Op = types.StringValue(or_.String())
				} else {
					cond.Op = types.StringNull()
				}
				if pr := c.Get("path"); pr.Exists() {
					cond.Path = types.StringValue(pr.String())
				} else {
					cond.Path = types.StringNull()
				}
				rVals := c.Get("values")
				if !rVals.Exists() {
					cond.Values = nil
				} else {
					var vals []types.String
					for _, v := range rVals.Array() {
						vals = append(vals, types.StringValue(v.String()))
					}
					cond.Values = vals
				}
				respConditions = append(respConditions, cond)
			}
			state.Conditions = respConditions
		}
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy.go -> Update]["+id+"]")

	var plan CMPolicyTFSDK
	var state CMPolicyTFSDK

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var payload CMPolicyJSON

	if len(plan.Actions) > 0 {
		var actions []string
		for _, str := range plan.Actions {
			actions = append(actions, str.ValueString())
		}
		payload.Actions = actions
	}

	if !plan.Allow.IsNull() && !plan.Allow.IsUnknown() {
		v := plan.Allow.ValueBool()
		payload.Allow = &v
	}

	if len(plan.Conditions) > 0 {
		var conditions []CMPolicyConditionJSON
		for _, condition := range plan.Conditions {
			var conditionJSON CMPolicyConditionJSON
			if !condition.Negate.IsNull() && !condition.Negate.IsUnknown() {
				v := condition.Negate.ValueBool()
				conditionJSON.Negate = &v
			}
			if !condition.Op.IsNull() && !condition.Op.IsUnknown() {
				conditionJSON.Op = condition.Op.ValueString()
			}
			if !condition.Path.IsNull() && !condition.Path.IsUnknown() {
				conditionJSON.Path = condition.Path.ValueString()
			}
			var values []string
			for _, v := range condition.Values {
				values = append(values, v.ValueString())
			}
			conditionJSON.Values = values
			conditions = append(conditions, conditionJSON)
		}
		payload.Conditions = conditions
	}

	if !plan.Effect.IsNull() && !plan.Effect.IsUnknown() {
		v := plan.Effect.ValueString()
		payload.Effect = &v
	}

	if !plan.IncludeDescendantAccounts.IsNull() && !plan.IncludeDescendantAccounts.IsUnknown() {
		v := plan.IncludeDescendantAccounts.ValueBool()
		payload.IncludeDescendantAccounts = &v
	}

	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		v := plan.Name.ValueString()
		payload.Name = &v
	}

	if len(plan.Resources) > 0 {
		var resources []string
		for _, str := range plan.Resources {
			resources = append(resources, str.ValueString())
		}
		payload.Resources = resources
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError("Invalid data input: Policy Update", err.Error())
		return
	}

	response, err := r.client.UpdateDataV2(ctx, state.ID.ValueString(), common.URL_CM_POLICIES, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Updating CipherTrust Policy",
			"Could not update policy "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	// effect is Optional+Computed with Default="deny" — always hydrate.
	if r := gjson.Get(response, "effect"); r.Exists() {
		plan.Effect = types.StringValue(r.String())
	} else {
		plan.Effect = types.StringNull()
	}

	// Optional-only fields: only hydrate when the new plan (desired config) is non-null.
	// This prevents CM's server defaults from overwriting null plan values and causing drift.
	if !plan.Name.IsNull() {
		if r := gjson.Get(response, "name"); r.Exists() {
			plan.Name = types.StringValue(r.String())
		} else {
			plan.Name = types.StringNull()
		}
	}

	if !plan.Allow.IsNull() {
		if r := gjson.Get(response, "allow"); r.Exists() {
			plan.Allow = types.BoolValue(r.Bool())
		} else {
			plan.Allow = types.BoolNull()
		}
	}

	if !plan.IncludeDescendantAccounts.IsNull() {
		if r := gjson.Get(response, "include_descendant_accounts"); r.Exists() {
			plan.IncludeDescendantAccounts = types.BoolValue(r.Bool())
		} else {
			plan.IncludeDescendantAccounts = types.BoolNull()
		}
	}

	if plan.Resources != nil {
		rResources := gjson.Get(response, "resources")
		if !rResources.Exists() {
			plan.Resources = nil
		} else {
			var respResources []types.String
			for _, res := range rResources.Array() {
				respResources = append(respResources, types.StringValue(res.String()))
			}
			plan.Resources = respResources
		}
	}

	if plan.Actions != nil {
		rActions := gjson.Get(response, "actions")
		if !rActions.Exists() {
			plan.Actions = nil
		} else {
			var respActions []types.String
			for _, act := range rActions.Array() {
				respActions = append(respActions, types.StringValue(act.String()))
			}
			plan.Actions = respActions
		}
	}

	if plan.Conditions != nil {
		rConditions := gjson.Get(response, "conditions")
		if !rConditions.Exists() {
			plan.Conditions = nil
		} else {
			var respConditions []CMPolicyConditionTFSDK
			for _, c := range rConditions.Array() {
				var cond CMPolicyConditionTFSDK
				if nr := c.Get("negate"); nr.Exists() {
					cond.Negate = types.BoolValue(nr.Bool())
				} else {
					cond.Negate = types.BoolNull()
				}
				if or_ := c.Get("op"); or_.Exists() {
					cond.Op = types.StringValue(or_.String())
				} else {
					cond.Op = types.StringNull()
				}
				if pr := c.Get("path"); pr.Exists() {
					cond.Path = types.StringValue(pr.String())
				} else {
					cond.Path = types.StringNull()
				}
				rVals := c.Get("values")
				if !rVals.Exists() {
					cond.Values = nil
				} else {
					var vals []types.String
					for _, v := range rVals.Array() {
						vals = append(vals, types.StringValue(v.String()))
					}
					cond.Values = vals
				}
				respConditions = append(respConditions, cond)
			}
			plan.Conditions = respConditions
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy.go -> Delete]["+state.ID.ValueString()+"]")
			return
		}
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
