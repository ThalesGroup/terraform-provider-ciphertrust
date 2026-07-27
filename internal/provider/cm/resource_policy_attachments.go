package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &resourceCMPolicyAttachment{}
	_ resource.ResourceWithConfigure      = &resourceCMPolicyAttachment{}
	_ resource.ResourceWithValidateConfig = &resourceCMPolicyAttachment{}
)

func NewResourceCMPolicyAttachment() resource.Resource {
	return &resourceCMPolicyAttachment{}
}

type resourceCMPolicyAttachment struct {
	client *common.Client
}

func (r *resourceCMPolicyAttachment) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_attachments"
}

func (r *resourceCMPolicyAttachment) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_policy_attachments", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMPolicyAttachment) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Attaches a CipherTrust Manager admin policy to a set of principals (matched by principal_selector), optionally scoped to a jurisdiction. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of this resource.",
			},
			"policy": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "(Immutable) The ID for the policy to be attached. Changing this forces a new resource.",
			},
			"principal_selector": schema.MapAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "(Immutable) Selects which principals to apply the policy to. This can also be done using the conditions set while creating a policy.",
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
			"jurisdiction": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) Jurisdiction to which the policy applies.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"actions": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) Action attribute of an operation is a string, in the form of VerbResource e.g. CreateKey, or VerbWithResource e.g. EncryptWithKey",
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"resources": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) Resources is a list of URI strings, which must be in URI format.",
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "A human readable unique identifier of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the resource was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPolicyAttachment) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy_attachments.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Create]["+id+"]")

	var plan CMPolicyAttachmentTFSDK
	var payload CMPolicyAttachmentJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Policy = plan.Policy.ValueString()

	selectorsPayload := make(map[string]interface{})
	for k, v := range plan.PrincipalSelector.Elements() {
		selectorsPayload[k] = v.(types.String).ValueString()
	}
	payload.PrincipalSelector = selectorsPayload

	if !plan.Jurisdiction.IsNull() && !plan.Jurisdiction.IsUnknown() {
		payload.Jurisdiction = plan.Jurisdiction.ValueString()
	}

	if !plan.Actions.IsNull() && !plan.Actions.IsUnknown() {
		var actions []string
		for _, elem := range plan.Actions.Elements() {
			actions = append(actions, elem.(types.String).ValueString())
		}
		payload.Actions = actions
	}

	if !plan.Resources.IsNull() && !plan.Resources.IsUnknown() {
		var resources []string
		for _, elem := range plan.Resources.Elements() {
			resources = append(resources, elem.(types.String).ValueString())
		}
		payload.Resources = resources
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy_attachments.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Policy Attachment",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CM_POLICY_ATTACHMENTS,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy_attachments.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error attaching to policy on CipherTrust Manager: ",
			"Could not attach to policy "+plan.Policy.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_policy_attachments.go -> Create Output]["+response+"]")

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	// policy, principal_selector, and jurisdiction are kept from plan (user-set values).
	// Reading them from the API response would override user values with CM-transformed
	// forms (e.g. short name → full URI) causing plan consistency errors.

	// actions: only hydrate from API when user explicitly set them in config
	// (plan is non-null, non-unknown). CM propagates policy actions for unconfigured
	// attachments — hydrating those would cause perpetual drift on subsequent plans.
	// If the API returns empty or omits the field entirely, keep the plan's value to
	// avoid "element has vanished" plan-consistency errors (CM POST responses may omit
	// these fields even when they were accepted).
	if plan.Actions.IsUnknown() {
		plan.Actions = types.ListNull(types.StringType)
	} else if !plan.Actions.IsNull() {
		rActions := gjson.Get(response, "actions")
		if rActions.Exists() {
			actArr := rActions.Array()
			if len(actArr) > 0 {
				actElems := make([]attr.Value, len(actArr))
				for i, a := range actArr {
					actElems[i] = types.StringValue(a.String())
				}
				actList, diags3 := types.ListValue(types.StringType, actElems)
				resp.Diagnostics.Append(diags3...)
				if resp.Diagnostics.HasError() {
					return
				}
				plan.Actions = actList
			}
			// else: API returned empty array; keep plan.Actions
		}
		// else: API omitted the field; keep plan.Actions
	}

	// resources: same guard as actions.
	if plan.Resources.IsUnknown() {
		plan.Resources = types.ListNull(types.StringType)
	} else if !plan.Resources.IsNull() {
		rResources := gjson.Get(response, "resources")
		if rResources.Exists() {
			resArr := rResources.Array()
			if len(resArr) > 0 {
				resElems := make([]attr.Value, len(resArr))
				for i, res := range resArr {
					resElems[i] = types.StringValue(res.String())
				}
				resList, diags4 := types.ListValue(types.StringType, resElems)
				resp.Diagnostics.Append(diags4...)
				if resp.Diagnostics.HasError() {
					return
				}
				plan.Resources = resList
			}
			// else: API returned empty array; keep plan.Resources
		}
		// else: API omitted the field; keep plan.Resources
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMPolicyAttachment) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMPolicyAttachmentTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy_attachments.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_POLICY_ATTACHMENTS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy_attachments.go -> Read]["+id+"]")
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"Policy Attachments Not Found — State Preserved",
				"The Policy Attachments resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading CM Policy Attachment on CipherTrust Manager: ",
			"Could not read Attachment for CM Policy: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	// policy is immutable and CM transforms the identifier to an internal URI format.
	// Reading from the API would cause perpetual drift (user sets "name", API returns URI).
	// Preserve state.Policy unconditionally — ImmutableString() prevents TF-side changes.

	psResult := gjson.Get(response, "principalSelector")
	if psResult.Exists() {
		psRaw := psResult.Map()
		psElems := make(map[string]attr.Value, len(psRaw))
		for k, v := range psRaw {
			psElems[k] = types.StringValue(v.String())
		}
		psMap, diags2 := types.MapValue(types.StringType, psElems)
		resp.Diagnostics.Append(diags2...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.PrincipalSelector = psMap
	} else {
		tflog.Warn(ctx, "[resource_policy_attachments.go -> Read]["+id+"] principalSelector absent from CM GET response; preserving prior state value to avoid silent drift masking")
	}

	// jurisdiction: CM auto-assigns even when unset; only hydrate when state already
	// holds a value (user-configured) to avoid perpetual drift on unconfigured fields.
	if rJuris := gjson.Get(response, "jurisdiction"); rJuris.Exists() && !state.Jurisdiction.IsNull() {
		state.Jurisdiction = types.StringValue(rJuris.String())
	} else if !rJuris.Exists() {
		state.Jurisdiction = types.StringNull()
	}

	// actions: CM may return empty-array even when actions were stored (the POST response
	// omits them and the GET may also return []). Only update state when the API returns
	// a non-empty array so we don't trigger perpetual drift for user-configured fields.
	// State is preserved when API returns empty or omits the field entirely.
	rActions := gjson.Get(response, "actions")
	if actArr := rActions.Array(); len(actArr) > 0 && !state.Actions.IsNull() {
		actElems := make([]attr.Value, len(actArr))
		for i, a := range actArr {
			actElems[i] = types.StringValue(a.String())
		}
		actList, diags3 := types.ListValue(types.StringType, actElems)
		resp.Diagnostics.Append(diags3...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Actions = actList
	}
	// else: preserve state.Actions (covers empty-array or absent cases)

	// resources: same guard as actions.
	rResources := gjson.Get(response, "resources")
	if resArr := rResources.Array(); len(resArr) > 0 && !state.Resources.IsNull() {
		resElems := make([]attr.Value, len(resArr))
		for i, res := range resArr {
			resElems[i] = types.StringValue(res.String())
		}
		resList, diags4 := types.ListValue(types.StringType, resElems)
		resp.Diagnostics.Append(diags4...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Resources = resList
	}
	// else: preserve state.Resources (covers empty-array or absent cases)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPolicyAttachment) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy_attachments.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_policy_attachment does not support updates. Delete and recreate this resource to change any field.",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPolicyAttachment) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMPolicyAttachmentTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_POLICY_ATTACHMENTS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy_attachments.go -> Delete]["+state.ID.ValueString()+"]")
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CM Policy Attachment",
			"Could not delete policy attachment, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMPolicyAttachment) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
