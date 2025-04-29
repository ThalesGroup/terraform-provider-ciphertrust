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
	_ resource.Resource              = &resourceCMPolicyAttachment{}
	_ resource.ResourceWithConfigure = &resourceCMPolicyAttachment{}
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

// Schema defines the schema for the resource.
func (r *resourceCMPolicyAttachment) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
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
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID for the policy to be attached.",
			},
			"principal_selector": schema.MapAttribute{
				ElementType: types.StringType,
				Required:    true,
				PlanModifiers: []planmodifier.Map{
					common.NewMapUseStateForUnknown(),
				},
				Description: "Selects which principals to apply the policy to. This can also be done using the conditions set while creating a policy.",
			},
			"jurisdiction": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Jurisdiction to which the policy applies.",
			},
			"actions": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Action attribute of an operation is a string, in the form of VerbResource e.g. CreateKey, or VerbWithResource e.g. EncryptWithKey",
				ElementType: types.StringType,
			},
			"resources": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
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
func (r *resourceCMPolicyAttachment) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_policy_attachments.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMPolicyAttachmentTFSDK
	var payload CMPolicyAttachmentJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Policy = plan.Policy.ValueString()

	// Add selectors to payload
	selectorsPayload := make(map[string]interface{})
	for k, v := range plan.PrincipalSelector.Elements() {
		selectorsPayload[k] = v.(types.String).ValueString()
	}
	payload.PrincipalSelector = selectorsPayload

	if plan.Jurisdiction.ValueString() != "" && plan.Jurisdiction.ValueString() != types.StringNull().ValueString() {
		payload.Jurisdiction = common.TrimString(plan.Jurisdiction.String())
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
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	tflog.Debug(ctx, "[resource_policy_attachments.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Create]["+id+"]")
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

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_CM_POLICY_ATTACHMENTS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_policy_attachments.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Policy Attachment on CipherTrust Manager: ",
			"Could not read Attachment for CM Policy : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())

	arrResources := (gjson.Get(response, "resources").Array())
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

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMPolicyAttachment) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Updating Policy is not supported", "Unsupported Operation")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMPolicyAttachment) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMPolicyAttachmentTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_POLICY_ATTACHMENTS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_policy_attachments.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
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
