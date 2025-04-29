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
	_ resource.Resource              = &resourceCMDomain{}
	_ resource.ResourceWithConfigure = &resourceCMDomain{}
)

func NewResourceCMDomain() resource.Resource {
	return &resourceCMDomain{}
}

type resourceCMDomain struct {
	client *common.Client
}

func (r *resourceCMDomain) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain"
}

// Schema defines the schema for the resource.
func (r *resourceCMDomain) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"admins": schema.ListAttribute{
				Required:    true,
				Description: "List of administrators for the domain",
				PlanModifiers: []planmodifier.List{
					common.NewListUseStateForUnknown(),
				},
				ElementType: types.StringType,
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The name of the domain",
			},
			"allow_user_management": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "To allow user creation and management in the domain, set it to true. The default value is false.",
			},
			"hsm_connection_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The ID of the HSM connection. Required for HSM-anchored domains.",
			},
			"hsm_kek_label": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Optional name field for the domain KEK for an HSM-anchored domain. If not provided, a random UUID is assigned for KEK label.",
			},
			"meta_data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Optional end-user or service data stored with the domain. Should be JSON-serializable.",
			},
			"parent_ca_id": schema.StringAttribute{
				Optional:    true,
				Description: "This optional parameter is the ID or URI of the parent domain's CA. This CA is used for signing the default CA of a newly created sub-domain. The oldest CA in the parent domain is used if this value is not supplied.",
			},
			"uri": schema.StringAttribute{
				Computed: true,
			},
			"account": schema.StringAttribute{
				Computed: true,
			},
			"application": schema.StringAttribute{
				Computed: true,
			},
			"dev_account": schema.StringAttribute{
				Computed: true,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMDomain) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_domain.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMDomainTFSDK
	var payload CMDomainJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = plan.Name.ValueString()

	var admins []string
	for _, str := range plan.Admins {
		admins = append(admins, str.ValueString())
	}
	payload.Admins = admins

	if plan.AllowUserManagement.ValueBool() != types.BoolNull().ValueBool() {
		payload.AllowUserManagement = plan.AllowUserManagement.ValueBool()
	}
	if plan.HSMConnectionId.ValueString() != "" && plan.HSMConnectionId.ValueString() != types.StringNull().ValueString() {
		payload.HSMConnectionId = plan.HSMConnectionId.ValueString()
	}
	if plan.HSMKEKLabel.ValueString() != "" && plan.HSMKEKLabel.ValueString() != types.StringNull().ValueString() {
		payload.HSMKEKLabel = plan.HSMKEKLabel.ValueString()
	}
	if plan.ParentCAId.ValueString() != "" && plan.ParentCAId.ValueString() != types.StringNull().ValueString() {
		payload.ParentCAId = plan.ParentCAId.ValueString()
	}

	// Add labels to payload
	metadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = metadataPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Domain Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_DOMAIN, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating domain on CipherTrust Manager: ",
			"Could not create domain, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt ").String())
	plan.Account = types.StringValue(gjson.Get(response, "account ").String())
	plan.HSMConnectionId = types.StringValue(gjson.Get(response, "hsm_connection_id").String())
	plan.HSMKEKLabel = types.StringValue(gjson.Get(response, "hsm_kek_label").String())

	tflog.Debug(ctx, "[resource_cm_domain.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_domain.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMDomain) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMDomainTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_DOMAIN)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Domain on CipherTrust Manager: ",
			"Could not read CM Domain id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.HSMConnectionId = types.StringValue(gjson.Get(response, "hsm_connection_id").String())
	state.HSMKEKLabel = types.StringValue(gjson.Get(response, "hsm_kek_label").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt ").String())
	state.Account = types.StringValue(gjson.Get(response, "account ").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMDomain) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMDomainTFSDK
	var payload CMDomainJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.HSMKEKLabel.ValueString() != "" && plan.HSMKEKLabel.ValueString() != types.StringNull().ValueString() {
		payload.HSMKEKLabel = plan.HSMKEKLabel.ValueString()
	}
	if plan.HSMConnectionId.ValueString() != "" && plan.HSMConnectionId.ValueString() != types.StringNull().ValueString() {
		payload.HSMConnectionId = plan.HSMConnectionId.ValueString()
	}

	metadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = metadataPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_domain.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Domain Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		id,
		common.URL_DOMAIN+"/"+plan.ID.ValueString(),
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_domain.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating domain on CipherTrust Manager: ",
			"Could not update domain, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt ").String())
	plan.Account = types.StringValue(gjson.Get(response, "account ").String())
	plan.HSMConnectionId = types.StringValue(gjson.Get(response, "hsm_connection_id").String())
	plan.HSMKEKLabel = types.StringValue(gjson.Get(response, "hsm_kek_label").String())

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMDomain) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMDomainTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_DOMAIN, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_domain.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Domain",
			"Could not delete domain, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMDomain) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
