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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
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
				ElementType: types.StringType,
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the domain",
			},
			"allow_user_management": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "To allow user creation and management in the domain, set it to true. The default value is false.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"hsm_connection_id": schema.StringAttribute{
				Optional:    true,
				Description: "The ID of the HSM connection. Required for HSM-anchored domains.",
			},
			"hsm_kek_label": schema.StringAttribute{
				Optional:    true,
				Description: "Optional name field for the domain KEK for an HSM-anchored domain. If not provided, a random UUID is assigned for KEK label.",
			},
			"meta_data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the domain. Should be JSON-serializable.",
			},
			"parent_ca_id": schema.StringAttribute{
				Optional:    true,
				Description: "This optional parameter is the ID or URI of the parent domain's CA. This CA is used for signing the default CA of a newly created sub-domain. The oldest CA in the parent domain is used if this value is not supplied.",
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
			"application": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
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

	if !plan.AllowUserManagement.IsNull() && !plan.AllowUserManagement.IsUnknown() {
		val := plan.AllowUserManagement.ValueBool()
		payload.AllowUserManagement = &val
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
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.AllowUserManagement = types.BoolValue(gjson.Get(response, "allow_user_management").Bool())

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionIdResp := gjson.Get(response, "hsm_connection_id").String()
	if hsmConnectionIdResp == "" {
		plan.HSMConnectionId = types.StringNull()
	} else {
		plan.HSMConnectionId = types.StringValue(hsmConnectionIdResp)
	}

	hsmKekLabelResp := gjson.Get(response, "hsm_kek_label").String()
	if hsmKekLabelResp == "" {
		plan.HSMKEKLabel = types.StringNull()
	} else {
		plan.HSMKEKLabel = types.StringValue(hsmKekLabelResp)
	}

	parentCaIdResp := gjson.Get(response, "parent_ca_id").String()
	if parentCaIdResp == "" {
		plan.ParentCAId = types.StringNull()
	} else {
		plan.ParentCAId = types.StringValue(parentCaIdResp)
	}

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

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionId := gjson.Get(response, "hsm_connection_id").String()
	if hsmConnectionId == "" {
		state.HSMConnectionId = types.StringNull()
	} else {
		state.HSMConnectionId = types.StringValue(hsmConnectionId)
	}

	hsmKekLabel := gjson.Get(response, "hsm_kek_label").String()
	if hsmKekLabel == "" {
		state.HSMKEKLabel = types.StringNull()
	} else {
		state.HSMKEKLabel = types.StringValue(hsmKekLabel)
	}

	parentCaId := gjson.Get(response, "parent_ca_id").String()
	if parentCaId == "" {
		state.ParentCAId = types.StringNull()
	} else {
		state.ParentCAId = types.StringValue(parentCaId)
	}

	state.AllowUserManagement = types.BoolValue(gjson.Get(response, "allow_user_management").Bool())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())

	// Read admins list
	adminsResult := gjson.Get(response, "admins")
	if adminsResult.Exists() && adminsResult.IsArray() {
		var admins []types.String
		for _, admin := range adminsResult.Array() {
			admins = append(admins, types.StringValue(admin.String()))
		}
		state.Admins = admins
	}

	// Read meta_data map
	metaResult := gjson.Get(response, "meta")
	if metaResult.Exists() {
		metaMap := make(map[string]types.String)
		metaResult.ForEach(func(key, value gjson.Result) bool {
			metaMap[key.String()] = types.StringValue(value.String())
			return true
		})
		mapValue, diags2 := types.MapValueFrom(ctx, types.StringType, metaMap)
		if diags2.HasError() {
			resp.Diagnostics.Append(diags2...)
		} else {
			state.Meta = mapValue
		}
	}

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
	var state CMDomainTFSDK
	var payload CMDomainJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state to preserve computed fields
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if there are actual changes to user-controlled fields
	hasChanges := false

	// Check HSM fields
	if plan.HSMKEKLabel.ValueString() != state.HSMKEKLabel.ValueString() {
		hasChanges = true
	}
	if plan.HSMConnectionId.ValueString() != state.HSMConnectionId.ValueString() {
		hasChanges = true
	}

	// Check metadata
	if !plan.Meta.Equal(state.Meta) {
		hasChanges = true
	}

	// Check admins list
	if len(plan.Admins) != len(state.Admins) {
		hasChanges = true
	} else {
		for i := range plan.Admins {
			if plan.Admins[i].ValueString() != state.Admins[i].ValueString() {
				hasChanges = true
				break
			}
		}
	}

	// If no changes detected, preserve existing state and return
	if !hasChanges {
		tflog.Debug(ctx, "[resource_cm_domain.go -> Update] No changes detected, preserving state")
		diags = resp.State.Set(ctx, state)
		resp.Diagnostics.Append(diags...)
		return
	}

	// Build payload only if there are changes
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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_domain.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Domain Update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_DOMAIN, payloadJSON, "updatedAt")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_domain.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating domain on CipherTrust Manager: ",
			"Could not update domain, unexpected error: "+err.Error(),
		)
		return
	}

	// Read back the domain to get all computed fields with current values
	readResponse, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_DOMAIN)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_domain.go -> Update -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Domain on CipherTrust Manager after update: ",
			"Could not read CM Domain id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Update plan with current computed values from API
	plan.ID = types.StringValue(gjson.Get(readResponse, "id").String())
	plan.URI = types.StringValue(gjson.Get(readResponse, "uri").String())
	plan.Account = types.StringValue(gjson.Get(readResponse, "account").String())
	plan.Application = types.StringValue(gjson.Get(readResponse, "application").String())
	plan.DevAccount = types.StringValue(gjson.Get(readResponse, "devAccount").String())
	plan.CreatedAt = types.StringValue(gjson.Get(readResponse, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(readResponse, "updatedAt").String())
	plan.AllowUserManagement = types.BoolValue(gjson.Get(readResponse, "allow_user_management").Bool())

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionIdUpdate := gjson.Get(readResponse, "hsm_connection_id").String()
	if hsmConnectionIdUpdate == "" {
		plan.HSMConnectionId = types.StringNull()
	} else {
		plan.HSMConnectionId = types.StringValue(hsmConnectionIdUpdate)
	}

	hsmKekLabelUpdate := gjson.Get(readResponse, "hsm_kek_label").String()
	if hsmKekLabelUpdate == "" {
		plan.HSMKEKLabel = types.StringNull()
	} else {
		plan.HSMKEKLabel = types.StringValue(hsmKekLabelUpdate)
	}

	parentCaIdUpdate := gjson.Get(readResponse, "parent_ca_id").String()
	if parentCaIdUpdate == "" {
		plan.ParentCAId = types.StringNull()
	} else {
		plan.ParentCAId = types.StringValue(parentCaIdUpdate)
	}

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
