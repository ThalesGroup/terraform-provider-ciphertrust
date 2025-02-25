package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	// "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	// "github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

var (
	_ resource.Resource              = &resourceLDTGroupCommSvc{}
	_ resource.ResourceWithConfigure = &resourceLDTGroupCommSvc{}
)

func NewResourceLDTGroupCommSvc() resource.Resource {
	return &resourceLDTGroupCommSvc{}
}

type resourceLDTGroupCommSvc struct {
	client *common.Client
}

func (r *resourceLDTGroupCommSvc) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_ldtgroupcomms"
}

// Schema defines the schema for the resource.
func (r *resourceLDTGroupCommSvc) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the LDT group communication service. This name will be visible on the CipherTrust Manager.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description to identify the LDT group communication service.",
			},
			"client_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of identifiers of clients to be associated with the LDT group communication service. This identifier can be the Name, ID (a UUIDv4), URI, or slug of the client.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceLDTGroupCommSvc) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_ldtgroupcomms.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan, state LDTGroupCommSvcTFSDK
	var payload LDTGroupCommSvcJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.String())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}

	// var clients []string
	// for _, client := range plan.ClientList {
	// 	clients = append(clients, client.ValueString())
	// }
	// payload.ClientList = clients

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: LDT Group Communication Service Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_LDT_GROUP_COMM_SVC, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating LDT Group Communication Service on CipherTrust Manager: ",
			"Could not create LDT Group Communication Service, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)
	LdtGroupAddRemoveClient(r, ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceLDTGroupCommSvc) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state LDTGroupCommSvcTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_LDT_GROUP_COMM_SVC)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading LDT comm group on CipherTrust Manager: ",
			"Could not read LDT comm group id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_ldtgroupcomms.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceLDTGroupCommSvc) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state LDTGroupCommSvcTFSDK

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

	LdtGroupUpdate(r, ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	LdtGroupAddRemoveClient(r, ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

func LdtGroupUpdate(r *resourceLDTGroupCommSvc, ctx context.Context, plan *LDTGroupCommSvcTFSDK, state *LDTGroupCommSvcTFSDK, diag *diag.Diagnostics) {
	var payload CTEClientGroupJSON

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Update]["+plan.ID.ValueString()+"]")
		diag.AddError(
			"[resource_cte_clientgroup.go -> ClientGroupUpdate]\nInvalid data input: CTE Client Group Update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_LDT_GROUP_COMM_SVC, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Update]["+plan.ID.ValueString()+"]")
		diag.AddError(
			"[resource_cte_clientgroup.go -> ClientGroupUpdate]\nError updating CTE Client Group on CipherTrust Manager: ",
			"Could not update CTE Client Group, unexpected error: "+err.Error(),
		)
		return
	}

}

func LdtGroupAddRemoveClient(r *resourceLDTGroupCommSvc, ctx context.Context, plan *LDTGroupCommSvcTFSDK, state *LDTGroupCommSvcTFSDK, diag *diag.Diagnostics) {
	var payload CTEClientGroupJSON
	id := uuid.New().String()

	stateSet := make(map[string]bool)
	for _, s := range state.ClientList {
		stateSet[s.String()] = true
	}

	planSet := make(map[string]bool)
	for _, s := range plan.ClientList {
		planSet[s.String()] = true
	}

	// Find added elements
	addedList := []string{}
	for k := range planSet {
		if !stateSet[k] {
			addedList = append(addedList, common.TrimString(k))
		}
	}
	// Find removed elements
	removedList := []string{}
	for k := range stateSet {
		if !planSet[k] {
			removedList = append(removedList, common.TrimString(k))
		}
	}

	if len(removedList) > 0 {
		payload.ClientList = removedList
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> delete-client]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"[resource_cte_clientgroup.go -> ClientGroupAddClient]\nInvalid data input: CTE Client Group Add Clients",
				err.Error(),
			)
			return
		}
		_, err = r.client.UpdateData(
			ctx,
			plan.ID.ValueString()+"/clients/delete/",
			common.URL_LDT_GROUP_COMM_SVC,
			payloadJSON,
			"id")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"Error deleting clients list from the LDT Group Communication Service on CipherTrust Manager: ",
				"Could not delete clients list from the LDT Group Communication Service, unexpected error: "+err.Error()+fmt.Sprintf("%s", removedList),
			)
			return
		}
	}
	if len(addedList) > 0 {
		payload.ClientList = addedList
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"[resource_cte_clientgroup.go -> ClientGroupAddClient]\nInvalid data input: CTE Client Group Add Clients",
				err.Error(),
			)
			return
		}
		_, err = r.client.PostDataV2(
			ctx,
			id,
			common.URL_LDT_GROUP_COMM_SVC+"/"+plan.ID.ValueString()+"/clients",
			payloadJSON,
		)

		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"[resource_cte_clientgroup.go -> ClientGroupAddCLient]\nError attaching client list to LDT Group Communication Service on CipherTrust Manager: ",
				"Could not attach client list to LDT Group Communication Service, unexpected error: "+err.Error()+fmt.Sprintf("%s", addedList),
			)
			return
		}
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceLDTGroupCommSvc) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state LDTGroupCommSvcTFSDK
	var payload CTEClientGroupJSON

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	removedList := []string{}
	for _, k := range state.ClientList {
		removedList = append(removedList, common.TrimString(k.String()))

	}
	payload.ClientList = removedList

	//Deleting Client List before deleting LDT comm group
	if len(removedList) > 0 {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> delete-client]["+state.ID.ValueString()+"]")
			diags.AddError(
				"[resource_cte_clientgroup.go -> ClientGroupDeleteClient]\nInvalid data input: CTE Client Group Add Clients",
				err.Error(),
			)
			return
		}
		_, err = r.client.UpdateData(
			ctx,
			state.ID.ValueString()+"/clients/delete/",
			common.URL_LDT_GROUP_COMM_SVC,
			payloadJSON,
			"id")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+state.ID.ValueString()+"]")
			diags.AddError(
				"Error deleting clients list from the LDT Group Communication Service on CipherTrust Manager: ",
				"Could not delete clients list before deleting LDT Group Communication Service, unexpected error: "+err.Error()+fmt.Sprintf("%s", removedList),
			)
			return
		}
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_LDT_GROUP_COMM_SVC, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_ldtgroupcomms.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting LDT Group Communication Service",
			"Could not delete LDT Group Communication Service, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceLDTGroupCommSvc) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
