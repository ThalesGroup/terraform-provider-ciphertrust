package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEClientGroup{}
	_ resource.ResourceWithConfigure = &resourceCTEClientGroup{}
)

func NewResourceCTEClientGroup() resource.Resource {
	return &resourceCTEClientGroup{}
}

type resourceCTEClientGroup struct {
	client *common.Client
}

func (r *resourceCTEClientGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_group"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClientGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of a CTE client group to be generated on successful creation of Client",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cluster_type": schema.StringAttribute{
				Required:    true,
				Description: "Cluster type of the ClientGroup, valid values are NON-CLUSTER and HDFS.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"NON-CLUSTER",
						"HDFS"}...),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the ClientGroup.",
			},
			"communication_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the File System communication is enabled.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of ClientGroup.",
			},
			"ldt_designated_primary_set": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the Designated Primary Set.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Description: "User supplied password if password_creation_method is MANUAL. The password MUST be minimum 8 characters and MUST contain one alphabet, one number, and one of the !@#$%^&*(){}[] special characters.",
			},
			"password_creation_method": schema.StringAttribute{
				Optional:    true,
				Description: "Password creation method, GENERATE or MANUAL.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"GENERATE",
						"MANUAL"}...),
				},
			},
			"profile_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the client group profile that is used to schedule custom configuration for logger, logging, and Quality of Service (QoS).",
			},
			"op_type": schema.StringAttribute{
				Optional:    true,
				Description: "Operation specifying weather to remove or add the provided client list to the GroupComm Service being updated.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"update",
						"auth-binaries",
						"update-password",
						"reset-password",
						"remove-client",
						"add-client",
						"ldt-pause"}...),
				},
			},
			// Update the Client Group Attributes
			"client_locked": schema.BoolAttribute{
				Optional:    true,
				Description: "Is FS Agent locked? Enables locking the configuration of the File System Agent on the client. This will prevent updates to any policies on the client. Default value is false.",
			},
			"enable_domain_sharing": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to enable domain sharing for ClientGroup.",
			},
			"enabled_capabilities": schema.StringAttribute{
				Optional:    true,
				Description: "Comma-separated agent capabilities which are enabled. Currently only RESIGN for re-signing client settings can be enabled.",
			},
			"shared_domain_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of domains with which ClientGroup needs to be shared.",
			},
			"system_locked": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.",
			},
			// Update Auth Binaries for the client group
			"auth_binaries": schema.StringAttribute{
				Optional:    true,
				Description: "Array of authorized binaries in the privilege-filename pair JSON format.",
			},
			"re_sign": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to re-sign the client settings.",
			},
			// Add clients to the group
			"client_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of Client identifier which are to be associated with clientgroup. This identifier can be the Name, ID (a UUIDv4), URI, or slug of the client.",
			},
			"inherit_attributes": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the client should inherit attributes from the ClientGroup.",
			},
			// Remove client from the group
			"client_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the client to be removed from the client group.",
			},
			// LDT Pause
			"paused": schema.BoolAttribute{
				Optional:    true,
				Description: "Suspend/resume the rekey operation on an LDT GuardPoint. Set the value to true to pause (suspend) the rekey. Set the value to false to resume rekey.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClientGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_clientgroup.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEClientGroupTFSDK
	var payload CTEClientGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.ValueString())
	payload.ClusterType = common.TrimString(plan.ClusterType.ValueString())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.LDTDesignatedPrimarySet.ValueString() != "" && plan.LDTDesignatedPrimarySet.ValueString() != types.StringNull().ValueString() {
		payload.LDTDesignatedPrimarySet = common.TrimString(plan.LDTDesignatedPrimarySet.String())
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = common.TrimString(plan.Password.String())
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
	}
	if plan.ProfileID.ValueString() != "" && plan.ProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ProfileID = common.TrimString(plan.ProfileID.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CTE_CLIENT_GROUP, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client Group on CipherTrust Manager: ",
			"Could not create CTE Client Group, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClientGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClientGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEClientGroupTFSDK
	var payload CTEClientGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.OpType.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		if plan.OpType.ValueString() == "update" {
			if plan.ClientLocked.ValueBool() != types.BoolNull().ValueBool() {
				payload.ClientLocked = plan.ClientLocked.ValueBool()
			}
			if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
				payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
			}
			if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
				payload.Description = common.TrimString(plan.Description.String())
			}
			if plan.EnableDomainSharing.ValueBool() != types.BoolNull().ValueBool() {
				payload.EnableDomainSharing = plan.EnableDomainSharing.ValueBool()
			}
			if plan.EnabledCapabilities.ValueString() != "" && plan.EnabledCapabilities.ValueString() != types.StringNull().ValueString() {
				payload.EnabledCapabilities = common.TrimString(plan.EnabledCapabilities.String())
			}
			if plan.LDTDesignatedPrimarySet.ValueString() != "" && plan.LDTDesignatedPrimarySet.ValueString() != types.StringNull().ValueString() {
				payload.LDTDesignatedPrimarySet = common.TrimString(plan.LDTDesignatedPrimarySet.String())
			}
			if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
				payload.Password = common.TrimString(plan.Password.String())
			}
			if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
				payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
			}
			if plan.ProfileID.ValueString() != "" && plan.ProfileID.ValueString() != types.StringNull().ValueString() {
				payload.ProfileID = common.TrimString(plan.ProfileID.String())
			}
			if plan.SharedDomainList != nil {
				for _, domain := range plan.SharedDomainList {
					payload.SharedDomainList = append(payload.SharedDomainList, domain.ValueString())
				}
			}
			if plan.SystemLocked.ValueBool() != types.BoolNull().ValueBool() {
				payload.SystemLocked = plan.SystemLocked.ValueBool()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Update",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_CTE_CLIENT_GROUP, payloadJSON, "id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "auth-binaries" {
			if plan.AuthBinaries.ValueString() != "" && plan.AuthBinaries.ValueString() != types.StringNull().ValueString() {
				payload.AuthBinaries = common.TrimString(plan.AuthBinaries.String())
			}
			if plan.ReSign.ValueBool() != types.BoolNull().ValueBool() {
				payload.ReSign = plan.ReSign.ValueBool()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> auth-binaries]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Auth Binaries",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/auth-binaries",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> auth-binaries]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "update-password" {
			if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
				payload.Password = common.TrimString(plan.Password.String())
			}
			if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
				payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> update-password]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Update Password",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/resetpassword",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> update-password]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "reset-password" {
			// TODO:
			var payload []byte
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/resetpassword",
				payload,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> update-password]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "remove-client" {
			response, err := r.client.DeleteByURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/clients/"+plan.ClientID.ValueString())
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> remove-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "add-client" {
			var clientsArr []string
			for _, client := range plan.ClientList {
				clientsArr = append(clientsArr, client.ValueString())
			}
			payload.ClientList = clientsArr

			if plan.InheritAttributes.ValueBool() != types.BoolNull().ValueBool() {
				payload.InheritAttributes = plan.InheritAttributes.ValueBool()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Add Clients",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/clients",
				payloadJSON,
				"items")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "ldt-pause" {
			if plan.Paused.ValueBool() != types.BoolNull().ValueBool() {
				payload.Paused = plan.Paused.ValueBool()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> ldt-pause]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group LDT pause",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/ldtpause",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> ldt-pause]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Could not update CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else {
			resp.Diagnostics.AddError(
				"Invalid op_type option",
				"The 'op_type' attribute must be one of update, auth-binaries, update-password, reset-password, remove-client, add-client, ldt-pause.",
			)
			return
		}
	} else {
		resp.Diagnostics.AddError(
			"op_type is a required",
			"The 'op_type' attribute must be provided during update.",
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClientGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGroupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_CLIENT_GROUP, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust CTE Client",
			"Could not delete CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEClientGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
