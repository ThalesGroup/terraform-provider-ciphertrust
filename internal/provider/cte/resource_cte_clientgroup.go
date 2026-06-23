package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTEClientGroup{}
	_ resource.ResourceWithConfigure   = &resourceCTEClientGroup{}
	_ resource.ResourceWithImportState = &resourceCTEClientGroup{}
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
				Computed:    true,
				Default:     booldefault.StaticBool(false),
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
				Computed:    true,
				Description: "Password creation method, GENERATE or MANUAL.",
				Default:     stringdefault.StaticString("GENERATE"),
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"GENERATE",
						"MANUAL"}...),
				},
			},
			"profile_id": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Is FS Agent locked? Enables locking the configuration of the File System Agent on the client. This will prevent updates to any policies on the client. Default value is false.",
			},
			"enable_domain_sharing": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
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
				Computed:    true,
				Default:     booldefault.StaticBool(false),
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
			"client_list": schema.SetAttribute{
				Optional: true,
				Computed: true,
				Default: setdefault.StaticValue(
					types.SetValueMust(types.StringType, []attr.Value{}),
				),
				ElementType: types.StringType,
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
		if plan.PasswordCreationMethod.ValueString() == "MANUAL" && (plan.Password.ValueString() == "" || plan.Password.ValueString() == types.StringNull().ValueString()) {
			resp.Diagnostics.AddError(
				"Error creating CTE Client Group on CipherTrust Manager: ",
				"Password is required when password_creation_method is MANUAL",
			)
			return
		}
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

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_CLIENT_GROUP, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client Group on CipherTrust Manager: ",
			"Could not create CTE Client Group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	if plan.ProfileID.ValueString() == "" || plan.ProfileID.ValueString() == types.StringNull().ValueString() {
		plan.ProfileID = types.StringValue(gjson.Get(response, "profile_id").String())
	}
	// Add clients to client group

	if len(plan.ClientList) > 0 {
		if plan.InheritAttributes.IsNull() || plan.InheritAttributes.IsUnknown() {
			resp.Diagnostics.AddError(
				"Invalid data input: CTE Client Group Add Clients",
				"Inherit Attributes value is required when adding clients to the group",
			)
			return
		}
		var clientNames []string
		for _, c := range plan.ClientList {
			clientNames = append(clientNames, c.ValueString())
		}

		addClientsPayload := CTEClientGroupJSON{
			ClientList:        clientNames,
			InheritAttributes: plan.InheritAttributes.ValueBool(),
		}
		addClientsPayloadJSON, err := json.Marshal(addClientsPayload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Create add-clients]["+id+"]")
			resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", err.Error())
			return
		}

		_, err = r.client.PostData(
			ctx,
			id,
			common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/clients",
			addClientsPayloadJSON,
			"items",
		)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Create add-clients]["+id+"]")
			resp.Diagnostics.AddError(
				"Error adding clients to CTE Client Group on CipherTrust Manager: ",
				"Could not add clients to CTE Client Group, unexpected error: "+err.Error(),
			)
			return
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClientGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGroupTFSDK
	id := uuid.New().String()

	tflog.Trace(
		ctx,
		common.MSG_METHOD_START+
			"[resource_cte_clientgroup.go -> Read]["+id+"]",
	)

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_CLIENT_GROUP)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp CTEClientGroupJSON

	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing API response",
			err.Error(),
		)
		return
	}

	clientsResponse, err := r.client.GetById(ctx, id, state.ID.ValueString()+"/clients", common.URL_CTE_CLIENT_GROUP)
	if err != nil {
		tflog.Debug(ctx, "Error fetching clients for CTE client group: "+err.Error()+" [resource_cte_clientgroup.go -> Read]["+id+"]")
	} else if clientsResponse != "" {
		var clientsResp CTEClientGroupClientsJSON
		if jsonErr := json.Unmarshal([]byte(clientsResponse), &clientsResp); jsonErr != nil {
			tflog.Debug(ctx, "Error parsing clients response: "+jsonErr.Error()+" [resource_cte_clientgroup.go -> Read]["+id+"]")
		} else {
			for _, c := range clientsResp.Resources {
				apiResp.ClientList = append(apiResp.ClientList, c.Name)
			}
		}
	}
	setCTEClientGroupState(&state, &apiResp)

	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(
		ctx,
		common.MSG_METHOD_END+
			"[resource_cte_clientgroup.go -> Read]["+id+"]",
	)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClientGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGroupTFSDK
	var payload CTEClientGroupJSON

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

	//handle immutable fields
	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannot change client group name once it is created", "client group name is an immutable field")
		return
	}
	if plan.ClusterType.ValueString() != state.ClusterType.ValueString() {
		resp.Diagnostics.AddError("Cannot change client group cluster_type once it is created", "cluster_type is an immutable field")
		return
	}

	if plan.OpType.ValueString() != "" && plan.OpType.ValueString() != types.StringNull().ValueString() {
		if plan.OpType.ValueString() == "update" {

			// Add error checks for fields we cant change in op_type = update
			if !stringSlicesEqual(plan.ClientList, state.ClientList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "client_list cannot be changed with op_type 'update'")
				return
			}
			if plan.InheritAttributes != state.InheritAttributes {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "inherit_attributes cannot be changed with op_type 'update'")
				return
			}
			if plan.AuthBinaries != state.AuthBinaries {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "auth_binaries cannot be changed with op_type 'update'")
				return
			}
			if plan.ReSign != state.ReSign {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "re_sign cannot be changed with op_type 'update'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "paused cannot be changed with op_type 'update'")
				return
			}

			//Now handle the mutable fields
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
				if plan.PasswordCreationMethod.ValueString() == "MANUAL" && (plan.Password.ValueString() == "" || plan.Password.ValueString() == types.StringNull().ValueString()) {
					resp.Diagnostics.AddError(
						"Error updating CTE Client Group on CipherTrust Manager: ",
						"Password is required when password_creation_method is MANUAL",
					)
					return
				}
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
			// Add error checks for fields we cant change in op_type = auth-binaries
			if !stringSlicesEqual(plan.ClientList, state.ClientList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "client_list cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.InheritAttributes != state.InheritAttributes {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "inherit_attributes cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "paused cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.Password != state.Password {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "password cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.PasswordCreationMethod != state.PasswordCreationMethod {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "password_creation_method cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.ClientLocked != state.ClientLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "client_locked cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.CommunicationEnabled != state.CommunicationEnabled {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "communication_enabled cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.Description != state.Description {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "description cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.EnableDomainSharing != state.EnableDomainSharing {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "enable_domain_sharing cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.EnabledCapabilities != state.EnabledCapabilities {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "enabled_capabilities cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.LDTDesignatedPrimarySet != state.LDTDesignatedPrimarySet {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "ldt_designated_primary_set cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.ProfileID != state.ProfileID {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "profile_id cannot be changed with op_type 'auth-binaries'")
				return
			}
			if !reflect.DeepEqual(plan.SharedDomainList, state.SharedDomainList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "shared_domain_list cannot be changed with op_type 'auth-binaries'")
				return
			}
			if plan.SystemLocked != state.SystemLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Auth Binaries", "system_locked cannot be changed with op_type 'auth-binaries'")
				return
			}

			//Now handle the mutable fields

			if plan.AuthBinaries.ValueString() != "" && plan.AuthBinaries.ValueString() != types.StringNull().ValueString() {
				payload.AuthBinaries = strings.TrimSpace(plan.AuthBinaries.ValueString())
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
					"Error updating auth binaries for CTE Client Group on CipherTrust Manager: ",
					"Could not update auth binaries for CTE Client Group "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "update-password" {
			// Add error checks for fields we cant change in op_type = update-password
			if !stringSlicesEqual(plan.ClientList, state.ClientList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "client_list cannot be changed with op_type 'update-password'")
				return
			}
			if plan.InheritAttributes != state.InheritAttributes {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "inherit_attributes cannot be changed with op_type 'update-password'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "paused cannot be changed with op_type 'update-password'")
				return
			}

			if plan.AuthBinaries != state.AuthBinaries {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "auth_binaries cannot be changed with op_type 'update-password'")
				return
			}
			if plan.ReSign != state.ReSign {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "re_sign cannot be changed with op_type 'update-password'")
				return
			}
			if plan.ClientLocked != state.ClientLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "client_locked cannot be changed with op_type 'update-password'")
				return
			}
			if plan.CommunicationEnabled != state.CommunicationEnabled {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "communication_enabled cannot be changed with op_type 'update-password'")
				return
			}
			if plan.Description != state.Description {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "description cannot be changed with op_type 'update-password'")
				return
			}
			if plan.EnableDomainSharing != state.EnableDomainSharing {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "enable_domain_sharing cannot be changed with op_type 'update-password'")
				return
			}
			if plan.EnabledCapabilities != state.EnabledCapabilities {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "enabled_capabilities cannot be changed with op_type 'update-password'")
				return
			}
			if plan.LDTDesignatedPrimarySet != state.LDTDesignatedPrimarySet {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "ldt_designated_primary_set cannot be changed with op_type 'update-password'")
				return
			}
			if plan.ProfileID != state.ProfileID {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "profile_id cannot be changed with op_type 'update-password'")
				return
			}
			if !reflect.DeepEqual(plan.SharedDomainList, state.SharedDomainList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "shared_domain_list cannot be changed with op_type 'update-password'")
				return
			}
			if plan.SystemLocked != state.SystemLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Update Password", "system_locked cannot be changed with op_type 'update-password'")
				return
			}

			//Now handle mutable fields
			if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
				payload.Password = common.TrimString(plan.Password.String())
			}
			if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
				payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
			}
			if plan.PasswordCreationMethod.ValueString() == "MANUAL" && (plan.Password.ValueString() == "" || plan.Password.ValueString() == types.StringNull().ValueString()) {
				resp.Diagnostics.AddError(
					"Error updating CTE Client Group on CipherTrust Manager: ",
					"Password is required when password_creation_method is MANUAL",
				)
				return
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
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/password",
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
			// Add error checks for fields we cant change in op_type = reset-password
			if !stringSlicesEqual(plan.ClientList, state.ClientList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "client_list cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.InheritAttributes != state.InheritAttributes {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "inherit_attributes cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "paused cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.AuthBinaries != state.AuthBinaries {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "auth_binaries cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.ReSign != state.ReSign {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "re_sign cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.Password != state.Password {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "password cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.PasswordCreationMethod != state.PasswordCreationMethod {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "password_creation_method cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.ClientLocked != state.ClientLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "client_locked cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.CommunicationEnabled != state.CommunicationEnabled {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "communication_enabled cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.Description != state.Description {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "description cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.EnableDomainSharing != state.EnableDomainSharing {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "enable_domain_sharing cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.EnabledCapabilities != state.EnabledCapabilities {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "enabled_capabilities cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.LDTDesignatedPrimarySet != state.LDTDesignatedPrimarySet {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "ldt_designated_primary_set cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.ProfileID != state.ProfileID {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "profile_id cannot be changed with op_type 'reset-password'")
				return
			}
			if !reflect.DeepEqual(plan.SharedDomainList, state.SharedDomainList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "shared_domain_list cannot be changed with op_type 'reset-password'")
				return
			}
			if plan.SystemLocked != state.SystemLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Reset Password", "system_locked cannot be changed with op_type 'reset-password'")
				return
			}
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
			// Add error checks for fields we cant change in op_type = remove-client
			if !plan.InheritAttributes.IsNull() {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "inherit_attributes must not be set with op_type 'remove-client'")
				return
			}
			if plan.AuthBinaries != state.AuthBinaries {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "auth_binaries cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.ReSign != state.ReSign {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "re_sign cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "paused cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.Password != state.Password {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "password cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.PasswordCreationMethod != state.PasswordCreationMethod {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "password_creation_method cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.ClientLocked != state.ClientLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "client_locked cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.CommunicationEnabled != state.CommunicationEnabled {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "communication_enabled cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.Description != state.Description {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "description cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.EnableDomainSharing != state.EnableDomainSharing {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "enable_domain_sharing cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.EnabledCapabilities != state.EnabledCapabilities {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "enabled_capabilities cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.LDTDesignatedPrimarySet != state.LDTDesignatedPrimarySet {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "ldt_designated_primary_set cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.ProfileID != state.ProfileID {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "profile_id cannot be changed with op_type 'remove-client'")
				return
			}
			if !reflect.DeepEqual(plan.SharedDomainList, state.SharedDomainList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "shared_domain_list cannot be changed with op_type 'remove-client'")
				return
			}
			if plan.SystemLocked != state.SystemLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Remove Client", "system_locked cannot be changed with op_type 'remove-client'")
				return
			}

			// clients in state but not in plan = to be removed
			planSet := make(map[string]bool)
			for _, c := range plan.ClientList {
				planSet[c.ValueString()] = true
			}

			for _, c := range state.ClientList {
				if !planSet[c.ValueString()] {
					_, err := r.client.DeleteByURL(
						ctx,
						plan.ID.ValueString(),
						common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/clients/"+c.ValueString())
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> remove-client]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError(
							"Error deleting client from CTE Client Group on CipherTrust Manager: ",
							"Could not delete client "+c.ValueString()+" from CTE Client Group, unexpected error: "+err.Error(),
						)
						return
					}
				}
			}

			// plan.ClientList already reflects desired end state, just save it
			state.ClientList = plan.ClientList
			state.InheritAttributes = types.BoolNull()
			state.OpType = plan.OpType
			diags = resp.State.Set(ctx, state)
			resp.Diagnostics.Append(diags...)
			return
		} else if plan.OpType.ValueString() == "add-client" {
			// Add error checks for fields we cant change in op_type = add-client
			if plan.AuthBinaries != state.AuthBinaries {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "auth_binaries cannot be changed with op_type 'add-client'")
				return
			}
			if plan.ReSign != state.ReSign {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "re_sign cannot be changed with op_type 'add-client'")
				return
			}
			if plan.Paused != state.Paused {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "paused cannot be changed with op_type 'add-client'")
				return
			}
			if plan.Password != state.Password {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "password cannot be changed with op_type 'add-client'")
				return
			}
			if plan.PasswordCreationMethod != state.PasswordCreationMethod {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "password_creation_method cannot be changed with op_type 'add-client'")
				return
			}
			if plan.ClientLocked != state.ClientLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "client_locked cannot be changed with op_type 'add-client'")
				return
			}
			if plan.CommunicationEnabled != state.CommunicationEnabled {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "communication_enabled cannot be changed with op_type 'add-client'")
				return
			}
			if plan.Description != state.Description {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "description cannot be changed with op_type 'add-client'")
				return
			}
			if plan.EnableDomainSharing != state.EnableDomainSharing {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "enable_domain_sharing cannot be changed with op_type 'add-client'")
				return
			}
			if plan.EnabledCapabilities != state.EnabledCapabilities {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "enabled_capabilities cannot be changed with op_type 'add-client'")
				return
			}
			if plan.LDTDesignatedPrimarySet != state.LDTDesignatedPrimarySet {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "ldt_designated_primary_set cannot be changed with op_type 'add-client'")
				return
			}
			if plan.ProfileID != state.ProfileID {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "profile_id cannot be changed with op_type 'add-client'")
				return
			}
			if !reflect.DeepEqual(plan.SharedDomainList, state.SharedDomainList) {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "shared_domain_list cannot be changed with op_type 'add-client'")
				return
			}
			if plan.SystemLocked != state.SystemLocked {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Group Add Clients", "system_locked cannot be changed with op_type 'add-client'")
				return
			}
			//Now handle mutable fields
			var clientsArr, stateClientsArr []string
			for _, client := range state.ClientList {
				stateClientsArr = append(stateClientsArr, client.ValueString())
			}
			for _, client := range plan.ClientList {
				if !slices.Contains(stateClientsArr, client.ValueString()) {
					clientsArr = append(clientsArr, client.ValueString())
				}
			}
			payload.ClientList = clientsArr
			if plan.InheritAttributes.IsNull() || plan.InheritAttributes.IsUnknown() {
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Add Clients",
					"Inherit Attributes value is required when adding clients to the group",
				)
				return
			}
			payload.InheritAttributes = plan.InheritAttributes.ValueBool()

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Client Group Add Clients",
					err.Error(),
				)
				return
			}

			response, err := r.client.PostData(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/clients",
				payloadJSON,
				"items")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> add-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error adding clients to CTE Client Group on CipherTrust Manager: ",
					"Could not add clients to CTE Client Group, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response + plan.ID.ValueString())
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

			response, err := r.client.PostData(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CLIENT_GROUP+"/"+plan.ID.ValueString()+"/ldtpause",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> ldt-pause]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error pausing LDT service for CTE Client Group on CipherTrust Manager: ",
					"Could not pause LDT service for CTE Client Group "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
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

	//Delete clients from client group
	for _, c := range state.ClientList {
		clientName := c.ValueString()
		if clientName == "" {
			continue
		}
		_, err := r.client.DeleteByURL(
			ctx,
			state.ID.ValueString(),
			common.URL_CTE_CLIENT_GROUP+"/"+state.ID.ValueString()+"/clients/"+clientName,
		)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> Delete client]["+state.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Error removing client from CTE Client Group before deletion",
				"Could not remove client "+clientName+" from group "+state.ID.ValueString()+": "+err.Error(),
			)
			return
		}
	}

	// Delete existing Client Group
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_CLIENT_GROUP, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Client Group on CipherTrust Manager",
			"Could not delete CTE Client Group "+state.ID.ValueString()+", unexpected error: "+err.Error(),
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

func setCTEClientGroupState(
	state *CTEClientGroupTFSDK,
	apiResp *CTEClientGroupJSON,
) {
	state.ID = types.StringValue(apiResp.ID)
	state.Name = types.StringValue(apiResp.Name)
	state.ClusterType = types.StringValue(apiResp.ClusterType)
	state.CommunicationEnabled = types.BoolValue(apiResp.CommunicationEnabled)
	state.ClientLocked = types.BoolValue(apiResp.ClientLocked)
	state.SystemLocked = types.BoolValue(apiResp.SystemLocked)
	state.EnableDomainSharing = types.BoolValue(apiResp.EnableDomainSharing)

	if apiResp.Description != "" {
		state.Description = types.StringValue(apiResp.Description)
	} else {
		state.Description = types.StringNull()
	}

	if apiResp.LDTDesignatedPrimarySet != "" {
		state.LDTDesignatedPrimarySet = types.StringValue(apiResp.LDTDesignatedPrimarySet)
	} else {
		state.LDTDesignatedPrimarySet = types.StringNull()
	}

	if apiResp.PasswordCreationMethod != "" {
		state.PasswordCreationMethod = types.StringValue(apiResp.PasswordCreationMethod)
	} else {
		state.PasswordCreationMethod = types.StringNull()
	}

	if state.ProfileID.ValueString() == "" || state.ProfileID.ValueString() == types.StringNull().ValueString() {
		if apiResp.ProfileID != "" {
			state.ProfileID = types.StringValue(apiResp.ProfileID)
		}
	}

	if apiResp.EnabledCapabilities != "" {
		state.EnabledCapabilities = types.StringValue(apiResp.EnabledCapabilities)
	} else {
		state.EnabledCapabilities = types.StringNull()
	}

	if apiResp.AuthBinaries != "" {
		state.AuthBinaries = types.StringValue(apiResp.AuthBinaries)
	} else {
		state.AuthBinaries = types.StringNull()
	}

	// SharedDomainList
	var sharedDomainList []types.String
	for _, d := range apiResp.SharedDomainList {
		sharedDomainList = append(sharedDomainList, types.StringValue(d))
	}
	state.SharedDomainList = sharedDomainList

	// ClientList
	clientList := make([]types.String, 0)
	for _, c := range apiResp.ClientList {
		clientList = append(clientList, types.StringValue(c))
	}
	state.ClientList = clientList
}

func stringSlicesEqual(a, b []types.String) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]bool, len(a))
	for _, v := range a {
		aMap[v.ValueString()] = true
	}
	for _, v := range b {
		if !aMap[v.ValueString()] {
			return false
		}
	}
	return true
}
func (r *resourceCTEClientGroup) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_clientgroup.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_clientgroup.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
