package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_                           resource.Resource                   = &resourceCTEClient{}
	_                           resource.ResourceWithConfigure      = &resourceCTEClient{}
	_                           resource.ResourceWithImportState    = &resourceCTEClient{}
	_                           resource.ResourceWithValidateConfig = &resourceCTEClient{}
	CtePasswordGenarationMethod                                     = []string{"GENERATE", "MANUAL"}
	CteClientType                                                   = []string{"FS", "CTE-U"}

	CTEResourceDescription = `CipherTrust Transparent Encryption (CTE) delivers data-at-rest encryption with centralized key management, privileged user access control, and detailed data access audit logging. This protects data wherever it resides—on-premises, across multiple clouds, and within big data.

	CTE:

	- Encrypts files and raw data
	- Controls which users can decrypt and access that data
	- Controls which processes and executables can decrypt and encrypt that data
	- Generates fine-grained audit trails on those processes, executables, and users`
)

func NewResourceCTEClient() resource.Resource {
	return &resourceCTEClient{}
}

type resourceCTEClient struct {
	client *common.Client
}

func (r *resourceCTEClient) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClient) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: CTEResourceDescription,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Identifier of a CTE client to be generated on successful creation of Client",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the client. This name will be visible on the CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"client_locked": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the CTE client is locked. The default value is false. Enable this option to lock the configuration of the CTE Agent on the client. Set to true to lock the configuration, set to false to unlock. Locking the Agent configuration prevents updates to any policies on the client.",
			},
			"client_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("FS"),
				Description: "Type of CTE Client. The default value is FS. Valid values are CTE-U and FS.",
				Validators: []validator.String{
					stringvalidator.OneOf(CteClientType...),
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"communication_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether communication with the client is enabled. The default value is false. Can be set to true only if registration_allowed is true.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Description to identify the client.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Password for the client. Required when password_creation_method is MANUAL. Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). To resend a rotated password, change `password` and bump `password_version` in the same apply.",
			},
			"password_version": schema.Int64Attribute{
				Optional:    true,
				Description: "Arbitrary version number used to trigger re-sending `password` to CipherTrust Manager. Since `password` is write-only, Terraform cannot detect a change in its value on its own; increment this on every apply where you want the current `password` value re-sent.",
			},
			"password_creation_method": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("GENERATE"),
				Description: "Password creation method for the client. Valid values are MANUAL and GENERATE. The default value is GENERATE.",
				Validators: []validator.String{
					stringvalidator.OneOf(CtePasswordGenarationMethod...),
				},
			},
			"profile_identifier": schema.StringAttribute{
				Optional:    true,
				Description: "Identifier of the Client Profile to be associated with the client. If not provided, the default profile will be linked.",
			},
			"profile_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the Client Profile to be associated with the client. If not provided, the default profile will be linked.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"registration_allowed": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether client's registration with the CipherTrust Manager is allowed. The default value is false. Set to true to allow registration.",
			},
			"system_locked": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.",
			},
			"client_mfa_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether MFA is enabled on the client.",
			},
			"del_client": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether to mark the client for deletion from the CipherTrust Manager. The default value is false.",
			},
			"disable_capability": schema.StringAttribute{
				Optional:    true,
				Description: "Client capability to be disabled. Only EKP - Encryption Key Protection can be disabled.",
			},
			"dynamic_parameters": schema.StringAttribute{
				Optional:    true,
				Description: "Array of parameters to be updated after the client is registered. Specify the parameters in the name-value pair JSON format strings. Make sure to specify all the parameters even if you want to update one or more parameters. For example, if there are two parameters in the CTE client list and you want to update the value of \"param1\", then specify the correct value (one from the \"allowed_values\") in the \"current_value\" field, and keep the remaining parameters intact.",
			},
			"enable_domain_sharing": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether domain sharing is enabled for the client.",
			},
			"enabled_capabilities": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Client capabilities to be enabled. Separate values with comma. Valid values are LDT and EKP",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: mapdefault.StaticValue(
					types.MapValueMust(types.StringType, map[string]attr.Value{}),
				),
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
			},
			"lgcs_access_only": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the client can be added to an LDT communication group. If lgcs_access_only is set to false, the client can be added to an LDT communication group. Only available on Windows clients.",
			},
			"max_num_cache_log": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum number of logs to cache.",
			},
			"max_space_cache_log": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum space for the cached logs.",
			},
			"profile_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "ID of the profile that contains logger, logging, and QOS configuration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"protection_mode": schema.StringAttribute{
				Optional:    true,
				Description: "Update protection mode for windows client. This change is irreversible. The valid value is \"CTE RWP\"",
			},
			"shared_domain_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of domains in which the client needs to be shared.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClient) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_client.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CTEClientTFSDK
	var payload CTEClientJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.Password is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config CTEClientTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.ValueString())

	payload.ClientType = common.TrimString(plan.ClientType.ValueString())

	if plan.ClientType.ValueString() != "CTE-U" {
		if !plan.ClientLocked.IsNull() && !plan.ClientLocked.IsUnknown() {
			v := plan.ClientLocked.ValueBool()
			payload.ClientLocked = &v
		}
		if !plan.SystemLocked.IsNull() && !plan.SystemLocked.IsUnknown() {
			v := plan.SystemLocked.ValueBool()
			payload.SystemLocked = &v
		}
	}

	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
	}
	if v := config.Password.ValueString(); v != "" {
		payload.Password = v
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.ValueString())
	}
	if plan.ProfileIdentifier.ValueString() != "" && plan.ProfileIdentifier.ValueString() != types.StringNull().ValueString() {
		payload.ProfileIdentifier = common.TrimString(plan.ProfileIdentifier.ValueString())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_CLIENT, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not create CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
	var clientData CTEClientsListJSON
	err = json.Unmarshal([]byte(response), &clientData)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing CTE Client response", err.Error())
		return
	}

	plan.ID = types.StringValue(clientData.ID)
	plan.ProfileID = types.StringValue(clientData.ProfileID)
	plan.ProfileName = types.StringValue(clientData.ProfileName)

	// password is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.Password = types.StringNull()

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClient) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientTFSDK

	id := uuid.New().String()

	r.client.Log.Trace(common.MSG_METHOD_START +
		"[resource_cte_client.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(
		ctx,
		id,
		state.ID.ValueString(),
		common.URL_CTE_CLIENT,
	)
	if handleReadNotFound(ctx, err, "CTE Client ("+state.ID.ValueString()+")", &resp.Diagnostics) {
		return
	}

	var apiResp CTEClientsListJSON
	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing API response",
			err.Error(),
		)
		return
	}

	setCTEClientState(&state, &apiResp, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.client.Log.Trace(common.MSG_METHOD_END +
		"[resource_cte_client.go -> Read][" + id + "]")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClient) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEClientTFSDK
	var payload CTEClientJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state CTEClientTFSDK

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Update() ever runs, so plan.Password is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config CTEClientTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// name and client_type immutability is enforced at plan time by
	// modifiers.ImmutableString() on the schema attributes above, so Update()
	// never observes a changed value for either field here.
	if state.ClientType.ValueString() != "CTE-U" {
		if !plan.ClientLocked.IsNull() && !plan.ClientLocked.IsUnknown() {
			v := plan.ClientLocked.ValueBool()
			payload.ClientLocked = &v
		}
		if !plan.SystemLocked.IsNull() && !plan.SystemLocked.IsUnknown() {
			v := plan.SystemLocked.ValueBool()
			payload.SystemLocked = &v
		}
	}

	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.ValueString())
	}
	// password is write-only (never stored in state), so its own value can never be
	// diffed against a prior value — password_version is the explicit, state-tracked
	// signal that the caller wants the current password value re-sent to CM.
	if !plan.PasswordVersion.Equal(state.PasswordVersion) {
		payload.Password = config.Password.ValueString()
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.ValueString())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}
	if plan.ClientMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientMFAEnabled = plan.ClientMFAEnabled.ValueBool()
	}
	if plan.DelClient.ValueBool() != types.BoolNull().ValueBool() {
		payload.DelClient = plan.DelClient.ValueBool()
	}
	if plan.DisableCapability.ValueString() != "" && plan.DisableCapability.ValueString() != types.StringNull().ValueString() {
		payload.DisableCapability = common.TrimString(plan.DisableCapability.ValueString())
	}
	if plan.DynamicParameters.ValueString() != "" && plan.DynamicParameters.ValueString() != types.StringNull().ValueString() {
		payload.DynamicParameters = common.TrimString(plan.DynamicParameters.ValueString())
	}
	if plan.EnableDomainSharing.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableDomainSharing = plan.EnableDomainSharing.ValueBool()
	}
	if plan.EnabledCapabilities.ValueString() != "" && plan.EnabledCapabilities.ValueString() != types.StringNull().ValueString() {
		payload.EnabledCapabilities = common.TrimString(plan.EnabledCapabilities.ValueString())
	}
	if plan.LGCSAccessOnly.ValueBool() != types.BoolNull().ValueBool() {
		payload.LGCSAccessOnly = plan.LGCSAccessOnly.ValueBool()
	}
	if plan.MaxNumCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxNumCacheLog = plan.MaxNumCacheLog.ValueInt64()
	}
	if plan.MaxSpaceCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxSpaceCacheLog = plan.MaxSpaceCacheLog.ValueInt64()
	}
	if plan.ProfileID.ValueString() != "" && plan.ProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ProfileID = common.TrimString(plan.ProfileID.ValueString())
	}
	if plan.ProtectionMode.ValueString() != "" && plan.ProtectionMode.ValueString() != types.StringNull().ValueString() {
		payload.ProtectionMode = common.TrimString(plan.ProtectionMode.ValueString())
	}
	if plan.SharedDomainList != nil {
		for _, domain := range plan.SharedDomainList {
			payload.SharedDomainList = append(payload.SharedDomainList, domain.ValueString())
		}
	}
	// Add labels to payload; send nil (JSON null) rather than an empty map
	// when labels is empty/removed, so CM actually clears them instead of
	// silently no-op'ing on {} (TFIN-463).
	if len(plan.Labels.Elements()) == 0 {
		payload.Labels = nil
	} else {
		labelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			labelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = labelsPayload
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_CTE_CLIENT, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not update CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
	var clientData CTEClientsListJSON
	err = json.Unmarshal([]byte(response), &clientData)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing CTE Client response", err.Error())
		return
	}
	plan.ID = types.StringValue(clientData.ID)
	plan.ProfileID = types.StringValue(clientData.ProfileID)
	plan.ProfileName = types.StringValue(clientData.ProfileName)

	// password is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.Password = types.StringNull()

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClient) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	DelClient := DelClientJSON{
		DelClient:      true,
		ForceDelClient: true,
	}
	PayloadJSON, err := json.Marshal(DelClient)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client.go -> Update][]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Update %s "+state.ID.ValueString(),
			err.Error(),
		)
		return
	}
	// Delete existing order using custom url
	url := fmt.Sprintf("%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_CLIENT, state.ID.ValueString(), "delete")
	output, err := r.client.DeleteByID(ctx, "PATCH", state.ID.ValueString(), url, PayloadJSON)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if handleDeleteNotFound(err, "CTE Client "+state.ID.ValueString(), &resp.Diagnostics) {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust CTE Client",
			"Could not delete CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEClient) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func validateCTEUClientConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var clientType types.String
	var clientLocked types.Bool
	var systemLocked types.Bool

	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("client_type"), &clientType)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("client_locked"), &clientLocked)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("system_locked"), &systemLocked)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if clientType.ValueString() == "CTE-U" {
		if !clientLocked.IsNull() && !clientLocked.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root("client_locked"),
				"Unsupported Field for CTE-U Client",
				"client_locked is not supported when client_type is CTE-U. Remove this field or change client_type to FS.",
			)
		}
		if !systemLocked.IsNull() && !systemLocked.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_locked"),
				"Unsupported Field for CTE-U Client",
				"system_locked is not supported when client_type is CTE-U. Remove this field or change client_type to FS.",
			)
		}
	}
}

// validateNonFunctionalCacheLogFields rejects max_num_cache_log/max_space_cache_log
// when explicitly configured. TFIN-467: CipherTrust Manager silently ignores
// writes to these two fields at the client level (confirmed via direct REST
// PATCH cross-check, including values that respect the linked profile's
// documented minimums) — every apply reports success but the value never
// persists, producing a perpetual, unresolvable plan diff. The equivalent
// setting is only functional on the linked ciphertrust_cte_profile resource's
// cache_settings.max_files/max_space. Erroring here up front, rather than
// sending a PATCH CM will 200-OK and silently no-op, matches the existing
// in-file precedent (see validateCTEUClientConfig above) of surfacing
// unsupported field combinations as an explicit attribute error instead of
// letting them fail silently against CM.
func validateNonFunctionalCacheLogFields(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var maxNumCacheLog types.Int64
	var maxSpaceCacheLog types.Int64

	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("max_num_cache_log"), &maxNumCacheLog)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("max_space_cache_log"), &maxSpaceCacheLog)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !maxNumCacheLog.IsNull() && !maxNumCacheLog.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("max_num_cache_log"),
			"Non-Functional Field for CTE Client",
			"max_num_cache_log cannot be set at the client level; CipherTrust Manager accepts the write but silently ignores it, so it can never persist. Configure the equivalent setting on the linked ciphertrust_cte_profile resource's cache_settings.max_files attribute instead.",
		)
	}
	if !maxSpaceCacheLog.IsNull() && !maxSpaceCacheLog.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("max_space_cache_log"),
			"Non-Functional Field for CTE Client",
			"max_space_cache_log cannot be set at the client level; CipherTrust Manager accepts the write but silently ignores it, so it can never persist. Configure the equivalent setting on the linked ciphertrust_cte_profile resource's cache_settings.max_space attribute instead.",
		)
	}
}

func (r *resourceCTEClient) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	validateCTEUClientConfig(ctx, req, resp)
	validateNonFunctionalCacheLogFields(ctx, req, resp)
}

func setCTEClientState(
	state *CTEClientTFSDK,
	apiResp *CTEClientsListJSON,
	resp *resource.ReadResponse,
) {

	state.ID = types.StringValue(apiResp.ID)
	// description is Optional+Computed with a "" default (see schema), so both
	// an omitted config value and an explicit description = "" converge to the
	// same state value here. Do NOT normalize "" to null (TFIN-619): that
	// reintroduces a perpetual plan loop because config "" would never match a
	// null state.
	state.Description = types.StringValue(apiResp.Description)
	// TFIN-465: name must be refreshed from the live API response on every
	// Read() (including `terraform apply -refresh-only`), not just the very
	// first read when state happens to be null/empty. name now carries
	// modifiers.ImmutableString() on its schema attribute (TFIN-461), so a
	// refreshed value that no longer matches config surfaces as an explicit
	// "Attribute is immutable" error at plan time instead of a silent,
	// unresolvable diff.
	state.Name = types.StringValue(apiResp.Name)
	state.ClientLocked = types.BoolValue(apiResp.ClientLocked)
	state.ClientType = types.StringValue(apiResp.ClientType)
	state.CommunicationEnabled = types.BoolValue(apiResp.CommunicationEnabled)
	state.PasswordCreationMethod = types.StringValue(apiResp.PasswordCreationMethod)
	state.RegistrationAllowed = types.BoolValue(apiResp.RegistrationAllowed)
	state.SystemLocked = types.BoolValue(apiResp.SystemLocked)
	state.ClientMFAEnabled = types.BoolValue(apiResp.ClientMFAEnabled)
	state.DelClient = types.BoolValue(apiResp.DelClient)
	state.EnableDomainSharing = types.BoolValue(apiResp.EnableDomainSharing)
	state.EnabledCapabilities = types.StringValue(apiResp.EnabledCapabilities)
	state.ProfileID = types.StringValue(apiResp.ProfileID)
	state.ProfileName = types.StringValue(apiResp.ProfileName)

	// protection_mode is refreshed from the live response only when state already
	// holds a value, i.e. the configuration actually asked for a protection mode.
	// CipherTrust Manager reports protection_mode = "CTE" for every client that has
	// never had its protection mode changed, so populating it unconditionally would
	// put a value in state for configurations that never set this Optional (not
	// Computed) attribute and produce a plan diff that can never be resolved. The
	// non-empty check on the response guards against a client whose payload omits
	// the field, which would otherwise blank out a configured value.
	if !state.ProtectionMode.IsNull() && state.ProtectionMode.ValueString() != "" &&
		apiResp.ProtectionMode != "" {
		state.ProtectionMode = types.StringValue(apiResp.ProtectionMode)
	}

	state.MaxNumCacheLog = types.Int64Value(apiResp.MaxNumCacheLog)
	state.MaxSpaceCacheLog = types.Int64Value(apiResp.MaxSpaceCacheLog)

	// labels is Optional+Computed with an empty-map default (see schema), so
	// both an omitted config value and an explicit labels = {} converge to the
	// same state value here. Do NOT normalize an absent/nil/empty labels
	// response to null (TFIN-619): that reintroduces a perpetual plan loop
	// because config {} would never match a null state. Always reflect CM's
	// actual labels value (including empty) directly into state.
	labelsMap := map[string]attr.Value{}
	for k, v := range apiResp.Labels {
		if strVal, ok := v.(string); ok {
			labelsMap[k] = types.StringValue(strVal)
		}
	}
	labels, diags := types.MapValue(types.StringType, labelsMap)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Labels = labels
}

func (r *resourceCTEClient) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_cte_client.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_cte_client.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
