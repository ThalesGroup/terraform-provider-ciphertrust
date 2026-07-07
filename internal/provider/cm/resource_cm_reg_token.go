package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMRegToken{}
	_ resource.ResourceWithConfigure = &resourceCMRegToken{}
)

func NewResourceCMRegToken() resource.Resource {
	return &resourceCMRegToken{}
}

type resourceCMRegToken struct {
	client *common.Client
}

func (r *resourceCMRegToken) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_reg_token"
}

// Schema defines the schema for the resource.
func (r *resourceCMRegToken) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"token": schema.StringAttribute{
				Computed:    true,
				Description: "Set the token recieved from the API call to the state.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ca_id": schema.StringAttribute{
				Optional:    true,
				Description: "DEPRECATED: the field is deprecated. Use the ca_id in the client profile instead. ca_id is the ID of the trusted Certificate Authority that will be used to sign client certificate during registration process.",
			},
			"cert_duration": schema.Int64Attribute{
				Optional:    true,
				Description: "Duration in days for which the CipherTrust Manager client certificate is valid. The value cannot be negative. If 0 is provided then the value will be ignored. It is not recommended to use this parameter. Please use the one supported in client profile.",
			},
			"client_management_profile_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the client management profile",
			},
			"label": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Label is the key value pair. In case of KMIP client registration, Key is KmipClientProfile and in case of PA client registration Key is ClientProfile. Value for the key is the profile name of protectapp/Kmip client profile to be mapped with the token for protectapp/Kmip client registration.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels",
			},
			"lifetime": schema.StringAttribute{
				Optional:    true,
				Description: "Duration in minutes/hours/days for which this token can be used for registering CipherTrust Manager clients. No limit by default. For 'x' amount of time, it should formatted as xm for x minutes, xh for hours and xd for days.",
			},
			"max_clients": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of clients that can be registered using this registration token. No limit by default.",
			},
			"name_prefix": schema.StringAttribute{
				Optional:    true,
				Description: "Prefix for the client name. For a client registered using this registration token, name_prefix, if specified, client name will be constructed as 'name_prefix{nth client registered using this registation token}', If name_prefix is not specified, CipherTrust Manager server will generate a random name for the client.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMRegToken) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_reg_token.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMRegTokenTFSDK
	var payload CMRegTokenJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.CAID.ValueString() != "" && plan.CAID.ValueString() != types.StringNull().ValueString() {
		payload.CAID = plan.CAID.ValueString()
	}
	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}
	if plan.ClientManagementProfileID.ValueString() != "" && plan.ClientManagementProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ClientManagementProfileID = plan.ClientManagementProfileID.ValueString()
	}

	// Add label to payload — fix: both blocks previously iterated plan.Labels (bug); first block now iterates plan.Label
	if !plan.Label.IsNull() && !plan.Label.IsUnknown() {
		labelPayload := make(map[string]interface{})
		for k, v := range plan.Label.Elements() {
			labelPayload[k] = v.(types.String).ValueString()
		}
		payload.Label = labelPayload
	}

	// Add labels to payload — null guard prevents sending {} when unconfigured
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		labelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			labelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = labelsPayload
	}

	if plan.Lifetime.ValueString() != "" && plan.Lifetime.ValueString() != types.StringNull().ValueString() {
		payload.Lifetime = plan.Lifetime.ValueString()
	}
	if plan.MaxClients.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxClients = plan.MaxClients.ValueInt64()
	}
	if plan.NamePrefix.ValueString() != "" && plan.NamePrefix.ValueString() != types.StringNull().ValueString() {
		payload.NamePrefix = plan.NamePrefix.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: RegToken Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_REG_TOKEN, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating RegToken on CipherTrust Manager: ",
			"Could not create RegToken, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Token = types.StringValue(gjson.Get(response, "token").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_reg_token.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMRegToken) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Registration tokens are ephemeral; 404 means expired/deleted → RemoveResource
	// so Terraform recreates on next apply. Intentional deviation from keep-in-state convention.
	var state CMRegTokenTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_reg_token.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_reg_token.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_REG_TOKEN)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Debug(ctx, common.ERR_METHOD_END+"resource removed from CM"+" [resource_cm_reg_token.go -> Read]["+id+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading RegToken from CipherTrust Manager",
			"Could not read RegToken id "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	// Computed-only fields — hydrate unconditionally
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Token = types.StringValue(gjson.Get(response, "token").String())

	// Optional string scalars — CM may not echo back these fields in GET responses.
	// The !state.X.IsNull() guard prevents null→"" drift for unconfigured fields.
	// When the field IS configured (state non-null) and CM returns it, hydrate from CM.
	// When CM doesn't return it, preserve the prior state to avoid perpetual drift.
	if !state.CAID.IsNull() {
		if r := gjson.Get(response, "ca_id"); r.Exists() {
			state.CAID = types.StringValue(r.String())
		} else {
			state.CAID = types.StringNull()
		}
	}

	if !state.ClientManagementProfileID.IsNull() {
		if r := gjson.Get(response, "client_management_profile_id"); r.Exists() {
			state.ClientManagementProfileID = types.StringValue(r.String())
		} else {
			state.ClientManagementProfileID = types.StringNull()
		}
	}

	if !state.Lifetime.IsNull() {
		if r := gjson.Get(response, "lifetime"); r.Exists() {
			state.Lifetime = types.StringValue(r.String())
		} else {
			state.Lifetime = types.StringNull()
		}
	}

	if !state.NamePrefix.IsNull() {
		if r := gjson.Get(response, "name_prefix"); r.Exists() {
			state.NamePrefix = types.StringValue(r.String())
		} else {
			state.NamePrefix = types.StringNull()
		}
	}

	// Optional int64 scalars — CM returns 0 for unset non-pointer int64 fields; guard prevents null→0 drift
	if !state.CertDuration.IsNull() {
		if r := gjson.Get(response, "cert_duration"); r.Exists() {
			state.CertDuration = types.Int64Value(r.Int())
		} else {
			state.CertDuration = types.Int64Null()
		}
	}

	if !state.MaxClients.IsNull() {
		if r := gjson.Get(response, "max_clients"); r.Exists() {
			state.MaxClients = types.Int64Value(r.Int())
		} else {
			state.MaxClients = types.Int64Null()
		}
	}

	// Optional map fields — three-branch: absent/null → MapNull, empty → MapValueMust({}), present → MapValueFrom
	labelResult := gjson.Get(response, "label")
	if !labelResult.Exists() || labelResult.Type == gjson.Null {
		state.Label = types.MapNull(types.StringType)
	} else if len(labelResult.Map()) == 0 {
		state.Label = types.MapValueMust(types.StringType, map[string]attr.Value{})
	} else {
		labelMap := make(map[string]string)
		labelResult.ForEach(func(k, v gjson.Result) bool {
			labelMap[k.String()] = v.String()
			return true
		})
		lv, diag := types.MapValueFrom(ctx, types.StringType, labelMap)
		resp.Diagnostics.Append(diag...)
		if !resp.Diagnostics.HasError() {
			state.Label = lv
		}
	}

	labelsResult := gjson.Get(response, "labels")
	if !labelsResult.Exists() || labelsResult.Type == gjson.Null {
		state.Labels = types.MapNull(types.StringType)
	} else if len(labelsResult.Map()) == 0 {
		state.Labels = types.MapValueMust(types.StringType, map[string]attr.Value{})
	} else {
		labelsMap := make(map[string]string)
		labelsResult.ForEach(func(k, v gjson.Result) bool {
			labelsMap[k.String()] = v.String()
			return true
		})
		lv, diag := types.MapValueFrom(ctx, types.StringType, labelsMap)
		resp.Diagnostics.Append(diag...)
		if !resp.Diagnostics.HasError() {
			state.Labels = lv
		}
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMRegToken) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CMRegTokenTFSDK
	var state CMRegTokenTFSDK
	var payload CMRegTokenJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current state to preserve computed fields
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Token = state.Token

	if plan.CAID.ValueString() != "" && plan.CAID.ValueString() != types.StringNull().ValueString() {
		payload.CAID = plan.CAID.ValueString()
	}
	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}
	if plan.ClientManagementProfileID.ValueString() != "" && plan.ClientManagementProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ClientManagementProfileID = plan.ClientManagementProfileID.ValueString()
	}

	// Add labels to payload — null guard prevents sending {} when unconfigured
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		labelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			labelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = labelsPayload
	}

	// Add label to payload — null guard
	if !plan.Label.IsNull() && !plan.Label.IsUnknown() {
		labelPayload := make(map[string]interface{})
		for k, v := range plan.Label.Elements() {
			labelPayload[k] = v.(types.String).ValueString()
		}
		payload.Label = labelPayload
	}

	// Add name_prefix to payload — null guard
	if !plan.NamePrefix.IsNull() && !plan.NamePrefix.IsUnknown() {
		payload.NamePrefix = plan.NamePrefix.ValueString()
	}

	if plan.Lifetime.ValueString() != "" && plan.Lifetime.ValueString() != types.StringNull().ValueString() {
		payload.Lifetime = plan.Lifetime.ValueString()
	}
	if plan.MaxClients.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxClients = plan.MaxClients.ValueInt64()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Update]["+state.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: RegToken Update",
			err.Error(),
		)
		return
	}

	// Fix: URL path must use state.ID (resource UUID from prior state), not plan.ID
	response, err := r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_REG_TOKEN, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Update]["+state.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating RegToken on CipherTrust Manager: ",
			"Could not upodate RegToken, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_reg_token.go -> Update]["+plan.ID.ValueString()+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMRegToken) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMRegTokenTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_reg_token.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_reg_token.go -> Delete]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_REG_TOKEN, state.ID.ValueString())
	_, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// Token already deleted out-of-band — treat as success; defer emits MSG_METHOD_END
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_reg_token.go -> Delete]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust RegToken",
			"Could not delete RegToken, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMRegToken) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
