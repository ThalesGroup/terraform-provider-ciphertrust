package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                   = &resourceHSMRootOfTrust{}
	_ resource.ResourceWithConfigure      = &resourceHSMRootOfTrust{}
	_ resource.ResourceWithValidateConfig = &resourceHSMRootOfTrust{}
)

func NewResourceHSMRootOfTrustServer() resource.Resource {
	return &resourceHSMRootOfTrust{}
}

type resourceHSMRootOfTrust struct {
	client *common.Client
}

func (r *resourceHSMRootOfTrust) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hsm_root_of_trust_setup"
}

func (r *resourceHSMRootOfTrust) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_hsm_root_of_trust_setup", resp)
}

// Schema defines the schema for the resource.
func (r *resourceHSMRootOfTrust) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Performs the initial HSM root-of-trust setup for the CipherTrust Manager appliance. Supported HSM types: Luna Network HSM (`luna`), Luna PCIe (`lunapci`), Luna T-Series (`lunatct`), ProtectServer HSM (`protectserver`), AWS CloudHSM (`aws`), DPoD (`dpod`), Entrust nShield Connect (`nshield`), and IBM HPCS (`ibmhpcs`). **Warning: this operation resets the appliance and wipes all existing CipherTrust Manager data.** **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the HSM root-of-trust setup resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Type of HSM server to setup. Supported values: \"luna\", \"lunapci\", \"lunatct\", \"protectserver\", \"aws\", \"dpod\", \"nshield\", \"ibmhpcs\". Must be lowercase.",
				Validators: []validator.String{
					stringvalidator.OneOf("luna", "lunapci", "lunatct", "protectserver", "aws", "dpod", "nshield", "ibmhpcs"),
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"conn_info": schema.MapAttribute{
				ElementType: types.StringType,
				Required:    true,
				Sensitive:   true,
				Description: "(Immutable) Connection information for initial HSM to setup in key-value format. The expected content of this parameter depends on the specific HSM type used.\n\nFor Luna Network HSM (including TCT) and Luna PCIe, the required attributes are:\n\n- \"partition_name\"  \n  The name of the HSM partition to use.\n\n- \"partition_password\"  \n  The password of the initial partition to use. This will be the Crypto Officer role password or challenge secret. Luna documentation describes in detail how to set up a password for an application to access a partition.  \n  If you plan to use multiple Luna HSMs operating in high-availability (HA) mode, all HSMs must have the same password.\n\nLuna Network/PCIe HSM (including TCT) example:  \n\n{\n \"partition_name\": \"kylo-partition\",\n \"partition_password\": \"sOmeP@ssword\"\n}",
				PlanModifiers: []planmodifier.Map{
					modifiers.ImmutableMap(),
				},
			},
			"initial_config": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "(Immutable) A map of key-value pairs representing the initial configuration for the HSM setup. The expected content of this parameter depends on the specific HSM type used.\n\nFor Luna Network HSM (including TCT) the required attributes are:\n- \"host\"\n  IP or hostname\n- \"serial\"\n  Serial number of the partition to use\n- \"server-cert\"\n  Server certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n  For externally signed server certs (not supported on TCT), append all certificates in the signing chain.\n- \"client-cert\"\n  Client certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n- \"client-cert-key\"\n  Client private key in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n\nFor Luna Network HSM using the STC protocol, the required attributes are:\n- \"host\"\n  IP or hostname\n- \"serial\"\n  Serial number of the partition to use\n- \"server-cert\"\n  Server certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n- \"stc-par-identity\"\n  STC partition identity encoded as a base64 string without line breaks (base64 -w0 1234567890123.pid)\nNote that this instance's STC client identity (see /system/hsm/clients/stcidentity) must be registered externally prior to invoking this API.\n\nLuna PCIe HSM (including TCT) does not require any attribute. initialConfig shall be omitted.\n\nLuna Network HSM (including TCT) example:\n\n    {\n      \"host\": \"10.10.10.10\",\n      \"serial\": \"1234\",\n      \"server-cert\": \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\",\n      \"client-cert\": \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\",\n      \"client-cert-key\": \"-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\"\n    }\n\nNote: JSON does not allow line-breaks, it needs to be replaced with \\n. Use \"sed -z 's/\\n/\\\\n/g' cert-file.pem\" command to format the certificate.\n",
				PlanModifiers: []planmodifier.Map{
					modifiers.ImmutableMap(),
				},
			},
			"reset": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) If true CipherTrust Manager will perform a reset operation after the initial HSM setup. WARNING: destructive — wipes all CipherTrust Manager data.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"delay": schema.Int64Attribute{
				Optional:    true,
				Description: "(Immutable) Delay in seconds before reset, defaults to 5 seconds.",
				PlanModifiers: []planmodifier.Int64{
					modifiers.ImmutableInt64(),
				},
			},
			"sub_type": schema.StringAttribute{
				Computed:    true,
				Description: "The subtype of the HSM setup.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"config": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Configuration of the HSM.",
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceHSMRootOfTrust) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_hsm_rot.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan HSMSetupTFSDK
	var payload HSMSetupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Type.ValueString() != "" && plan.Type.ValueString() != types.StringNull().ValueString() {
		payload.Type = plan.Type.ValueString()
	}
	if plan.Delay.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Delay = plan.Delay.ValueInt64()
	}
	if plan.Reset.ValueBool() != types.BoolNull().ValueBool() {
		payload.Reset = plan.Reset.ValueBool()
	}

	// Extract conn_info map and convert it into JSON string
	connInfoMap := make(map[string]interface{})
	for k, v := range plan.ConnInfo.Elements() {
		strVal, ok := v.(types.String)
		if !ok || strVal.IsNull() || strVal.IsUnknown() {
			resp.Diagnostics.AddError(
				"Invalid conn_info input",
				fmt.Sprintf("Key %q in conn_info has an invalid or unconfigured string value", k),
			)
			return
		}
		connInfoMap[k] = strVal.ValueString()
	}

	connInfoJSON, err := json.Marshal(connInfoMap)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid conn_info input",
			"Could not convert conn_info to JSON: "+err.Error(),
		)
		return
	}
	payload.ConnInfo = string(connInfoJSON)

	initialConfigPayload := make(map[string]interface{})
	for k, v := range plan.InitialConfig.Elements() {
		strVal, ok := v.(types.String)
		if !ok || strVal.IsNull() || strVal.IsUnknown() {
			resp.Diagnostics.AddError(
				"Invalid initial_config input",
				fmt.Sprintf("Key %q in initial_config has an invalid or unconfigured string value", k),
			)
			return
		}
		initialConfigPayload[k] = strVal.ValueString()
	}
	payload.InitialConfig = initialConfigPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: HSM Root of trust Setup",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_HSM_SETUP, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating HSM Root of trust setup on CipherTrust Manager: ",
			"Could not create HSM Root of trust setup, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	// Apply ToLower so state matches the lowercase value the user writes in config;
	// the schema validator enforces lowercase at plan time, so this normalises any
	// casing difference in CM's POST response.
	plan.Type = types.StringValue(strings.ToLower(gjson.Get(response, "type").String()))
	plan.SubType = types.StringValue(gjson.Get(response, "sub_type").String())
	plan.Config = parseConfig(ctx, response, &resp.Diagnostics)

	r.client.Log.Debug("[resource_hsm_rot.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_hsm_rot.go -> Create][" + id + "]")

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceHSMRootOfTrust) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state HSMSetupTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_hsm_rot.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_hsm_rot.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve write-only field before the CM GET call.
	// After HSM setup completes, CM records the operation as done and returns
	// reset: false in the GET /api/v1/system/hsm/servers/{id} response.
	// Reading that value back would overwrite state.Reset from true to false,
	// causing ImmutableBool.PlanModifyBool() to fire 'old: false, new: true'
	// on every subsequent plan and destroy. Same pattern as priorLicense in
	// resource_license.go (TFIN-430 fix).
	priorReset := state.Reset

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_HSM_Server)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"HSM Root of Trust Setup Not Found — State Preserved",
				"The HSM Root of Trust Setup resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading HSM Server on CipherTrust Manager: ",
			"Could not read HSM Server id : ,"+state.ID.ValueString()+" unexpected error: "+err.Error(),
		)
		return
	}

	// Computed-only fields — hydrate unconditionally (always present in CM GET response).
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.SubType = types.StringValue(gjson.Get(response, "sub_type").String())
	state.Config = parseConfig(ctx, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Required field: type — preserve from prior state.
	// ImmutableString() prevents any plan change; Create() stores the lowercase value.
	// (state.Type is left unchanged — no assignment needed)

	// Required field: conn_info.
	// HSMSetupJSON.ConnInfo is a plain string (JSON-encoded object) — use json.Unmarshal,
	// not gjson.ForEach, to deserialise the nested object.
	if connInfoResult := gjson.Get(response, "connInfo"); connInfoResult.Exists() {
		connInfoMap := make(map[string]string)
		if err := json.Unmarshal([]byte(connInfoResult.String()), &connInfoMap); err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Read][" + id + "]")
			resp.Diagnostics.AddError(
				"Error parsing conn_info from CM response",
				"Could not unmarshal connInfo JSON string: "+err.Error(),
			)
			return
		}

		// Blend prior state values to preserve write-only credentials (such as partition_password)
		// which are omitted or masked from the GET response.
		priorConnInfo := make(map[string]string)
		for k, v := range state.ConnInfo.Elements() {
			if strVal, ok := v.(types.String); ok && !strVal.IsNull() && !strVal.IsUnknown() {
				priorConnInfo[k] = strVal.ValueString()
			}
		}
		for k, v := range connInfoMap {
			priorConnInfo[k] = v
		}

		m, d := types.MapValueFrom(ctx, types.StringType, priorConnInfo)
		resp.Diagnostics.Append(d...)
		state.ConnInfo = m
	}
	// else: CM omitted connInfo — preserve prior state.ConnInfo unchanged.
	// Required field: assigning MapNull causes perpetual drift against the user's configured value.
	// state.ConnInfo is already loaded from req.State.Get.
	if resp.Diagnostics.HasError() {
		return
	}

	// Optional field: initial_config.
	// HSMSetupJSON.InitialConfig is map[string]interface{} — gjson.ForEach is correct here.
	if !state.InitialConfig.IsNull() {
		if r := gjson.Get(response, "initialConfig"); r.Exists() {
			initialConfigMap := make(map[string]string)
			r.ForEach(func(key, value gjson.Result) bool {
				initialConfigMap[key.String()] = value.String()
				return true
			})

			// Blend prior state values to preserve write-only keys like client-cert-key
			priorInitialConfig := make(map[string]string)
			for k, v := range state.InitialConfig.Elements() {
				if strVal, ok := v.(types.String); ok && !strVal.IsNull() && !strVal.IsUnknown() {
					priorInitialConfig[k] = strVal.ValueString()
				}
			}
			for k, v := range initialConfigMap {
				priorInitialConfig[k] = v
			}

			m, d := types.MapValueFrom(ctx, types.StringType, priorInitialConfig)
			resp.Diagnostics.Append(d...)
			state.InitialConfig = m
		}
		// else: CM omitted initialConfig — preserve prior state.InitialConfig unchanged.
		// No swagger GET evidence confirms CM always returns this field when set.
		// For HSM types like lunapci, CM may legitimately omit it.
	}
	// outer else: user never configured initial_config — preserve null prior state.
	if resp.Diagnostics.HasError() {
		return
	}

	// Optional field: reset — write-only; restore prior state value (never read from API).
	state.Reset = priorReset

	// Optional field: delay
	if !state.Delay.IsNull() {
		if r := gjson.Get(response, "delay"); r.Exists() && r.Type != gjson.Null {
			state.Delay = types.Int64Value(r.Int())
		}
	}
	// else: user never configured delay — preserve null prior state.

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	// defer fires MSG_METHOD_END after this return.
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceHSMRootOfTrust) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_hsm_rot.go -> Update]")

	// update not supported for this resource
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"This resource does not support updates. You must recreate the resource to apply any changes.",
	)

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_hsm_rot.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceHSMRootOfTrust) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_hsm_rot.go -> Delete]")

	var state HSMSetupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Prepare parameters
	payload := map[string]interface{}{
		"reset": true,
		"delay": 5,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating payload",
			"Could not encode payload to JSON"+err.Error(),
		)
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_HSM_Server, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, payloadBytes)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// Resource already deleted out-of-band; treat terraform destroy as successful.
			r.client.Log.Debug("[resource_hsm_rot.go -> Delete] resource already absent, skipping [" + state.ID.ValueString() + "]")
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_hsm_rot.go -> Delete][" + state.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error Deleting HSM Server on CipherTrust Manager: ",
			"Could not Delete HSM Server : ,"+state.ID.ValueString()+" unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_hsm_rot.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
}

func (d *resourceHSMRootOfTrust) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// parseConfig extracts the "config" map from a CM JSON response string and
// returns it as a types.Map. When "config" is absent from the response, an
// empty map is returned (consistent with the pre-existing two-argument form —
// this is a signature-only change; absent-branch behaviour is unchanged).
// Any conversion error is appended to diags.
func parseConfig(ctx context.Context, response string, diags *diag.Diagnostics) types.Map {
	result := gjson.Get(response, "config")
	if !result.Exists() {
		return types.MapValueMust(types.StringType, map[string]attr.Value{})
	}
	configMap := make(map[string]string)
	result.ForEach(func(key, value gjson.Result) bool {
		configMap[key.String()] = value.String()
		return true
	})
	m, d := types.MapValueFrom(ctx, types.StringType, configMap)
	diags.Append(d...)
	return m
}
