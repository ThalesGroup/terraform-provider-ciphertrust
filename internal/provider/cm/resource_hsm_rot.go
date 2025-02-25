package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceHSMRootOfTrust{}
	_ resource.ResourceWithConfigure = &resourceHSMRootOfTrust{}
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

// Schema defines the schema for the resource.
func (r *resourceHSMRootOfTrust) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Type of HSM server to setup, supported types are \"luna\", \"lunapci\", and \"lunatct\". \"luna\" refers to the Luna Network HSM version 5, 6, or 7, \"lunapci\" refers to the embedded Luna PCIe HSM, and \"lunatct\" refers to the Luna T-Series HSMs.",
			},
			"conn_info": schema.MapAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Connection information for initial HSM to setup in key-value format. The expected content of this parameter depends on the specific HSM type used.\n\nFor Luna Network HSM (including TCT) and Luna PCIe, the required attributes are:\n\n- \"partition_name\"  \n  The name of the HSM partition to use.\n\n- \"partition_password\"  \n  The password of the initial partition to use. This will be the Crypto Officer role password or challenge secret. Luna documentation describes in detail how to set up a password for an application to access a partition.  \n  If you plan to use multiple Luna HSMs operating in high-availability (HA) mode, all HSMs must have the same password.\n\nLuna Network/PCIe HSM (including TCT) example:  \n\n{\n \"partition_name\": \"kylo-partition\",\n \"partition_password\": \"sOmeP@ssword\"\n}",
			},
			"initial_config": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "A map of key-value pairs representing the initial configuration for the HSM setup. The expected content of this parameter depends on the specific HSM type used.\n\nFor Luna Network HSM (including TCT) the required attributes are:\n- \"host\"\n  IP or hostname\n- \"serial\"\n  Serial number of the partition to use\n- \"server-cert\"\n  Server certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n  For externally signed server certs (not supported on TCT), append all certificates in the signing chain.\n- \"client-cert\"\n  Client certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n- \"client-cert-key\"\n  Client private key in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n\nFor Luna Network HSM using the STC protocol, the required attributes are:\n- \"host\"\n  IP or hostname\n- \"serial\"\n  Serial number of the partition to use\n- \"server-cert\"\n  Server certificate in PEM format. Line breaks in PEM string must be replaced with \"\\n\".\n- \"stc-par-identity\"\n  STC partition identity encoded as a base64 string without line breaks (base64 -w0 1234567890123.pid)\nNote that this instance's STC client identity (see /system/hsm/clients/stcidentity) must be registered externally prior to invoking this API.\n\nLuna PCIe HSM (including TCT) does not require any attribute. initialConfig shall be omitted.\n\nLuna Network HSM (including TCT) example:\n\n    {\n      \"host\": \"10.10.10.10\",\n      \"serial\": \"1234\",\n      \"server-cert\": \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\",\n      \"client-cert\": \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\",\n      \"client-cert-key\": \"-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\"\n    }\n\nNote: JSON does not allow line-breaks, it needs to be replaced with \\n. Use \"sed -z 's/\\n/\\\\n/g' cert-file.pem\" command to format the certificate.\n",
			},
			"reset": schema.BoolAttribute{
				Optional:    true,
				Description: "If true CipherTrust Manager will perform a reset operation after the initial HSM setup.\n\nCurrently a reset is required for this operation to succeed.\n\nWARNING - Reset is a destructive operation and will wipe all\ndata in the CipherTrust Manager.\n",
			},
			"delay": schema.Int64Attribute{
				Optional:    true,
				Description: "Delay in seconds before reset, defaults to 5 seconds",
			},
			"sub_type": schema.StringAttribute{
				Computed:    true,
				Description: "The subtype of the HSM setup.",
			},
			"config": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Configuration of the HSM.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceHSMRootOfTrust) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_hsm_rot.go -> Create]["+id+"]")

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
		connInfoMap[k] = v.(types.String).ValueString()
	}

	connInfoJSON, err := json.Marshal(connInfoMap)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_hsm_rot.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid conn_info input",
			"Could not convert conn_info to JSON: "+err.Error(),
		)
		return
	}
	payload.ConnInfo = string(connInfoJSON)

	initialConfigPayload := make(map[string]interface{})
	for k, v := range plan.InitialConfig.Elements() {
		initialConfigPayload[k] = v.(types.String).ValueString()
	}
	payload.InitialConfig = initialConfigPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_hsm_rot.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: HSM Root of trust Setup",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_HSM_SETUP, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_hsm_rot.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating HSM Root of trust setup on CipherTrust Manager: ",
			"Could not create HSM Root of trust setup, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Type = types.StringValue(gjson.Get(response, "type").String())
	plan.SubType = types.StringValue(gjson.Get(response, "sub_type").String())
	plan.Config = parseConfig(response, &resp.Diagnostics)

	tflog.Debug(ctx, "[resource_hsm_rot.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_hsm_rot.go -> Create]["+id+"]")

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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_hsm_rot.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_HSM_Server)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_hsm_rot.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading HSM Server on CipherTrust Manager: ",
			"Could not read HSM Server id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_hsm_rot.go -> Read]["+id+"]")
	return
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceHSMRootOfTrust) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_hsm_rot.go -> Update]")

	// update not supported for this resource
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"This resource does not support updates. You must recreate the resource to apply any changes.",
	)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_hsm_rot.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceHSMRootOfTrust) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_hsm_rot.go -> Delete]")

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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_hsm_rot.go -> Delete]["+state.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error Deleting HSM Server on CipherTrust Manager: ",
			"Could not Delete HSM Server : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_hsm_rot.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
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

func parseConfig(response string, diagnostics *diag.Diagnostics) types.Map {
	// Parse the "config" field from the JSON response
	configJSON := gjson.Get(response, "config").Raw

	// Initialize a map to hold the parsed config
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		diagnostics.AddError(
			"Error parsing config",
			"Unable to parse 'config' field: "+err.Error(),
		)
		return types.MapNull(types.StringType)
	}

	// Convert map[string]interface{} to Terraform types.Map
	convertedMap := make(map[string]attr.Value)
	for key, value := range configMap {
		// Convert each value to a Terraform String or dynamic value based on its type
		convertedMap[key] = types.StringValue(fmt.Sprintf("%v", value))
	}

	return types.MapValueMust(types.StringType, convertedMap)
}
