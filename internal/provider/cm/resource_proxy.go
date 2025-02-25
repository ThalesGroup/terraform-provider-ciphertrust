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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMProxy{}
	_ resource.ResourceWithConfigure = &resourceCMProxy{}
)

func NewResourceCMProxy() resource.Resource {
	return &resourceCMProxy{}
}

type resourceCMProxy struct {
	client *common.Client
}

func (r *resourceCMProxy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_proxy"
}

// Schema defines the schema for the resource.
func (r *resourceCMProxy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"certificate": schema.StringAttribute{
				Optional:    true,
				Description: "CA certificate to trust for proxy.",
			},
			"http_proxy": schema.StringAttribute{
				Optional:    true,
				Description: "HTTP proxy URL for proxy configurations. If the proxy server's password contains any special character replace it with encoded values.",
			},
			"https_proxy": schema.StringAttribute{
				Optional:    true,
				Description: "HTTPS proxy URL for proxy configurations. If the proxy server's password contains any special character replace it with encoded values.",
			},
			"no_proxy": schema.ListAttribute{
				Optional:    true,
				Description: "List of hosts for a proxy exception.",
				ElementType: types.StringType,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMProxy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_proxy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMProxyTFSDK
	var payload CMProxyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.HTTPProxy.ValueString() != "" && plan.HTTPProxy.ValueString() != types.StringNull().ValueString() {
		payload.HTTPProxy = plan.HTTPProxy.ValueString()
	}

	if plan.HTTPSProxy.ValueString() != "" && plan.HTTPSProxy.ValueString() != types.StringNull().ValueString() {
		payload.HTTPSProxy = plan.HTTPSProxy.ValueString()
	}

	var hosts []string
	for _, str := range plan.NoProxy {
		hosts = append(hosts, str.ValueString())
	}
	payload.NoProxy = hosts

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Proxy Configuration",
			err.Error(),
		)
		return
	}

	response, err := r.client.PutData(
		ctx,
		id,
		common.URL_CM_PROXY,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error setting proxy information on CipherTrust Manager: ",
			"Could not set proxy information, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_proxy.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_proxy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMProxy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMProxyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, "all", common.URL_CM_PROXY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Proxy information on CipherTrust Manager: ",
			"Could not read Proxy information: unexpected error: "+err.Error(),
		)
		return
	}

	state.Certificate = types.StringValue(gjson.Get(response, "certificate").String())
	state.HTTPProxy = types.StringValue(gjson.Get(response, "http_proxy").String())
	state.HTTPSProxy = types.StringValue(gjson.Get(response, "https_proxy").String())

	hosts := gjson.Get(response, "no_proxy").Array()
	var noProxies []types.String
	for _, host := range hosts {
		noProxies = append(noProxies, types.StringValue(host.String()))
	}
	state.NoProxy = noProxies

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_proxy.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMProxy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMProxyTFSDK
	var payload CMProxyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.HTTPProxy.ValueString() != "" && plan.HTTPProxy.ValueString() != types.StringNull().ValueString() {
		payload.HTTPProxy = plan.HTTPProxy.ValueString()
	}

	if plan.HTTPSProxy.ValueString() != "" && plan.HTTPSProxy.ValueString() != types.StringNull().ValueString() {
		payload.HTTPSProxy = plan.HTTPSProxy.ValueString()
	}

	var hosts []string
	for _, str := range plan.NoProxy {
		hosts = append(hosts, str.ValueString())
	}
	payload.NoProxy = hosts

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Syslog Updation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		id,
		common.URL_CM_PROXY,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_proxy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Proxy information on CipherTrust Manager: ",
			"Could not update Proxy information, unexpected error: "+err.Error(),
		)
		return
	}

	plan.Certificate = types.StringValue(gjson.Get(response, "certificate").String())
	plan.HTTPProxy = types.StringValue(gjson.Get(response, "http_proxy").String())
	plan.HTTPSProxy = types.StringValue(gjson.Get(response, "https_proxy").String())

	noProxyHosts := gjson.Get(response, "no_proxy").Array()
	var noProxies []types.String
	for _, host := range noProxyHosts {
		noProxies = append(noProxies, types.StringValue(host.String()))
	}
	plan.NoProxy = noProxies

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMProxy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	var state CMProxyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s", r.client.CipherTrustURL, common.URL_CM_PROXY)
	output, err := r.client.DeleteByID(ctx, "DELETE", id, url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_proxy.go -> Delete]["+id+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Proxy",
			"Could not delete Proxy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMProxy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
