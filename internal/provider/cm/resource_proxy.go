package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMProxy{}
	_ resource.ResourceWithConfigure      = &resourceCMProxy{}
	_ resource.ResourceWithValidateConfig = &resourceCMProxy{}
	_ resource.ResourceWithImportState    = &resourceCMProxy{}
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

func (r *resourceCMProxy) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_proxy", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMProxy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Configures outbound HTTP/HTTPS proxy settings (with optional CA certificate and no_proxy bypass list) for the CipherTrust Manager appliance. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the proxy configuration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"certificate": schema.StringAttribute{
				Optional:    true,
				Description: "CA certificate to trust for proxy.",
				Validators: []validator.String{
					validators.PEMCertificate(),
				},
			},
			// http_proxy: uses ProxyURL() instead of URL() to accept the schemeless
			// proxy format (e.g. "user:pass@host:port") that CM's own documentation
			// describes as valid (Scenario 3 — protocol not specified explicitly).
			// validators.URL() was too strict: it enforced RFC URL semantics and
			// rejected valid CM-accepted values. (TFIN-526)
			"http_proxy": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "HTTP proxy address. Accepts a full URL (e.g. " +
					"`http://username:password@proxy.example.com:8080`), a schemeless address " +
					"(e.g. `username:password@host:port` or `host:port`), or a bare hostname. " +
					"If the proxy password contains special characters, percent-encode them. " +
					"**Known limitation**: CipherTrust Manager always returns this value with the password " +
					"masked (replaced with `xxxxxx`) in GET responses. After `terraform apply`, Terraform " +
					"state holds the cleartext value from your configuration. A password-only out-of-band " +
					"change is undetectable by `terraform plan -refresh-only` because the masked URL is " +
					"structurally identical before and after. Changes to scheme, host, port, or username " +
					"are fully detectable and will surface as drift.",
				Validators: []validator.String{
					validators.ProxyURL(),
				},
			},
			// https_proxy: same validator relaxation as http_proxy. (TFIN-526)
			"https_proxy": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "HTTPS proxy address. Accepts a full URL (e.g. " +
					"`https://username:password@proxy.example.com:8080`), a schemeless address " +
					"(e.g. `username:password@host:port` or `host:port`), or a bare hostname. " +
					"If the proxy password contains special characters, percent-encode them. " +
					"**Known limitation**: CipherTrust Manager always returns this value with the password " +
					"masked (replaced with `xxxxxx`) in GET responses. After `terraform apply`, Terraform " +
					"state holds the cleartext value from your configuration. A password-only out-of-band " +
					"change is undetectable by `terraform plan -refresh-only` because the masked URL is " +
					"structurally identical before and after. Changes to scheme, host, port, or username " +
					"are fully detectable and will surface as drift.",
				Validators: []validator.String{
					validators.ProxyURL(),
				},
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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_proxy.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CMProxyTFSDK
	var payload CMProxyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		certVal := plan.Certificate.ValueString()
		payload.Certificate = &certVal
	}

	if plan.HTTPProxy.ValueString() != "" && plan.HTTPProxy.ValueString() != types.StringNull().ValueString() {
		httpVal := plan.HTTPProxy.ValueString()
		payload.HTTPProxy = &httpVal
	}

	if plan.HTTPSProxy.ValueString() != "" && plan.HTTPSProxy.ValueString() != types.StringNull().ValueString() {
		httpsVal := plan.HTTPSProxy.ValueString()
		payload.HTTPSProxy = &httpsVal
	}

	var hosts []string
	for _, str := range plan.NoProxy {
		hosts = append(hosts, str.ValueString())
	}
	payload.NoProxy = hosts

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_proxy.go -> Create][" + id + "]")
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_proxy.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error setting proxy information on CipherTrust Manager: ",
			"Could not set proxy information, unexpected error: "+err.Error(),
		)
		return
	}

	r.client.Log.Debug("[resource_proxy.go -> Create Output][" + response + "]")

	plan.ID = types.StringValue("proxy")
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_proxy.go -> Create][" + id + "]")
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
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "CM Proxy"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "CM Proxy", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_proxy.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading Proxy information on CipherTrust Manager: ",
			"Could not read Proxy information: unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue("proxy")

	// Handle certificate - convert empty string to null for consistency
	certFromAPI := gjson.Get(response, "certificate").String()
	if certFromAPI == "" {
		state.Certificate = types.StringNull()
	} else {
		state.Certificate = types.StringValue(certFromAPI)
	}

	// http_proxy: detect structural (non-password) drift; preserve state on password-only change.
	if !state.HTTPProxy.IsNull() {
		if r := gjson.Get(response, "http_proxy"); r.Exists() && r.String() != "" {
			if proxyNonPasswordPart(r.String()) != proxyNonPasswordPart(state.HTTPProxy.ValueString()) {
				// Scheme, host, port, or username changed out-of-band — store new masked value.
				state.HTTPProxy = types.StringValue(r.String())
			}
			// else: non-password portion unchanged → preserve prior state (password-only change,
			// documented known limitation).
		} else {
			// Attribute cleared on CM out-of-band.
			state.HTTPProxy = types.StringNull()
		}
	}
	// else: attribute was never configured — leave state.HTTPProxy null.

	// https_proxy: same pattern.
	if !state.HTTPSProxy.IsNull() {
		if r := gjson.Get(response, "https_proxy"); r.Exists() && r.String() != "" {
			if proxyNonPasswordPart(r.String()) != proxyNonPasswordPart(state.HTTPSProxy.ValueString()) {
				state.HTTPSProxy = types.StringValue(r.String())
			}
			// else: preserve prior state.
		} else {
			state.HTTPSProxy = types.StringNull()
		}
	}
	// else: attribute was never configured — leave state.HTTPSProxy null.

	hosts := gjson.Get(response, "no_proxy").Array()
	var noProxies []types.String
	for _, host := range hosts {
		noProxies = append(noProxies, types.StringValue(host.String()))
	}
	state.NoProxy = noProxies

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_proxy.go -> Read][" + id + "]")
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

	var state CMProxyTFSDK
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	emptyStr := ""

	// Certificate transition
	if !plan.Certificate.IsNull() && !plan.Certificate.IsUnknown() {
		certVal := plan.Certificate.ValueString()
		payload.Certificate = &certVal
	} else if !state.Certificate.IsNull() && !state.Certificate.IsUnknown() {
		payload.Certificate = &emptyStr
	}

	// HTTP Proxy transition
	if !plan.HTTPProxy.IsNull() && !plan.HTTPProxy.IsUnknown() {
		httpVal := plan.HTTPProxy.ValueString()
		payload.HTTPProxy = &httpVal
	} else if !state.HTTPProxy.IsNull() && !state.HTTPProxy.IsUnknown() {
		payload.HTTPProxy = &emptyStr
	}

	// HTTPS Proxy transition
	if !plan.HTTPSProxy.IsNull() && !plan.HTTPSProxy.IsUnknown() {
		httpsVal := plan.HTTPSProxy.ValueString()
		payload.HTTPSProxy = &httpsVal
	} else if !state.HTTPSProxy.IsNull() && !state.HTTPSProxy.IsUnknown() {
		payload.HTTPSProxy = &emptyStr
	}

	// No Proxy transition
	if plan.NoProxy != nil {
		var hosts []string
		for _, str := range plan.NoProxy {
			hosts = append(hosts, str.ValueString())
		}
		payload.NoProxy = hosts
	} else if state.NoProxy != nil {
		payload.NoProxy = []string{}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_proxy.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Proxy Update",
			err.Error(),
		)
		return
	}

	// Use PutData instead of UpdateDataV2 because proxy is a singleton resource (no ID)
	response, err := r.client.PutData(
		ctx,
		id,
		common.URL_CM_PROXY,
		payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_proxy.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Error updating Proxy information on CipherTrust Manager: ",
			"Could not update Proxy information, unexpected error: "+err.Error(),
		)
		return
	}

	// Handle certificate - convert empty string to null for consistency
	certFromAPI := gjson.Get(response, "certificate").String()
	if certFromAPI == "" {
		plan.Certificate = types.StringNull()
	} else {
		plan.Certificate = types.StringValue(certFromAPI)
	}

	// http_proxy / https_proxy: TFIN-527 — preserve the plan value after a successful
	// update. CM's password-masking implementation corrupts the non-password portion of
	// the proxy URL in its PUT response (e.g. "http://proxyuser:p@host" comes back as
	// "httxxxxxx://xxxxxxroxyuser:xxxxxx@host" — scheme and username partially overwritten
	// by mask characters). This corruption is non-deterministic and depends on the byte
	// length of the previous and new credentials. Passing CM's corrupted response to
	// proxyNonPasswordPart() produces a structural mismatch against the plan value, which
	// causes the provider to write the corrupted masked string to state — and
	// terraform-plugin-framework then rejects the state as inconsistent with the plan.
	//
	// Since the PUT returned 200 (success), the planned value IS now the server state.
	// Preserve the plan value unconditionally. The API response is lossy/corrupted for
	// this specific field; it must not be used to hydrate state after an update.
	// (Read() uses proxyNonPasswordPart() for structural drift detection and is unaffected.)
	if !plan.HTTPProxy.IsNull() {
		if r := gjson.Get(response, "http_proxy"); r.Exists() && r.String() != "" {
			// Preserve the cleartext plan value — do not use CM's masked/corrupted response.
			// plan.HTTPProxy already holds the correct post-update state.
		} else {
			plan.HTTPProxy = types.StringNull()
		}
	}

	if !plan.HTTPSProxy.IsNull() {
		if r := gjson.Get(response, "https_proxy"); r.Exists() && r.String() != "" {
			// Preserve the cleartext plan value — do not use CM's masked/corrupted response.
		} else {
			plan.HTTPSProxy = types.StringNull()
		}
	}

	noProxyHosts := gjson.Get(response, "no_proxy").Array()
	var noProxies []types.String
	for _, host := range noProxyHosts {
		noProxies = append(noProxies, types.StringValue(host.String()))
	}
	plan.NoProxy = noProxies

	plan.ID = types.StringValue("proxy")
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
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_proxy.go -> Delete][" + id + "][" + output + "]")
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

func (r *resourceCMProxy) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// proxyNonPasswordPart returns "scheme://username@host:port" for a proxy URL,
// intentionally excluding the password. Returns empty string on parse failure or
// if no host is present (e.g. schemeless URLs, which the schema validator now rejects).
// Used to detect structural (non-password) drift without exposing the password.
//
// net/url correctness:
//
//	url.Parse("http://user01:xxxxxx@10.0.0.1:8080").User.Username() == "user01"
//	url.Parse("http://user01:cleartext@10.0.0.1:8080").User.Username() == "user01"
//
// Both forms produce the same non-password string — no spurious diff after apply.
func proxyNonPasswordPart(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	username := ""
	if u.User != nil {
		username = u.User.Username()
	}
	if username != "" {
		return fmt.Sprintf("%s://%s@%s", u.Scheme, username, u.Host)
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
