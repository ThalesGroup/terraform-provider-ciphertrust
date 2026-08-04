// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceInterfaceCertificateRenewal{}
	_ resource.ResourceWithConfigure      = &resourceInterfaceCertificateRenewal{}
	_ resource.ResourceWithValidateConfig = &resourceInterfaceCertificateRenewal{}
	_ resource.ResourceWithModifyPlan     = &resourceInterfaceCertificateRenewal{}
)

func NewResourceInterfaceCertificateRenewal() resource.Resource {
	return &resourceInterfaceCertificateRenewal{}
}

type resourceInterfaceCertificateRenewal struct {
	client *common.Client
}

// InterfaceCertificateRenewalTFSDK is the Terraform plan/state model for
// ciphertrust_interface_certificate_renewal.
type InterfaceCertificateRenewalTFSDK struct {
	ID                 types.String `tfsdk:"id"`
	InterfaceName      types.String `tfsdk:"interface_name"`
	Certificate        types.String `tfsdk:"certificate"`
	Format             types.String `tfsdk:"format"`
	Password           types.String `tfsdk:"password"`
	Generate           types.Bool   `tfsdk:"generate"`
	SkipValidation     types.Bool   `tfsdk:"skip_validation"`
	Trigger            types.String `tfsdk:"trigger"`
	AppliedCertificate types.String `tfsdk:"applied_certificate"`
}

// interfaceRenewalCertificatePayloadJSON is the wire payload for
// PUT api/v1/configs/interfaces/{interface}/renewal-certificate.
type interfaceRenewalCertificatePayloadJSON struct {
	Certificate    string `json:"certificate,omitempty"`
	Format         string `json:"format,omitempty"`
	Password       string `json:"password,omitempty"`
	Generate       bool   `json:"generate,omitempty"`
	SkipValidation bool   `json:"skip_validation,omitempty"`
}

func (r *resourceInterfaceCertificateRenewal) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface_certificate_renewal"
}

func (r *resourceInterfaceCertificateRenewal) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_interface_certificate_renewal", resp)
}

func (r *resourceInterfaceCertificateRenewal) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = client
}

func (r *resourceInterfaceCertificateRenewal) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Renews the TLS server certificate of a CipherTrust Manager interface (web, NAE, KMIP, or SNMP). " +
			"Each time the trigger value changes, this resource stages a new certificate as the interface's upcoming " +
			"certificate (PUT .../renewal-certificate) and then applies it (POST .../renewal-certificate/apply) exactly " +
			"once. This is a single-shot operation: once staged and applied it is never retried automatically. " +
			"To perform another renewal, change the trigger value to cause resource replacement. " +
			"**Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier in the form <interface_name>/<trigger>.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"interface_name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Name of the ciphertrust_interface whose certificate will be renewed.",
			},
			"certificate": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) The certificate and key data in PEM format or base64 encoded PKCS12 format. A chain of certs may be included - it must be in ascending order (server to root ca). Not used when generate is true. Changing this value causes resource replacement.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"format": schema.StringAttribute{
				Optional:    true,
				Description: "(Immutable) The format of the certificate data (PEM or PKCS12). Required unless generate is true. Changing this value causes resource replacement.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"PEM", "PKCS12"}...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				Description: "Password to the encrypted key, if the certificate data is an encrypted PKCS12. " +
					"Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). " +
					"No RequiresReplace modifier on this attribute — since it is write-only, its own value can " +
					"never be diffed against a prior value. `trigger` is the signal that controls when a " +
					"renewal (and re-send of `password`) happens; change `trigger` to perform another renewal.",
			},
			"generate": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) Create a new self-signed certificate instead of importing certificate/format. Changing this value causes resource replacement.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"skip_validation": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) Disables the certificate chain validation. Default set to false by CipherTrust Manager. Changing this value causes resource replacement.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"trigger": schema.StringAttribute{
				Required: true,
				Description: "Arbitrary user-supplied value that controls when a renewal is requested. " +
					"Changing this value causes resource replacement, which stages and applies exactly one additional renewal.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"applied_certificate": schema.StringAttribute{
				Computed:    true,
				Description: "The PEM certificate that was staged and applied to the interface by this renewal.",
			},
		},
	}
}

// Create stages the configured certificate as the interface's upcoming certificate,
// then applies it exactly once. Both calls are single-shot: if apply fails after a
// successful stage, this resource is not written to state and the user must re-apply
// (which re-stages the same certificate and retries apply) rather than relying on
// automatic retries.
func (r *resourceInterfaceCertificateRenewal) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface_certificate_renewal.go -> Create][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface_certificate_renewal.go -> Create][" + id + "]")

	var plan InterfaceCertificateRenewalTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// password is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.Password is always null
	// here. req.Config is populated fresh from the HCL configuration on every RPC (not
	// derived from the nullified plan), so it reliably carries the actual value.
	var config InterfaceCertificateRenewalTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	interfaceName := plan.InterfaceName.ValueString()

	// Verify the target interface exists. CM's interface API uses NAME (not UUID) as
	// the path key for this whole endpoint family, same exception documented in
	// resource_interface.go's Read.
	if _, err := r.client.ReadDataByParam(ctx, id, interfaceName, common.URL_INTERFACE); err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface_certificate_renewal.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error looking up target interface on CipherTrust Manager",
			"Could not read interface \""+interfaceName+"\": "+err.Error(),
		)
		return
	}

	payload := interfaceRenewalCertificatePayloadJSON{
		Certificate:    plan.Certificate.ValueString(),
		Format:         plan.Format.ValueString(),
		Password:       config.Password.ValueString(),
		Generate:       plan.Generate.ValueBool(),
		SkipValidation: plan.SkipValidation.ValueBool(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface_certificate_renewal.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Interface Certificate Renewal",
			err.Error(),
		)
		return
	}

	stageResponse, err := r.client.PutData(ctx, id, common.URL_INTERFACE+"/"+interfaceName+"/renewal-certificate", payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface_certificate_renewal.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error staging upcoming certificate on CipherTrust Manager",
			"Could not stage renewal certificate for interface \""+interfaceName+"\": "+err.Error(),
		)
		return
	}
	stagedCertificate := gjson.Get(stageResponse, "certificates").String()

	// Apply the staged certificate exactly once. This is a single-shot action: if it
	// succeeds it must NOT be retried, even if a later step fails.
	if _, err := r.client.PostNoData(ctx, id, common.URL_INTERFACE+"/"+interfaceName+"/renewal-certificate/apply"); err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface_certificate_renewal.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error applying upcoming certificate on CipherTrust Manager",
			"The certificate was staged as upcoming for interface \""+interfaceName+"\" but applying it failed: "+err.Error()+
				". The staged certificate remains pending; re-running apply will retry both steps.",
		)
		return
	}

	plan.ID = types.StringValue(interfaceName + "/" + plan.Trigger.ValueString())
	plan.AppliedCertificate = types.StringValue(stagedCertificate)
	// password is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.Password = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read confirms the target interface still has an active certificate. There is no
// persistent "renewal" object to refresh - this is a best-effort verification, not a
// full refresh of the applied certificate.
func (r *resourceInterfaceCertificateRenewal) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface_certificate_renewal.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface_certificate_renewal.go -> Read][" + id + "]")

	var state InterfaceCertificateRenewalTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	interfaceName := state.InterfaceName.ValueString()

	response, err := r.client.GetById(ctx, id, interfaceName+"/certificate", common.URL_INTERFACE)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"CM Interface Not Found — State Preserved",
				"The interface \""+interfaceName+"\" was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface_certificate_renewal.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading active certificate for interface on CipherTrust Manager",
			"Could not read certificate for interface \""+interfaceName+"\": "+err.Error(),
		)
		return
	}

	if r := gjson.Get(response, "certificates"); r.Exists() && r.String() != "" {
		state.AppliedCertificate = types.StringValue(r.String())
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is a no-op. interface_name is immutable (enforced in ModifyPlan) and trigger
// uses RequiresReplace, so Update should never be called in practice.
func (r *resourceInterfaceCertificateRenewal) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete is a no-op. Removing this resource from state does not revert the applied
// certificate on the interface.
func (r *resourceInterfaceCertificateRenewal) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ModifyPlan enforces immutability of interface_name after creation.
func (r *resourceInterfaceCertificateRenewal) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state InterfaceCertificateRenewalTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.InterfaceName != state.InterfaceName {
		resp.Diagnostics.AddError(
			"interface_name cannot be changed",
			"The interface_name attribute cannot be modified after this resource is created. "+
				"Delete and recreate this resource to renew the certificate of a different interface.",
		)
	}
}
