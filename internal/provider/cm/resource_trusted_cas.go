package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
)

var (
	_ resource.Resource              = &resourceCMTrustedCAs{}
	_ resource.ResourceWithConfigure = &resourceCMTrustedCAs{}
)

type resourceCMTrustedCAs struct {
	client *common.Client
}

func NewResourceTrustedCas() resource.Resource {
	return &resourceCMTrustedCAs{}
}

func (r *resourceCMTrustedCAs) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trusted_cas"
}

func (r *resourceCMTrustedCAs) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*common.Client)
}

func (r *resourceCMTrustedCAs) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Trusted CA entry on CipherTrust Manager. Use ca_id and service for the single-create path. Use cert_list for bulk creation via POST /v1/trusted-cas-create-many; ca_id and service are still required by the schema but are not forwarded to the bulk endpoint. Changing cert_list after initial creation is a no-op in CM; only the first bulk-created CA is tracked in Terraform state. CM permits duplicate ca_id+service entries — each POST creates an independent row with a unique id.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the trusted CA entry.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "The URI of the trusted CA entry.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "Account the trusted CA belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"application": schema.StringAttribute{
				Computed:    true,
				Description: "Application the trusted CA belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
				Computed:    true,
				Description: "Developer account the trusted CA belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the trusted CA entry was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the trusted CA entry was last updated. Not stable after PATCH — no UseStateForUnknown.",
			},
			"ca_id": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The identifier (URI) of the Local CA resource to trust. Always required; not forwarded to the bulk endpoint when cert_list is set.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"service": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The service for which the CA is being trusted (e.g. nae, web, kmip). Always required; not forwarded to the bulk endpoint when cert_list is set.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"auto_restart": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, automatically restart the service after adding the trusted CA.",
			},
			"ca_type": schema.StringAttribute{
				Optional:    true,
				Description: "Type of the CA being trusted (e.g. local, external). CM does not return an empty string for this field; the absent-branch sets null in state.",
			},
			"cert_list": schema.StringAttribute{
				Optional:    true,
				Description: "JSON array string of CA objects for bulk creation via POST /v1/trusted-cas-create-many. When set, the bulk endpoint is used; ca_id and service are still required but not forwarded. Only the first created CA is tracked in state. Changing this field after initial creation is a no-op in CM.",
			},
			"subject": schema.StringAttribute{
				Computed:    true,
				Description: "Subject of the trusted CA certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"issuer": schema.StringAttribute{
				Computed:    true,
				Description: "Issuer of the trusted CA certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"serial_number": schema.StringAttribute{
				Computed:    true,
				Description: "Serial number of the trusted CA certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sha1_fingerprint": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-1 fingerprint of the trusted CA certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sha256_fingerprint": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 fingerprint of the trusted CA certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"not_before": schema.StringAttribute{
				Computed:    true,
				Description: "Certificate validity start timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"not_after": schema.StringAttribute{
				Computed:    true,
				Description: "Certificate validity end timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *resourceCMTrustedCAs) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_trusted_cas.go -> Create][" + id + "]")

	var plan CMTrustedCAsTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var response string
	var err error
	var gjsonPrefix string
	isBulk := !plan.CertList.IsNull() && plan.CertList.ValueString() != ""

	if isBulk {
		gjsonPrefix = "0."
		response, err = r.client.PostDataV2(ctx, id, common.URL_TRUSTED_CAS_CREATE_MANY, []byte(plan.CertList.ValueString()))
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating Trusted CAs (bulk) on CipherTrust Manager: ",
				"Could not create Trusted CAs, unexpected error: "+err.Error(),
			)
			return
		}
	} else {
		gjsonPrefix = ""
		var payload CMTrustedCAsJSON
		payload.CAID = plan.CAID.ValueString()
		payload.Service = plan.Service.ValueString()
		if !plan.AutoRestart.IsNull() {
			payload.AutoRestart = plan.AutoRestart.ValueBool()
		}
		if !plan.CAType.IsNull() {
			payload.CAType = plan.CAType.ValueString()
		}
		payloadJSON, err2 := json.Marshal(payload)
		if err2 != nil {
			resp.Diagnostics.AddError("Invalid data input: Trusted CA Creation", err2.Error())
			return
		}
		response, err = r.client.PostDataV2(ctx, id, common.URL_TRUSTED_CAS, payloadJSON)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating Trusted CA on CipherTrust Manager: ",
				"Could not create Trusted CA, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Computed-only — hydrate unconditionally.
	plan.ID = types.StringValue(gjson.Get(response, gjsonPrefix+"id").String())
	plan.URI = types.StringValue(gjson.Get(response, gjsonPrefix+"uri").String())
	plan.Account = types.StringValue(gjson.Get(response, gjsonPrefix+"account").String())
	plan.Application = types.StringValue(gjson.Get(response, gjsonPrefix+"application").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, gjsonPrefix+"devAccount").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, gjsonPrefix+"createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, gjsonPrefix+"updatedAt").String())
	plan.Subject = types.StringValue(gjson.Get(response, gjsonPrefix+"subject").String())
	plan.Issuer = types.StringValue(gjson.Get(response, gjsonPrefix+"issuer").String())
	plan.SerialNumber = types.StringValue(gjson.Get(response, gjsonPrefix+"serial_number").String())
	plan.SHA1Fingerprint = types.StringValue(gjson.Get(response, gjsonPrefix+"sha1Fingerprint").String())
	plan.SHA256Fingerprint = types.StringValue(gjson.Get(response, gjsonPrefix+"sha256Fingerprint").String())
	plan.NotBefore = types.StringValue(gjson.Get(response, gjsonPrefix+"notBefore").String())
	plan.NotAfter = types.StringValue(gjson.Get(response, gjsonPrefix+"notAfter").String())

	// Required: ca_id and service.
	// Single path: echo from API response.
	// Bulk path: preserve from plan — the bulk endpoint does not return ca_id or service.
	if !isBulk {
		plan.CAID = types.StringValue(gjson.Get(response, "ca_id").String())
		plan.Service = types.StringValue(gjson.Get(response, "service").String())
	}

	// Optional bool: auto_restart — guarded by IsNull (pure Optional, cannot be unknown).
	if !plan.AutoRestart.IsNull() {
		if r2 := gjson.Get(response, gjsonPrefix+"auto_restart"); r2.Exists() {
			plan.AutoRestart = types.BoolValue(r2.Bool())
		} else {
			plan.AutoRestart = types.BoolNull()
		}
	}

	// Optional string: ca_type — guarded by IsNull. CM does not return an empty string for ca_type.
	if !plan.CAType.IsNull() {
		if r2 := gjson.Get(response, gjsonPrefix+"ca_type"); r2.Exists() {
			plan.CAType = types.StringValue(r2.String())
		} else {
			plan.CAType = types.StringNull()
		}
	}

	// cert_list is write-only: plan.CertList already holds the user value; no hydration needed.

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read is a no-op: state is populated from the Create() POST response only.
func (r *resourceCMTrustedCAs) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *resourceCMTrustedCAs) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_trusted_cas.go -> Update][" + id + "]")

	var plan CMTrustedCAsTFSDK
	var state CMTrustedCAsTFSDK

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

	payload := make(map[string]interface{})

	// auto_restart: send when changed. Null transition sends false to clear in CM.
	if !plan.AutoRestart.Equal(state.AutoRestart) {
		if !plan.AutoRestart.IsNull() {
			payload["auto_restart"] = plan.AutoRestart.ValueBool()
		} else if !state.AutoRestart.IsNull() {
			payload["auto_restart"] = false
		}
	}

	// ca_type: send when changed. Null transition sends "" to clear in CM.
	if !plan.CAType.Equal(state.CAType) {
		if !plan.CAType.IsNull() {
			payload["ca_type"] = plan.CAType.ValueString()
		} else if !state.CAType.IsNull() {
			payload["ca_type"] = ""
		}
	}

	// Skip PATCH when no mutable field changed.
	if len(payload) == 0 {
		plan.ID = state.ID
		plan.URI = state.URI
		plan.Account = state.Account
		plan.Application = state.Application
		plan.DevAccount = state.DevAccount
		plan.CreatedAt = state.CreatedAt
		plan.UpdatedAt = state.UpdatedAt
		plan.CAID = state.CAID
		plan.Service = state.Service
		plan.CertList = state.CertList
		plan.Subject = state.Subject
		plan.Issuer = state.Issuer
		plan.SerialNumber = state.SerialNumber
		plan.SHA1Fingerprint = state.SHA1Fingerprint
		plan.SHA256Fingerprint = state.SHA256Fingerprint
		plan.NotBefore = state.NotBefore
		plan.NotAfter = state.NotAfter
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Update][" + id + "]")
		diags = resp.State.Set(ctx, plan)
		resp.Diagnostics.Append(diags...)
		return
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		resp.Diagnostics.AddError("Invalid data input: Trusted CA Update", err.Error())
		return
	}

	// Use state.ID as the URL path key: PATCH /v1/trusted-cas/{id}
	updatedAt, err := r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_TRUSTED_CAS, payloadJSON, "updatedAt")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Error updating Trusted CA on CipherTrust Manager: ",
			"Could not update Trusted CA, unexpected error: "+err.Error(),
		)
		return
	}

	plan.UpdatedAt = types.StringValue(updatedAt)

	// Preserve stable Computed-only fields from prior state.
	plan.ID = state.ID
	plan.URI = state.URI
	plan.Account = state.Account
	plan.Application = state.Application
	plan.DevAccount = state.DevAccount
	plan.CreatedAt = state.CreatedAt
	plan.Subject = state.Subject
	plan.Issuer = state.Issuer
	plan.SerialNumber = state.SerialNumber
	plan.SHA1Fingerprint = state.SHA1Fingerprint
	plan.SHA256Fingerprint = state.SHA256Fingerprint
	plan.NotBefore = state.NotBefore
	plan.NotAfter = state.NotAfter

	// Preserve immutable Required fields and write-only field from state.
	plan.CAID = state.CAID
	plan.Service = state.Service
	plan.CertList = state.CertList

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Update][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *resourceCMTrustedCAs) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMTrustedCAsTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_trusted_cas.go -> Delete][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteURL := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_TRUSTED_CAS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), deleteURL, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				common.NotFoundDeleteWarningSummary,
				fmt.Sprintf(common.NotFoundDeleteWarningDetailFmt, "CM Trusted CA", state.ID.ValueString()),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Trusted CA",
			"Could not delete Trusted CA, unexpected error: "+err.Error(),
		)
		return
	}
}
