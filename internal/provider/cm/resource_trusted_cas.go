package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &resourceCMTrustedCA{}
	_ resource.ResourceWithConfigure = &resourceCMTrustedCA{}
)

func NewResourceTrustedCas() resource.Resource {
	return &resourceCMTrustedCA{}
}

type resourceCMTrustedCA struct {
	client *common.Client
}

func (r *resourceCMTrustedCA) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trusted_cas"
}

func (r *resourceCMTrustedCA) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCMTrustedCA) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a trusted CA certificate entry on CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the trusted CA entry.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ca_id": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The ID of the CA to be trusted.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"ca_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) The type of the CA (e.g. 'local', 'external'). Server-assigned if not set.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"service": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The service context for this trusted CA.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"auto_restart": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) If true, automatically restart services after bulk-adding trusted CAs. Applies only when use_bulk = true; not sent in the single-entry POST body.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
			"use_bulk": schema.BoolAttribute{
				Optional:    true,
				Description: "(Immutable) If true, use POST /v1/trusted-cas-create-many/ for creation. Stored in Terraform state; never sent to CM.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.ImmutableBool(),
				},
			},
		},
	}
}

func (r *resourceCMTrustedCA) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_trusted_cas.go -> Create][" + id + "]")

	var plan CMTrustedCATFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	entry := CMTrustedCAJSON{
		CAID:    plan.CAID.ValueString(),
		Service: plan.Service.ValueString(),
	}
	if !plan.CAType.IsNull() && !plan.CAType.IsUnknown() {
		entry.CAType = plan.CAType.ValueString()
	}

	var response string
	var err error

	if !plan.UseBulk.IsNull() && plan.UseBulk.ValueBool() {
		bulk := CMTrustedCABulkJSON{
			TrustedCAs: []CMTrustedCAJSON{entry},
		}
		if !plan.AutoRestart.IsNull() && !plan.AutoRestart.IsUnknown() {
			v := plan.AutoRestart.ValueBool()
			bulk.AutoRestart = &v
		}
		bulkJSON, err2 := json.Marshal(bulk)
		if err2 != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err2.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError("Invalid data input: Trusted CA Bulk Creation", err2.Error())
			return
		}
		response, err = r.client.PostDataV2(ctx, id, common.URL_TRUSTED_CAS_CREATE_MANY, bulkJSON)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating Trusted CA (bulk) on CipherTrust Manager: ",
				"Could not create Trusted CA (bulk), unexpected error: "+err.Error(),
			)
			return
		}
		// The bulk POST response uses a "success" array containing the created entries.
		firstID := gjson.Get(response, "success.0.id").String()
		if firstID == "" {
			r.client.Log.Debug(common.ERR_METHOD_END + "bulk POST response did not contain success.0.id; full response: " + response + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating Trusted CA (bulk) on CipherTrust Manager: ",
				"Bulk POST response did not contain a recognisable resource ID. Full response: "+response,
			)
			return
		}
		plan.ID = types.StringValue(firstID)
		if r2 := gjson.Get(response, "success.0.ca_type"); r2.Exists() {
			plan.CAType = types.StringValue(r2.String())
		} else {
			plan.CAType = types.StringNull()
		}
	} else {
		singleJSON, err2 := json.Marshal(entry)
		if err2 != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err2.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError("Invalid data input: Trusted CA Creation", err2.Error())
			return
		}
		response, err = r.client.PostDataV2(ctx, id, common.URL_TRUSTED_CAS, singleJSON)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating Trusted CA on CipherTrust Manager: ",
				"Could not create Trusted CA, unexpected error: "+err.Error(),
			)
			return
		}
		plan.ID = types.StringValue(gjson.Get(response, "id").String())
		// Hydrate ca_type unconditionally — the API assigns it ("local", "external", etc.).
		if r2 := gjson.Get(response, "ca_type"); r2.Exists() {
			plan.CAType = types.StringValue(r2.String())
		} else {
			plan.CAType = types.StringNull()
		}
	}
	// auto_restart and use_bulk are not returned by CM; plan values remain correct.

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *resourceCMTrustedCA) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMTrustedCATFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_trusted_cas.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CM does not expose GET /v1/trusted-cas/{id}; use the list endpoint and filter by ID.
	response, err := r.client.GetAll(ctx, id, common.URL_TRUSTED_CAS)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading Trusted CA on CipherTrust Manager: ",
			"Could not list trusted CAs, unexpected error: "+err.Error(),
		)
		return
	}

	// Find the entry matching our resource ID.
	targetID := state.ID.ValueString()
	var entry gjson.Result
	gjson.Parse(response).ForEach(func(_, v gjson.Result) bool {
		if v.Get("id").String() == targetID {
			entry = v
			return false
		}
		return true
	})

	if !entry.Exists() {
		// Not found — remove from state so Terraform shows a recreate plan.
		resp.State.RemoveResource(ctx)
		return
	}

	// Computed-only — hydrate unconditionally.
	state.ID = types.StringValue(entry.Get("id").String())

	// service is always present in the list response.
	state.Service = types.StringValue(entry.Get("service").String())

	// Optional — gate on Exists() only.
	if r2 := entry.Get("ca_type"); r2.Exists() {
		state.CAType = types.StringValue(r2.String())
	} else {
		state.CAType = types.StringNull()
	}

	// ca_id, auto_restart, use_bulk are not in the list response; preserved via req.State.Get passthrough.

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_trusted_cas.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *resourceCMTrustedCA) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// No PATCH endpoint — all fields are immutable. ImmutableString/Bool plan modifiers
	// prevent Update() from being invoked. This stub satisfies the resource.Resource interface.
}

func (r *resourceCMTrustedCA) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMTrustedCATFSDK
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
				"CipherTrust Trusted CA Not Found",
				"Trusted CA "+state.ID.ValueString()+" was not found during delete; it may have been deleted out-of-band. Terraform will remove it from state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_trusted_cas.go -> Delete][" + id + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Trusted CA",
			"Could not delete trusted CA id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
}
