package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIConnection{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIConnection{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIConnection{}
)

func NewResourceCCKMOCIConnection() resource.Resource {
	return &resourceCCKMOCIConnection{}
}

type resourceCCKMOCIConnection struct {
	client *common.Client
}

func (r *resourceCCKMOCIConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_connection"
}

func (d *resourceCCKMOCIConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Schema defines the schema for the resource.
func (r *resourceCCKMOCIConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The APIs in this section deal with connections to the OCI cloud. " +
			"The following operations can be performed:\n* Create/Delete/Get/Update an OCI connection.\n",
		Attributes: map[string]schema.Attribute{
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the connection was created.",
			},
			// description: Optional+Computed with UseStateWhenClearingString so that removing
			// the attribute from config preserves the prior value in state (TFIN-569). CM does not
			// support clearing description via PATCH, so the plan modifier correctly prevents the
			// plan=null / state="old text" mismatch that would crash the post-apply consistency check.
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
				Description: "Description about the connection. Once set, this field cannot be cleared back to empty — CM does not support clearing it via PATCH. Removing this attribute from config preserves the existing value.",
			},
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager resource ID of the connection.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_file": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Path to or data of the OCI private key file (PEM format). Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). To resend a rotated key (and/or its passphrase), change `key_file`/`key_file_pass_phrase` and bump `key_file_version` in the same apply.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"key_file_version": schema.Int64Attribute{
				Optional:    true,
				Description: "Arbitrary version number used to trigger re-sending `key_file`/`key_file_pass_phrase` to CipherTrust Manager. Since both are write-only, Terraform cannot detect a change in their values on its own; increment this on every apply where you want the current values re-sent.",
			},
			"key_file_pass_phrase": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Passphrase if the OCI key file is encrypted. Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). Resent together with key_file — see key_file_version.",
			},
			// meta: Optional+Computed with UseStateWhenClearingMap so that removing the attribute
			// from config preserves the prior value in state (TFIN-569). CM's merge-PATCH semantics
			// mean omitting the field leaves it unchanged; the modifier prevents the plan=null /
			// state={...} mismatch that would crash the post-apply consistency check.
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.UseStateForUnknown(),
					modifiers.UseStateWhenClearingMap(),
				},
				Description: "Optional end-user or service data stored with the connection.",
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "(Immutable) Unique connection name.",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"pub_key_fingerprint": schema.StringAttribute{
				Required:    true,
				Description: "Fingerprint of the public key added to the OCI user.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"products": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Array of the CipherTrust products to associate with the connection. Default is 'cckm'",
				Default:     listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{types.StringValue("cckm")})),
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("cckm", "ddc", "cte", "data discovery", "backup/restore", "logger", "hsm_anchored_domain", "csm"),
					),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "OCI connection region.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"tenancy_ocid": schema.StringAttribute{
				Required:    true,
				Description: "Tenant OCID.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"user_ocid": schema.StringAttribute{
				Required:    true,
				Description: "User OCID.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time of last update.",
			},
			"uri":                   schema.StringAttribute{Computed: true},
			"account":               schema.StringAttribute{Computed: true},
			"service":               schema.StringAttribute{Computed: true},
			"category":              schema.StringAttribute{Computed: true},
			"resource_url":          schema.StringAttribute{Computed: true},
			"last_connection_ok":    schema.BoolAttribute{Computed: true},
			"last_connection_error": schema.StringAttribute{Computed: true},
			"last_connection_at":    schema.StringAttribute{Computed: true},
			"skip_connection_params_test": schema.BoolAttribute{
				Optional:    true,
				Description: "Set to true to skip connection parameter test.",
			},
		},
	}
}

// Create creates a new OCI connection resource on CipherTrust Manager.
func (r *resourceCCKMOCIConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_oci_connection.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_oci_connection.go -> Create][" + id + "]")

	var plan OCIConnectionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_file / key_file_pass_phrase are write-only: the framework nulls them out of
	// PlannedState during PlanResourceChange, before Create() ever runs, so
	// plan.KeyFile/plan.PassPhrase are always null here. req.Config is populated fresh
	// from the HCL configuration on every RPC (not derived from the nullified plan), so
	// it reliably carries the actual values.
	var config OCIConnectionTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// User can give path the pem file or pem data.
	keyFileData := readKeyFileData(ctx, config.KeyFile.ValueString(), &resp.Diagnostics, r.client.Log)
	if resp.Diagnostics.HasError() {
		return
	}

	credentials := OCIConnectionCredentialsJSON{
		PassPhrase: config.PassPhrase.ValueString(),
		KeyFile:    keyFileData,
	}

	payload := OCIConnectionJSON{
		Name: plan.Name.ValueString(),
		OCIConnectionCommonJSON: OCIConnectionCommonJSON{
			Description: plan.Description.ValueString(),
			Fingerprint: plan.Fingerprint.ValueString(),
			Region:      plan.Region.ValueString(),
			TenancyOCID: plan.TenancyOcid.ValueString(),
			UserOCID:    plan.UserOcid.ValueString(),
		},
		Credentials: credentials,
	}

	if len(plan.Meta.Elements()) != 0 {
		ociMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			ociMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = ociMetadataPayload
	}

	if len(plan.Products.Elements()) != 0 {
		var ociProducts []string
		resp.Diagnostics.Append(plan.Products.ElementsAs(ctx, &ociProducts, false)...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Error(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = ociProducts
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: OCI connection Creation",
			err.Error(),
		)
		return
	}

	if !plan.SkipConnectionParamsTest.ValueBool() {
		r.testConnectionParameters(ctx, id, payloadJSON, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating OCI Connection on CipherTrust Manager: ",
			"Could not create oci connection, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// The connection has been created, no errors returned after this

	var testConnectionDiags diag.Diagnostics
	r.testConnection(ctx, id, plan.ID.ValueString(), &testConnectionDiags)
	if testConnectionDiags.HasError() {
		for _, d := range testConnectionDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	response, err = r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddWarning(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+plan.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	var getParamsDiags diag.Diagnostics
	r.getOciParamsFromResponse(ctx, response, &getParamsDiags, &plan)
	if getParamsDiags.HasError() {
		for _, d := range getParamsDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	// key_file / key_file_pass_phrase are write-only — the framework nulls them from
	// outgoing state/plan artifacts automatically, but null them explicitly too for clarity.
	plan.KeyFile = types.StringNull()
	plan.PassPhrase = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the OCI connection resource state from CipherTrust Manager.
func (r *resourceCCKMOCIConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_oci_connection.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_oci_connection.go -> Read][" + id + "]")

	var state OCIConnectionTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "OCI Connection"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "OCI Connection", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+state.ID.ValueString()+" unexpected error: "+err.Error(),
		)
		return
	}

	r.getOciParamsFromResponse(ctx, response, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update modifies an existing OCI connection resource on CipherTrust Manager.
func (r *resourceCCKMOCIConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {

	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_oci_connection.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_oci_connection.go -> Update][" + id + "]")

	var plan OCIConnectionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state OCIConnectionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_file / key_file_pass_phrase are write-only: the framework nulls them out of
	// PlannedState during PlanResourceChange, before Update() ever runs, so
	// plan.KeyFile/plan.PassPhrase are always null here. req.Config is populated fresh
	// from the HCL configuration on every RPC (not derived from the nullified plan), so
	// it reliably carries the actual values.
	var config OCIConnectionTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	var payload OCIConnectionUpdateJSON
	// key_file / key_file_pass_phrase are write-only (never stored in state), so their own
	// values can never be diffed against a prior value — key_file_version is the explicit,
	// state-tracked signal that the caller wants the current values re-sent to CM.
	if !plan.KeyFileVersion.Equal(state.KeyFileVersion) {
		keyFileData := readKeyFileData(ctx, config.KeyFile.ValueString(), &resp.Diagnostics, r.client.Log)
		if resp.Diagnostics.HasError() {
			return
		}
		credentials := OCIConnectionCredentialsJSON{
			PassPhrase: config.PassPhrase.ValueString(),
			KeyFile:    keyFileData,
		}
		payload.Credentials = credentials
	}

	if plan.Description.ValueString() != gjson.Get(response, "description").String() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.Fingerprint.ValueString() != gjson.Get(response, "fingerprint").String() {
		payload.Fingerprint = plan.Fingerprint.ValueString()
	}

	// If meta not specified in config/plan, do not manage it.
	// Use meta = {} to remove all keys.
	if !(plan.Meta.IsNull() || plan.Meta.IsUnknown()) {

		// Desired meta from plan (strings)
		planMetadata := map[string]interface{}{}
		for k, v := range plan.Meta.Elements() {
			if s, ok := v.(types.String); ok {
				// handle null just in case (rare for map(string))
				if s.IsNull() {
					planMetadata[k] = nil
				} else {
					planMetadata[k] = s.ValueString()
				}
			}
		}

		// Current meta from CM (normalize to strings)
		connectionMeta := map[string]interface{}{}
		if metaVal := gjson.Get(response, "meta"); metaVal.Exists() && metaVal.Type == gjson.JSON {
			if metaMap, ok := gjson.Parse(metaVal.Raw).Value().(map[string]interface{}); ok {
				for key, value := range metaMap {
					if value == nil {
						connectionMeta[key] = nil
					} else {
						connectionMeta[key] = fmt.Sprintf("%v", value)
					}
				}
			}
		}

		// Add deletes for keys removed from config (including meta = {} => delete all)
		for key := range connectionMeta {
			if _, exists := planMetadata[key]; !exists {
				planMetadata[key] = nil
			}
		}

		// Update only if needed
		if !reflect.DeepEqual(planMetadata, connectionMeta) {
			payload.Meta = planMetadata
		}
	}

	var planProducts []string
	resp.Diagnostics.Append(plan.Products.ElementsAs(ctx, &planProducts, false)...)
	if resp.Diagnostics.HasError() {
		r.client.Log.Error(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
		return
	}
	var connectionProducts []string
	if gjson.Get(response, "products").Exists() {
		for _, p := range gjson.Get(response, "products").Value().([]interface{}) {
			connectionProducts = append(connectionProducts, p.(string))
		}
	}
	if !reflect.DeepEqual(planProducts, connectionProducts) {
		payload.Products = &planProducts
	}

	if plan.TenancyOcid.ValueString() != gjson.Get(response, "tenancy_ocid").String() {
		payload.TenancyOCID = plan.TenancyOcid.ValueString()
	}

	if plan.UserOcid.ValueString() != gjson.Get(response, "user_ocid").String() {
		payload.UserOCID = plan.UserOcid.ValueString()
	}

	if plan.Region.ValueString() != gjson.Get(response, "region").String() {
		payload.Region = plan.Region.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: OCI connection update",
			err.Error(),
		)
		return
	}

	connectionID := gjson.Get(response, "id").String()
	response, err = r.client.UpdateDataV2(ctx, connectionID, common.URL_OCI_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating OCI Connection on CipherTrust Manager: ",
			"Could not update oci connection, unexpected error: "+err.Error(),
		)
		return
	}

	response, err = r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	r.getOciParamsFromResponse(ctx, response, &resp.Diagnostics, &plan)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_file / key_file_pass_phrase are write-only — the framework nulls them from
	// outgoing state/plan artifacts automatically, but null them explicitly too for clarity.
	plan.KeyFile = types.StringNull()
	plan.PassPhrase = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes an OCI connection resource from CipherTrust Manager.
func (r *resourceCCKMOCIConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_oci_connection.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_oci_connection.go -> Delete][" + id + "]")

	var state OCIConnectionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_OCI_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddWarning(
				common.NotFoundDeleteWarningSummary,
				fmt.Sprintf(common.NotFoundDeleteWarningDetailFmt, "OCI Connection", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> Delete][" + id + "][" + output + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust OCI Connection",
			"Could not delete oci connection, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState imports an existing OCI connection resource into Terraform state using the connection ID.
func (r *resourceCCKMOCIConnection) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_oci_connection.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_oci_connection.go -> ImportState][" + id + "]")

	response, err := r.client.GetById(ctx, id, req.ID, common.URL_OCI_CONNECTION)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> ImportState][" + id + "]")
		resp.Diagnostics.AddError(
			"Error importing OCI Connection from CipherTrust Manager: ",
			"Could not read oci connection id: "+req.ID+", unexpected error: "+err.Error(),
		)
		return
	}

	var state OCIConnectionTFSDK
	r.getOciParamsFromResponse(ctx, response, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// getOciParamsFromResponse populates the TFSDK model from a CM API response JSON string.
func (r *resourceCCKMOCIConnection) getOciParamsFromResponse(ctx context.Context, response string, diags *diag.Diagnostics, data *OCIConnectionTFSDK) {
	// Common parameters for all connections
	data.ID = types.StringValue(gjson.Get(response, "id").String())
	data.URI = types.StringValue(gjson.Get(response, "uri").String())
	data.Account = types.StringValue(gjson.Get(response, "account").String())
	data.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	data.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	data.Category = types.StringValue(gjson.Get(response, "category").String())
	data.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	data.Service = types.StringValue(gjson.Get(response, "service").String())
	data.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	data.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	data.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())
	// Connection identity fields returned by CM on every read.
	data.Name = types.StringValue(gjson.Get(response, "name").String())
	// description: hydrate unconditionally so drift is detected. Clear to null when absent
	// or empty-string so stale state is not preserved after a CM-side removal — UNLESS the
	// value already on hand is itself a deliberately-empty string (e.g. description = "" from
	// config on Create/Update). CM has no wire representation for "explicitly empty" versus
	// "unset", so without this guard a plan of description = "" would be overwritten with null
	// here and Terraform's post-apply consistency check would crash (.description: was
	// cty.StringVal(""), but now null).
	if desc := gjson.Get(response, "description"); desc.Exists() && desc.String() != "" {
		data.Description = types.StringValue(desc.String())
	} else if data.Description.IsNull() || data.Description.IsUnknown() || data.Description.ValueString() != "" {
		data.Description = types.StringNull()
	}
	data.Fingerprint = types.StringValue(gjson.Get(response, "fingerprint").String())
	data.Region = types.StringValue(gjson.Get(response, "region").String())
	data.TenancyOcid = types.StringValue(gjson.Get(response, "tenancy_ocid").String())
	data.UserOcid = types.StringValue(gjson.Get(response, "user_ocid").String())
	// meta: always assign a typed value to avoid DynamicPseudoType zero-value conversion error.
	// Same explicitly-empty-vs-unset reasoning as description above: a plan of meta = {} is a
	// known, non-null empty map, and CM omits/nulls the field on the wire when it has nothing
	// to return — collapsing that straight to null here would contradict the plan and crash
	// Terraform's post-apply consistency check (.meta: was cty.MapValEmpty(cty.String), but now
	// null). Preserve the value already on hand when it is itself a deliberately-empty map.
	if len(gjson.Get(response, "meta").String()) > 0 {
		data.Meta = common.ParseMap(response, diags, "meta")
	} else if data.Meta.IsNull() || data.Meta.IsUnknown() || len(data.Meta.Elements()) != 0 {
		data.Meta = types.MapNull(types.StringType)
	}
	if len(gjson.Get(response, "products").String()) > 0 {
		data.Products = common.ParseArray(response, "products")
	}
}

// readKeyFileData resolves the key_file attribute: if it is a filesystem path, the file is read
// and its contents returned; otherwise the raw value is returned as-is (inline PEM data).
func readKeyFileData(ctx context.Context, inputParam string, diags *diag.Diagnostics, logger hclog.Logger) string {
	inputParam = strings.TrimSpace(inputParam)
	_, err := os.Stat(inputParam)
	if err == nil {
		var data []byte
		data, err = os.ReadFile(inputParam)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to read key file %s,error: %s", inputParam, err.Error()))
			diags.AddError(
				"Failed to create OCI connection.",
				"Error reading 'key_file' parameter, unexpected error: "+err.Error(),
			)
			return ""
		}
		return string(data)
	}
	return inputParam
}

// testConnectionParameters sends the connection payload to the CM test endpoint before creating the
// connection, failing fast if the credentials are invalid.
func (r *resourceCCKMOCIConnection) testConnectionParameters(ctx context.Context, id string, payloadJSON []byte, diags *diag.Diagnostics) {
	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI_CONNECTION_TEST, payloadJSON)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> test connection params][" + id + "]")
		diags.AddError(
			"Error testing OCI Connection parameters on CipherTrust Manager: ",
			"error: "+err.Error(),
		)
		return
	}
	if !gjson.Get(response, "connection_ok").Bool() {
		diags.AddError(
			"Error testing OCI Connection parameters on CipherTrust Manager: ",
			"Please correct the connection parameters.",
		)
	}
}

// testConnection exercises the test endpoint on an already-created connection and adds a warning if
// the connection is not healthy (non-fatal - the connection resource is still saved to state).
func (r *resourceCCKMOCIConnection) testConnection(ctx context.Context, id string, connectionID string, diags *diag.Diagnostics) {
	response, err := r.client.PostNoData(ctx, id, common.URL_OCI_CONNECTION+"/"+connectionID+"/test")
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_oci_connection.go -> test existing connection][" + id + "]")
		diags.AddError(
			"Error testing OCI Connection on CipherTrust Manager: ",
			"error: "+err.Error(),
		)
		return
	}
	if !gjson.Get(response, "connection_ok").Bool() {
		diags.AddWarning(
			"Error testing OCI Connection on CipherTrust Manager: ",
			"Please test manually to ensure the connection is usable.",
		)
	}
}
