package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceGCPConnection{}
	_ resource.ResourceWithConfigure = &resourceGCPConnection{}
)

func NewResourceGCPConnection() resource.Resource {
	return &resourceGCPConnection{}
}

type resourceGCPConnection struct {
	client *common.Client
}

func (r *resourceGCPConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcp_connection"
}

// Schema defines the schema for the resource.
func (r *resourceGCPConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The APIs in this section deal with connections to the Google Cloud Platform (GCP). The following operations can be performed:\n* Create/Delete/Get/Update a GCP connection.\n* List all GCP connections.\n* Test an existing GCP connection.\n*Test a connection that hasn't been created yet by passing in the connection parameters.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_file": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "The private key JSON file of a Google Cloud Platform (GCP) service account can be provided either as a JSON file or as a string. Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). To resend a rotated key, change `key_file` and bump `key_file_version` in the same apply.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"key_file_version": schema.Int64Attribute{
				Optional:    true,
				Description: "Arbitrary version number used to trigger re-sending `key_file` to CipherTrust Manager. Since `key_file` is write-only, Terraform cannot detect a change in its value on its own; increment this on every apply where you want the current `key_file` value re-sent.",
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "(Immutable) Unique connection name.",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"cloud_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the cloud. Default value is gcp.\n\nOptions:\n\ngcp",
				Validators:  []validator.String{stringvalidator.OneOf("gcp")},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: labelsDescription,
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Optional end-user or service data stored with the connection.",
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: productsDescription,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("cckm", "ddc", "cte", "data discovery", "backup/restore", "logger", "hsm_anchored_domain", "csm"),
					),
				},
			},
			"client_email": schema.StringAttribute{
				Computed:    true,
				Description: "The GCP service account email address associated with the key file.",
			},
			"private_key_id": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
			},
			//common response parameters (read-only)
			"uri": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			// updated_at intentionally has no UseStateForUnknown(): CM sets a fresh
			// timestamp on every successful update, so showing it as "known after
			// apply" is accurate, not spurious drift.
			"updated_at": schema.StringAttribute{Computed: true},
			"service": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"category": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"resource_url": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_ok": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"last_connection_error": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceGCPConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_gcp_connection.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan GCPConnectionTFSDK
	var payload GCPConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_file is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.KeyFile is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config GCPConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		gcpLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			gcpLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = gcpLabelsPayload
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		gcpMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			gcpMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = gcpMetadataPayload
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var gcpProducts []string
		diags = plan.Products.ElementsAs(ctx, &gcpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = gcpProducts
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	keyFile, errMsg := resolveGcpKeyFile(ctx, config.KeyFile.ValueString(), r.client.Log)
	if errMsg != "" {
		r.client.Log.Debug(common.ERR_METHOD_END + errMsg + " [resource_gcp_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: GCP connection Creation",
			errMsg,
		)
		return
	}
	payload.KeyFile = keyFile

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_gcp_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: GCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_GCP_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_gcp_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating GCP Connection on CipherTrust Manager: ",
			"Could not create gcp connection, unexpected error: "+err.Error(),
		)
		return
	}

	r.client.Log.Debug("[resource_gcp_connection.go -> Create Output][" + response + "]")
	getGcpParamsFromResponse(response, &resp.Diagnostics, &plan)

	// key_file is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.KeyFile = types.StringNull()

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_gcp_connection.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceGCPConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state GCPConnectionTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_gcp_connection.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_GCP_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddWarning(
				"GCP Connection Not Found on CipherTrust Manager — State Preserved",
				fmt.Sprintf("The managed GCP connection %q was not found during refresh.\n\n"+
					"To prevent accidental data loss and key recreation, this connection has been kept in state.\n\n"+
					"Please verify if this is a transient cluster issue. If the connection was permanently deleted, "+
					"manually remove it from state: 'terraform state rm <resource-address>'",
					state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_gcp_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading GCP Connection on CipherTrust Manager: ",
			"Could not read gcp connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Debug("resource_gcp_connection.go: response :" + response)

	getGcpParamsFromResponse(response, &resp.Diagnostics, &state)
	// required parameters are fetched separately
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_gcp_connection.go -> Read][" + id + "]")
	return
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceGCPConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_gcp_connection.go -> Update][" + id + "]")
	var plan GCPConnectionTFSDK
	var state GCPConnectionTFSDK
	var payload GCPConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Load prior state to detect a key_file_version bump (see below).
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_file is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Update() ever runs, so plan.KeyFile is always
	// null here. req.Config is populated fresh from the HCL configuration on
	// every RPC (not derived from the nullified plan), so it reliably carries
	// the actual value.
	var config GCPConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		gcpLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			gcpLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = gcpLabelsPayload
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		gcpMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			gcpMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = gcpMetadataPayload
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var gcpProducts []string
		diags = plan.Products.ElementsAs(ctx, &gcpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = gcpProducts
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	// key_file is write-only (never stored in state), so its own value can never be
	// diffed against a prior value — key_file_version is the explicit, state-tracked
	// signal that the caller wants the current key_file value re-sent to CM.
	if !plan.KeyFileVersion.Equal(state.KeyFileVersion) {
		keyFile, errMsg := resolveGcpKeyFile(ctx, config.KeyFile.ValueString(), r.client.Log)
		if errMsg != "" {
			r.client.Log.Debug(common.ERR_METHOD_END + errMsg + " [resource_gcp_connection.go -> Update][" + id + "]")
			resp.Diagnostics.AddError(
				"Invalid data input: GCP connection update",
				errMsg,
			)
			return
		}
		payload.KeyFile = keyFile
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_gcp_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: GCP connection update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_GCP_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_gcp_connection.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating GCP Connection on CipherTrust Manager: ",
			"Could not update gcp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getGcpParamsFromResponse(response, &resp.Diagnostics, &plan)

	// key_file is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	plan.KeyFile = types.StringNull()

	r.client.Log.Debug(fmt.Sprintf("Response: %s", response))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceGCPConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state GCPConnectionTFSDK
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_gcp_connection.go -> Delete][" + state.ID.ValueString() + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_GCP_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			r.client.Log.Debug("GCP connection already deleted out-of-band on CM")
			return
		}
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_gcp_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust GCP Connection",
			"Could not delete gcp connection, unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_gcp_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
}

func (d *resourceGCPConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func getGcpKeyFile(ctx context.Context, file string, logger hclog.Logger) string {

	file = strings.TrimSpace(file)
	_, err := os.Stat(file)
	if err == nil {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			logger.Error("error reading google cloud key file file : " + err.Error())
			return ""
		}
		return string(data)
	}
	return file
}

// resolveGcpKeyFile wraps getGcpKeyFile and returns errMsg instead of a resolved
// value whenever resolution collapses to empty, so callers can reject the change.
func resolveGcpKeyFile(ctx context.Context, rawKeyFile string, logger hclog.Logger) (resolved string, errMsg string) {
	resolved = getGcpKeyFile(ctx, rawKeyFile, logger)
	if resolved == "" {
		return "", "key_file resolved to an empty value; provide a non-empty GCP service account key, either inline JSON or a path to a readable, non-empty key file"
	}
	return resolved, ""
}

func getGcpParamsFromResponse(response string, diag *diag.Diagnostics, data *GCPConnectionTFSDK) {
	// Common parameters for all connections
	data.ID = types.StringValue(gjson.Get(response, "id").String())
	data.URI = types.StringValue(gjson.Get(response, "uri").String())
	data.Account = types.StringValue(gjson.Get(response, "account").String())
	data.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	data.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	data.Category = types.StringValue(gjson.Get(response, "category").String())
	data.Service = types.StringValue(gjson.Get(response, "service").String())
	data.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	data.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	data.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	data.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	// Parameters specific to the GCP connection
	data.ClientEmail = types.StringValue(gjson.Get(response, "client_email").String())
	data.PrivateKeyID = types.StringValue(gjson.Get(response, "private_key_id").String())
	data.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	data.Description = types.StringValue(gjson.Get(response, "description").String())
	data.ClientEmail = types.StringValue(gjson.Get(response, "client_email").String())
	data.PrivateKeyID = types.StringValue(gjson.Get(response, "private_key_id").String())
	data.Labels = common.ParseMap(response, diag, "labels")
	data.Meta = common.ParseMap(response, diag, "meta")
	data.Products = common.ParseArray(response, "products")
}
