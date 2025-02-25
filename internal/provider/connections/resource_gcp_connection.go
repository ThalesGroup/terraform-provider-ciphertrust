package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_file": schema.StringAttribute{
				Required:    true,
				Description: "The private key JSON file of a Google Cloud Platform (GCP) service account can be provided either as a JSON file or as a string.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique connection name.",
			},
			"cloud_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the cloud. Default value is gcp.\n\nOptions:\n\ngcp",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: labelsDescription,
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Optional end-user or service data stored with the connection.",
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: productsDescription,
			},
			"client_email": schema.StringAttribute{
				Computed: true,
			},
			"private_key_id": schema.StringAttribute{
				Computed: true,
			},
			//common response parameters (optional)
			"uri":                   schema.StringAttribute{Computed: true, Optional: true},
			"account":               schema.StringAttribute{Computed: true, Optional: true},
			"created_at":            schema.StringAttribute{Computed: true, Optional: true},
			"updated_at":            schema.StringAttribute{Computed: true, Optional: true},
			"service":               schema.StringAttribute{Computed: true, Optional: true},
			"category":              schema.StringAttribute{Computed: true, Optional: true},
			"resource_url":          schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_ok":    schema.BoolAttribute{Computed: true, Optional: true},
			"last_connection_error": schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_at":    schema.StringAttribute{Computed: true, Optional: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceGCPConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_gcp_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan GCPConnectionTFSDK
	var payload GCPConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
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

	gcpLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		gcpLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = gcpLabelsPayload

	gcpMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		gcpMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = gcpMetadataPayload

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var gcpProducts []string
		diags = plan.Products.ElementsAs(ctx, &gcpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = gcpProducts
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.KeyFile.ValueString() != "" && plan.KeyFile.ValueString() != types.StringNull().ValueString() {
		payload.KeyFile = getGcpKeyFile(ctx, plan.KeyFile.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_gcp_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: GCP connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_GCP_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_gcp_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating GCP Connection on CipherTrust Manager: ",
			"Could not create gcp connection, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_gcp_connection.go -> Create Output]["+response+"]")
	getGcpParamsFromResponse(response, &resp.Diagnostics, &plan)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_gcp_connection.go -> Create]["+id+"]")
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_gcp_connection.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_GCP_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_gcp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading GCP Connection on CipherTrust Manager: ",
			"Could not read gcp connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Debug(ctx, "resource_gcp_connection.go: response :"+response)

	getGcpParamsFromResponse(response, &resp.Diagnostics, &state)
	// required parameters are fetched separately
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.KeyFile = types.StringValue(gjson.Get(response, "keyFile").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_gcp_connection.go -> Read]["+id+"]")
	return
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceGCPConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_gcp_connection.go -> Update]["+id+"]")
	var plan GCPConnectionTFSDK
	var payload GCPConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	gcpLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		gcpLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = gcpLabelsPayload

	gcpMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		gcpMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = gcpMetadataPayload

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var gcpProducts []string
		diags = plan.Products.ElementsAs(ctx, &gcpProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = gcpProducts
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.KeyFile.ValueString() != "" && plan.KeyFile.ValueString() != types.StringNull().ValueString() {
		payload.KeyFile = getGcpKeyFile(ctx, plan.KeyFile.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_gcp_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: GCP connection update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_GCP_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_gcp_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating GCP Connection on CipherTrust Manager: ",
			"Could not update gcp connection, unexpected error: "+err.Error(),
		)
		return
	}
	getGcpParamsFromResponse(response, &resp.Diagnostics, &plan)
	tflog.Debug(ctx, fmt.Sprintf("Response: %s", response))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceGCPConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state GCPConnectionTFSDK
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_gcp_connection.go -> Delete]["+state.ID.ValueString()+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_GCP_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_gcp_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust GCP Connection",
			"Could not delete gcp connection, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_gcp_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
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

func getGcpKeyFile(ctx context.Context, file string) string {

	file = strings.TrimSpace(file)
	_, err := os.Stat(file)
	if err == nil {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			tflog.Error(ctx, "error reading google cloud key file file : "+err.Error())
			return ""
		}
		return string(data)
	}
	return file
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
