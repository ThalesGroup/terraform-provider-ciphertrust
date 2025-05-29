package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"os"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCCKMOCIConnection{}
	_ resource.ResourceWithConfigure = &resourceCCKMOCIConnection{}
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
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description about the connection. Once set, 'description' can be changed but not removed.",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager resource ID of the connection.",
			},
			"key_file": schema.StringAttribute{
				Required:    true,
				Description: "Path to or data of the OCI private key file (PEM format).",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"key_file_pass_phrase": schema.StringAttribute{
				Optional:    true,
				Description: "Passphrase if the OCI key file is encrypted.",
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection. Once set, 'meta' can be changed but not removed.\",",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique connection name",
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

func (r *resourceCCKMOCIConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_connection.go -> Create]["+id+"]")

	var plan OCIConnectionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// User can give path the pem file or pem data.
	keyFileData := readKeyFileData(ctx, plan.KeyFile.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	credentials := OCIConnectionCredentialsJSON{
		PassPhrase: plan.PassPhrase.ValueString(),
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
			tflog.Error(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = ociProducts
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection Creation",
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
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating OCI Connection on CipherTrust Manager: ",
			"Could not create oci connection, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// The connection has been created, no errors returned after this
	tflog.Trace(ctx, "[resource_oci_connection.go -> Create Output]["+response+"]")

	var testConnectionDiags diag.Diagnostics
	r.testConnection(ctx, id, plan.ID.ValueString(), &testConnectionDiags)
	if resp.Diagnostics.HasError() {
		for _, d := range testConnectionDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	response, err = r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Read]["+id+"]")
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

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_connection.go -> Create]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMOCIConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_connection.go -> Read]["+id+"]")

	var state OCIConnectionTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	r.getOciParamsFromResponse(ctx, response, &resp.Diagnostics, &state)
	if diags.HasError() {
		return
	}
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_connection.go -> Read]["+id+"]")
}

func (r *resourceCCKMOCIConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {

	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Read]["+id+"]")

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

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading OCI Connection on CipherTrust Manager: ",
			"Could not read oci connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	var payload OCIConnectionUpdateJSON
	planKeyFileData := readKeyFileData(ctx, plan.KeyFile.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	stateKeyFileData := readKeyFileData(ctx, state.KeyFile.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if planKeyFileData != stateKeyFileData {
		credentials := OCIConnectionCredentialsJSON{
			PassPhrase: plan.PassPhrase.ValueString(),
			KeyFile:    planKeyFileData,
		}
		payload.Credentials = credentials
	}

	if plan.Description.ValueString() != gjson.Get(response, "description").String() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.Fingerprint.ValueString() != gjson.Get(response, "fingerprint").String() {
		payload.Fingerprint = plan.Fingerprint.ValueString()
	}

	planMetadata := make(map[string]string)
	for k, v := range plan.Meta.Elements() {
		planMetadata[k] = v.(types.String).ValueString()
	}
	connectionMeta := make(map[string]string)
	if gjson.Get(response, "meta").Exists() {
		metaMap, ok := gjson.Parse(gjson.Get(response, "meta").String()).Value().(map[string]interface{})
		if ok {
			for key, value := range metaMap {
				switch value.(type) {
				case string:
					connectionMeta[key] = value.(string)
				case int64:
					connectionMeta[key] = fmt.Sprintf("%s", value.(int))
				case bool:
					connectionMeta[key] = fmt.Sprintf("%t", value.(bool))
				default:
					// For unknown types, convert them to a string representation
					connectionMeta[key] = fmt.Sprintf("%v", value)
				}
			}
		}
	}
	if !reflect.DeepEqual(planMetadata, connectionMeta) {
		payload.Meta = planMetadata
	}

	var planProducts []string
	resp.Diagnostics.Append(plan.Products.ElementsAs(ctx, &planProducts, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
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
		payload.TenancyOCID = plan.TenancyOcid.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: OCI connection update",
			err.Error(),
		)
		return
	}

	connectionID := gjson.Get(response, "id").String()
	response, err = r.client.UpdateDataV2(ctx, connectionID, common.URL_OCI_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating OCI Connection on CipherTrust Manager: ",
			"Could not update oci connection, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("Response: %s", response))
	response, err = r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_OCI_CONNECTION)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> Read]["+id+"]")
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

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMOCIConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state OCIConnectionTFSDK
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_connection.go -> Delete]["+state.ID.ValueString()+"]")
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_OCI_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust OCI Connection",
			"Could not delete oci connection, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
}

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
	data.Meta = common.ParseMap(response, diags, "meta")
	data.Products = common.ParseArray(response, "products")
}

func readKeyFileData(ctx context.Context, inputParam string, diags *diag.Diagnostics) string {
	inputParam = strings.TrimSpace(inputParam)
	_, err := os.Stat(inputParam)
	if err == nil {
		var data []byte
		data, err = os.ReadFile(inputParam)
		if err != nil {
			tflog.Error(ctx, fmt.Sprintf("Failed to read key file %s,error: %s", inputParam, err.Error()))
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

func (r *resourceCCKMOCIConnection) testConnectionParameters(ctx context.Context, id string, payloadJSON []byte, diags *diag.Diagnostics) {
	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI_CONNECTION_TEST, payloadJSON)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> test connection params]["+id+"]")
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

func (r *resourceCCKMOCIConnection) testConnection(ctx context.Context, id string, connectionID string, diags *diag.Diagnostics) {
	response, err := r.client.PostNoData(ctx, id, common.URL_OCI_CONNECTION+"/"+connectionID+"/test")
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_oci_connection.go -> test existing connection]["+id+"]")
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
