package adp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceADPClientProfile{}
	_ resource.ResourceWithConfigure = &resourceADPClientProfile{}

	clientProfileCSRParamsDescription = `
Client certificate parameters to be updated.

	- csr_cn: common name
	- csr_country: country name
	- csr_state: state name
	- csr_city: city name
	- csr_org_name: organization name
	- csr_org_unit: organizational unit
	- csr_email: email
`
	clientProfileConfigurationsDescription = `
Parameters required to initialize connector.

	- symmetric_key_cache_enabled: Whether the symmetric key cache is enabled. Options.
		- true (Default)
		- false
	- symmetric_key_cache_expiry: Time after which the symmetric key cache will expire. Default: 43200
	- size_of_connection_pool: The maximum number of connections that can persist in connection pool. Default: 300
	- load_balancing_algorithm: Determines how the client selects a Key Manager from a load balancing group. Options.
		- round-robin (Default)
		- random
	- connection_idle_timeout: The time a connection is allowed to be idle in the connection pool before it gets automatically closed. Default: 600000
	- connection_retry_interval: The amount of time to wait before trying to reconnect to a disabled server. Default: 600000
	- log_level: The level of logging to determine verbosity of clients logs. Options.
		- ERROR
		- WARN (Default)
		- INFO
		- DEBUG
	- log_rotation: Specifies how frequently the log file is rotated. Options.
		- None
		- Daily (Default)
		- Weekly
		- Monthly
		- Size
	- log_size_limit: The maximum size of log file. Default: 100K
	- log_gmt: This value specifies if timestamp in logs should be formatted in GMT or not. Default disabled
	- log_type: Type of the log. Options.
		- Console (Default)
		- File
		- Multi
	- log_file_path: This value specifies the path where log file will be created
	- connection_timeout: Connection timeout value for clients. Default: 60000
	- connection_read_timeout: Read timeout value for clients. Default: 7000
	- heartbeat_interval: Frequency interval for sending heartbeat by connectors. Default: 300
	- heartbeat_timeout_count: heartbeat timeout missed communication counts with CM for connectors to decide on cleanup profile cache. Default: -1
	- tls_to_appserver
	- dial_timeout: Specifies the maximum duration (in seconds) the DPG server will wait for a connection with the Application Server to succeed.
	- dial_keep_alive: Specifies the interval (in seconds) between keep-alive probes for an active network connection.
	- auth_method_used the parameter is used to define how and from where to validate the application user
		- scheme_name: the type of authentication scheme to be used to fetch the suer Options.
			- Basic (Default)
			- Bearer
		- token_field: the json field which have the user information. Required when scheme_name is Bearer.
	- jwt_details: Information about the the JWT validation
		- issuer: String that identifies the principal that issued the JWT. If empty, the iss (issuer) field in the JWT won't be checked.
	- enable_performance_metrics: Flag used to enable clients to create a performance metrics. Options.
		- true (Default)
		- false
`
)

func NewResourceADPClientProfile() resource.Resource {
	return &resourceADPClientProfile{}
}

type resourceADPClientProfile struct {
	client *common.Client
}

func (r *resourceADPClientProfile) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_adp_client_profile"
}

// Schema defines the schema for the resource.
func (r *resourceADPClientProfile) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"app_connector_type": schema.StringAttribute{
				Required:    true,
				Description: "App connector type for which the client profile is created.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"DPG",
						"CADP For Java",
						"CRDP",
						"Plaintext"}...),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name for the client profile.",
			},
			"ca_id": schema.StringAttribute{
				Optional:    true,
				Description: "Local CA mapped with client profile.",
			},
			"cert_duration": schema.Int64Attribute{
				Optional:    true,
				Description: "Duration for which client credentials are valid.",
			},
			"configurations": schema.MapAttribute{
				Description: clientProfileConfigurationsDescription,
				ElementType: types.StringType,
				Optional:    true,
			},
			"csr_parameters": schema.MapAttribute{
				Description: clientProfileCSRParamsDescription,
				ElementType: types.StringType,
				Optional:    true,
			},
			"enable_client_autorenewal": schema.BoolAttribute{
				Description: "Flag used to check client autorenewal is enabled or not. Default value is false.",
				Optional:    true,
			},
			"groups": schema.ListAttribute{
				Description: "List of the groups in which client will be added during registration",
				Optional:    true,
				ElementType: types.StringType,
			},
			"heartbeat_threshold": schema.Int64Attribute{
				Optional:    true,
				Description: "The Threshold by which client's connectivity_status will be moved to Error if heartbeat is not received",
			},
			"jwt_verification_key": schema.StringAttribute{
				Optional:    true,
				Description: "PEM encoded PKCS#1 or PKCS#8 Public key used to validate a JWT. For example: -----BEGIN PUBLIC KEY-----\n<key content>\n-----END PUBLIC KEY-----",
			},
			"lifetime": schema.StringAttribute{
				Optional:    true,
				Description: "Validity of registration token.",
			},
			"max_clients": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of clients that can register using a registration token.",
			},
			"nae_iface_port": schema.Int64Attribute{
				Optional:    true,
				Description: "Nae interface mapped with client profile.",
			},
			"policy_id": schema.StringAttribute{
				Optional:    true,
				Description: "Policy mapped with client profile.",
			},
			"uri":        schema.StringAttribute{Computed: true},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
			"owner":      schema.StringAttribute{Computed: true},
			"reg_token":  schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceADPClientProfile) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_client_profile.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan ADPClientProfileTFSDK
	var payload ADPClientProfileJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.AppConnectorType = plan.AppConnectorType.ValueString()
	payload.Name = plan.Name.ValueString()

	if plan.CAId.ValueString() != "" && plan.CAId.ValueString() != types.StringNull().ValueString() {
		payload.CAId = plan.CAId.ValueString()
	}
	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	configurationsPayload := make(map[string]interface{})
	for k, v := range plan.Configurations.Elements() {
		configurationsPayload[k] = v.(types.String).ValueString()
	}
	payload.Configurations = configurationsPayload

	csrParamsPayload := make(map[string]interface{})
	for k, v := range plan.CSRParameters.Elements() {
		csrParamsPayload[k] = v.(types.String).ValueString()
	}
	payload.CSRParameters = csrParamsPayload

	if plan.EnableClientAutorenewal.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableClientAutorenewal = plan.EnableClientAutorenewal.ValueBool()
	}

	var groups []string
	for _, str := range plan.Groups {
		groups = append(groups, str.ValueString())
	}
	payload.Groups = groups

	if plan.HeartbeatThreshold.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.HeartbeatThreshold = plan.HeartbeatThreshold.ValueInt64()
	}
	if plan.JWTVerificationKey.ValueString() != "" && plan.JWTVerificationKey.ValueString() != types.StringNull().ValueString() {
		payload.JWTVerificationKey = plan.JWTVerificationKey.ValueString()
	}
	if plan.Lifetime.ValueString() != "" && plan.Lifetime.ValueString() != types.StringNull().ValueString() {
		payload.Lifetime = plan.Lifetime.ValueString()
	}
	if plan.MaxClients.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxClients = plan.MaxClients.ValueInt64()
	}
	if plan.NAEIfacePort.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.NAEIfacePort = plan.NAEIfacePort.ValueInt64()
	}
	if plan.PolicyId.ValueString() != "" && plan.PolicyId.ValueString() != types.StringNull().ValueString() {
		payload.PolicyId = plan.PolicyId.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_client_profile.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Client Profile Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, URL_CLIENT_PROFILE, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_client_profile.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Client Profile on CipherTrust Manager: ",
			"Could not create Client Profile, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Owner = types.StringValue(gjson.Get(response, "owner").String())
	plan.RegToken = types.StringValue(gjson.Get(response, "reg_token").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_client_profile.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceADPClientProfile) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ADPClientProfileTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), URL_CLIENT_PROFILE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_client_profile.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Client Profile on CipherTrust Manager: ",
			"Could not read Client Profile id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Owner = types.StringValue(gjson.Get(response, "owner").String())
	state.RegToken = types.StringValue(gjson.Get(response, "reg_token").String())
	state.AppConnectorType = types.StringValue(gjson.Get(response, "app_connector_type").String())
	state.PolicyId = types.StringValue(gjson.Get(response, "policy_id").String())
	state.HeartbeatThreshold = types.Int64Value(gjson.Get(response, "heartbeat_threshold").Int())
	state.CAId = types.StringValue(gjson.Get(response, "ca_id").String())
	state.CertDuration = types.Int64Value(gjson.Get(response, "cert_duration").Int())
	state.MaxClients = types.Int64Value(gjson.Get(response, "max_clients").Int())
	state.EnableClientAutorenewal = types.BoolValue(gjson.Get(response, "enable_client_autorenewal").Bool())

	configurationJSON := gjson.Get(response, "configurations")
	configurationMap := parseGJSONResult(configurationJSON)
	configurationsTypesMap, err := convertToTypesMap(configurationMap)
	if err != nil {
		log.Fatalf("Error converting to types.Map: %v", err)
	}
	state.Configurations = configurationsTypesMap

	csrParamsJSON := gjson.Get(response, "configurations")
	csrParamsMap := parseGJSONResult(csrParamsJSON)
	csrParamsTypesMap, err := convertToTypesMap(csrParamsMap)
	if err != nil {
		log.Fatalf("Error converting to types.Map: %v", err)
	}
	state.CSRParameters = csrParamsTypesMap

	groupsResult := gjson.Get(response, "groups")
	groupsResult.ForEach(func(key, value gjson.Result) bool {
		state.Groups = append(state.Groups, types.StringValue(value.String()))
		return true // Continue iterating
	})
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceADPClientProfile) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_client_profile.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan ADPClientProfileTFSDK
	var payload ADPClientProfileJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.AppConnectorType.ValueString() != "" && plan.AppConnectorType.ValueString() != types.StringNull().ValueString() {
		payload.AppConnectorType = plan.AppConnectorType.ValueString()
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.CAId.ValueString() != "" && plan.CAId.ValueString() != types.StringNull().ValueString() {
		payload.CAId = plan.CAId.ValueString()
	}
	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	configurationsPayload := make(map[string]interface{})
	for k, v := range plan.Configurations.Elements() {
		configurationsPayload[k] = v.(types.String).ValueString()
	}
	payload.Configurations = configurationsPayload

	csrParamsPayload := make(map[string]interface{})
	for k, v := range plan.CSRParameters.Elements() {
		csrParamsPayload[k] = v.(types.String).ValueString()
	}
	payload.CSRParameters = csrParamsPayload

	if plan.EnableClientAutorenewal.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableClientAutorenewal = plan.EnableClientAutorenewal.ValueBool()
	}

	var groups []string
	for _, str := range plan.Groups {
		groups = append(groups, str.ValueString())
	}
	payload.Groups = groups

	if plan.HeartbeatThreshold.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.HeartbeatThreshold = plan.HeartbeatThreshold.ValueInt64()
	}
	if plan.JWTVerificationKey.ValueString() != "" && plan.JWTVerificationKey.ValueString() != types.StringNull().ValueString() {
		payload.JWTVerificationKey = plan.JWTVerificationKey.ValueString()
	}
	if plan.Lifetime.ValueString() != "" && plan.Lifetime.ValueString() != types.StringNull().ValueString() {
		payload.Lifetime = plan.Lifetime.ValueString()
	}
	if plan.MaxClients.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxClients = plan.MaxClients.ValueInt64()
	}
	if plan.NAEIfacePort.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.NAEIfacePort = plan.NAEIfacePort.ValueInt64()
	}
	if plan.PolicyId.ValueString() != "" && plan.PolicyId.ValueString() != types.StringNull().ValueString() {
		payload.PolicyId = plan.PolicyId.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_client_profile.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Client Profile Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		plan.ID.ValueString(),
		URL_CLIENT_PROFILE,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_client_profile.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Client Profile on CipherTrust Manager: ",
			"Could not update Client Profile, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_client_profile.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceADPClientProfile) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ADPClientProfileTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, URL_CLIENT_PROFILE, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_client_profile.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Client Profile",
			"Could not delete Client Profile, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceADPClientProfile) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Helper function to parse a gjson.Result into a Go map
func parseGJSONResult(result gjson.Result) map[string]interface{} {
	goMap := make(map[string]interface{})
	result.ForEach(func(key, value gjson.Result) bool {
		switch {
		case value.IsObject():
			// Recursively parse nested objects
			goMap[key.String()] = parseGJSONResult(value)
		case value.IsArray():
			// Handle arrays if needed (not shown here)
			goMap[key.String()] = value.Value()
		default:
			// Handle primitive values
			goMap[key.String()] = value.Value()
		}
		return true // keep iterating
	})
	return goMap
}

// Helper function to convert a Go map to a types.Map
func convertToTypesMap(goMap map[string]interface{}) (basetypes.MapValue, error) {
	// Create a map of basetypes.StringValue values
	mapValues := make(map[string]basetypes.StringValue, len(goMap))
	for key, value := range goMap {
		// Convert the value to a string representation
		valueStr := fmt.Sprintf("%v", value)
		mapValues[key] = types.StringValue(valueStr)
	}

	// Create a context
	ctx := context.Background()

	// Create a types.Map from the map of basetypes.StringValue values
	configurationsMap, diags := types.MapValueFrom(ctx, types.StringType, mapValues)

	// Check if there are any errors in the diagnostics
	if diags.HasError() {
		return basetypes.NewMapNull(types.StringType), fmt.Errorf("error creating types.Map: %v", diags)
	}

	// Return the types.Map and no error
	return configurationsMap, nil
}
