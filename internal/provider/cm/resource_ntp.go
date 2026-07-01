package cm

import (
	"strings"
	"context"
	"encoding/json"
	"fmt"

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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &resourceCMNTP{}
	_ resource.ResourceWithConfigure      = &resourceCMNTP{}
	_ resource.ResourceWithValidateConfig = &resourceCMNTP{}
)

func NewResourceCMNTP() resource.Resource {
	return &resourceCMNTP{}
}

type resourceCMNTP struct {
	client *common.Client
}

func (r *resourceCMNTP) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ntp"
}

func (r *resourceCMNTP) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_ntp", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMNTP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Configures an NTP server on the CipherTrust Manager appliance. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier for the NTP server (same as host)",
			},
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Host (hostname/ip) of NTP server to add",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key": schema.StringAttribute{
				Optional:    true,
				Description: "Symmetric key value to be used for authenticated NTP servers",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_type": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"MD5",
						"SHA-1",
						"SHA-256",
						"SHA-384",
						"SHA-512"}...),
				},
				Description: "Digest algorithm to be used for authenticated NTP servers; MD5, SHA-1, SHA-256, SHA-384 or SHA-512 (defaults to SHA-256)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMNTP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_ntp.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMNTPTFSDK
	var payload CMNTPJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Host = plan.Host.ValueString()
	if plan.Key.ValueString() != "" && plan.Key.ValueString() != types.StringNull().ValueString() {
		payload.Key = plan.Key.ValueString()
	}
	if plan.KeyType.ValueString() != "" && plan.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = plan.KeyType.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_ntp.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Add NTP",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_NTP, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_ntp.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error adding NTP on CipherTrust Manager: ",
			"Could not add NTP, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Host = types.StringValue(gjson.Get(response, "host").String())
	// API does not return id, use host as the identifier
	plan.ID = types.StringValue(plan.Host.ValueString())
	// key and key_type are only returned by API if user provided them
	if keyVal := gjson.Get(response, "key"); keyVal.Exists() && keyVal.String() != "" {
		plan.Key = types.StringValue(keyVal.String())
	}
	if keyTypeVal := gjson.Get(response, "key_type"); keyTypeVal.Exists() && keyTypeVal.String() != "" {
		plan.KeyType = types.StringValue(keyTypeVal.String())
	}

	tflog.Debug(ctx, "[resource_ntp.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_ntp.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMNTP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMNTPTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Host.ValueString(), common.URL_NTP)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"NTP Server Not Found",
				"The NTP Server resource was not found on CipherTrust Manager (HTTP 404). It may have been deleted outside of Terraform. Removing it from state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_ntp.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM NTP on CipherTrust Manager: ",
			"Could not read CM NTP id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.Host = types.StringValue(gjson.Get(response, "host").String())
	// API does not return id, use host as the identifier
	state.ID = types.StringValue(state.Host.ValueString())
	// key and key_type are only returned by API if user provided them
	if keyVal := gjson.Get(response, "key"); keyVal.Exists() && keyVal.String() != "" {
		state.Key = types.StringValue(keyVal.String())
	} else {
		state.Key = types.StringNull()
	}
	if keyTypeVal := gjson.Get(response, "key_type"); keyTypeVal.Exists() && keyTypeVal.String() != "" {
		state.KeyType = types.StringValue(keyTypeVal.String())
	} else {
		state.KeyType = types.StringNull()
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_ntp.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
// Note: All attributes have RequiresReplace, so this method will never be called.
// Terraform will automatically delete and recreate the resource for any changes.
func (r *resourceCMNTP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMNTP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMNTPTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing license
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_NTP, state.Host.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_ntp.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust NTP",
			"Could not delete NTP, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMNTP) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
