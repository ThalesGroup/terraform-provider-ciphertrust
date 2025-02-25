package cm

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceCMPrometheus{}
	_ resource.ResourceWithConfigure = &resourceCMPrometheus{}
)

func NewResourceCMPrometheus() resource.Resource {
	return &resourceCMPrometheus{}
}

type resourceCMPrometheus struct {
	client *common.Client
}

func (r *resourceCMPrometheus) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_prometheus"
}

// Schema defines the schema for the resource.
func (r *resourceCMPrometheus) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"token": schema.StringAttribute{
				Computed: true,
			},
			"enabled": schema.BoolAttribute{
				Required: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMPrometheus) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_prometheus.go -> Enable/Disable] - Create")

	// Retrieve values from plan
	var plan CMPrometheusMetricsConfigTFSDK
	var payload CMPrometheusMetricsConfigJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := common.URL_PROMETHEUS_DISABLE
	status := "disable"
	if plan.Enabled.ValueBool() {
		payload.Enabled = plan.Enabled.ValueBool()
		url = common.URL_PROMETHEUS_ENABLE
		status = "enable"
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Create]["+status+"]")
		resp.Diagnostics.AddError(
			fmt.Sprintf("Invalid data input for Prometheus : %s", status),
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, url, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Create]["+status+"]")
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error occured during prometheus %s", status),
			"unexpected error: "+err.Error(),
		)
		return
	}
	plan.Token = types.StringValue(gjson.Get(response, "token").String())

	tflog.Debug(ctx, "[resource_cm_prometheus.go -> Enable/Disable Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_prometheus.go -> Enable/Disable - Create]["+status+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMPrometheus) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_prometheus.go -> Read]["+id+"]")

	response, err := r.client.ReadDataByParam(ctx, id, "all", common.URL_PROMETHEUS_STATUS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_prometheus.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Read Error", "Error fetching Prometheus status: "+err.Error())
		return
	}

	state := &CMPrometheusMetricsConfigTFSDK{
		Enabled: types.BoolValue(gjson.Get(response, "enabled").Bool()),
		Token:   types.StringValue(gjson.Get(response, "token").String()),
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_prometheus.go -> Read]["+id+"]")

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMPrometheus) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// The Update operation is not natively supported by the CipherTrust API.
	// However, it is implemented here to enhance user convenience, allowing seamless enablement
	// and disablement of Prometheus functionality without requiring the deletion of the Terraform state file.
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_prometheus.go -> Enable/Disable - Update]")

	var plan CMPrometheusMetricsConfigTFSDK
	var payload CMPrometheusMetricsConfigJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := common.URL_PROMETHEUS_DISABLE
	if plan.Enabled.ValueBool() {
		payload.Enabled = plan.Enabled.ValueBool()
		url = common.URL_PROMETHEUS_ENABLE
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Update")
		resp.Diagnostics.AddError(
			"Invalid data input for disabling Prometheus",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, "", url, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Update")
		resp.Diagnostics.AddError(
			"Invalid data input for updating Prometheus state",
			"unexpected error: "+err.Error(),
		)
		return
	}
	plan.Token = types.StringValue(gjson.Get(response, "token").String())
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_prometheus.go -> Enable/Disable - Update")

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMPrometheus) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_prometheus.go -> Enable/Disable - Delete]")

	var payload CMPrometheusMetricsConfigJSON
	payload.Enabled = false
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Delete")
		resp.Diagnostics.AddError(
			"Invalid data input for disabling Prometheus",
			err.Error(),
		)
		return
	}

	_, err = r.client.PostDataV2(ctx, "", common.URL_PROMETHEUS_DISABLE, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_prometheus.go -> Enable/Disable - Delete")
		resp.Diagnostics.AddError(
			"Invalid data input for disabling Prometheus",
			"unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_prometheus.go -> Enable/Disable - Delete")
}

func (d *resourceCMPrometheus) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
