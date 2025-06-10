package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceGetOCICompartments{}
	_ datasource.DataSourceWithConfigure = &dataSourceGetOCICompartments{}
)

func NewDataSourceGetOCICompartments() datasource.DataSource {
	return &dataSourceGetOCICompartments{}
}

func (d *dataSourceGetOCICompartments) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

type dataSourceGetOCICompartments struct {
	client *common.Client
}

func (d *dataSourceGetOCICompartments) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_get_oci_compartments"
}

func (d *dataSourceGetOCICompartments) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI compartments available to the connection.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection name or ID.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of records to return in a paginated 'List' call. It might not return the exact number as the first page might return one more than provided limit because of the inclusion of the root compartment (tenancy).",
				Validators:  []validator.Int64{int64validator.AtLeast(1)},
			},
			"compartments": schema.ListNestedAttribute{
				Description: "A list of compartments available to the connection.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's ID.",
						},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's OCID.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's description.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The defined tags of the compartment.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed: true,
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
									},
								},
							},
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The freeform tags of the compartment.",
						},
						"inactive_status": schema.Int64Attribute{
							Computed:    true,
							Description: "The detailed status of the INACTIVE lifecycleState.",
						},
						"is_accessible": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether or not the compartment is accessible for the user making the request.",
						},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's current lifecycle state.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's name.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The time the compartment was created.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceGetOCICompartments) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_compartments.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_compartments.go -> Read]")
	id := uuid.New().String()

	var state models.GetOCICompartmentsDataSourceModelTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	connection := state.Connection.ValueString()
	payload := models.GetOCICompartmentsPayloadJSON{
		Connection: connection,
	}
	limit := state.Limit.ValueInt64()
	if limit != 0 {
		payload.Limit = &limit
	}

	var data []models.GetOCICompartmentJSON
	compartments := d.fetchCompartments(ctx, id, payload, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data = append(data, compartments.Data...)
	nextPage := compartments.NextPage
	for i := 0; nextPage != "" && (limit != 0 && int64(len(data)) < limit); i++ {
		payload.NextPage = &nextPage
		compartments = d.fetchCompartments(ctx, id, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		data = append(data, compartments.Data...)
		nextPage = compartments.NextPage
	}

	for _, compartment := range data {
		compartmentTFSDK := models.GetOCICompartmentTFSDK{
			ID:             types.StringValue(compartment.ID),
			CompartmentID:  types.StringValue(compartment.CompartmentID),
			Name:           types.StringValue(compartment.Name),
			Description:    types.StringValue(compartment.Description),
			TimeCreated:    types.StringValue(compartment.TimeCreated),
			LifecycleState: types.StringValue(compartment.LifecycleState),
			InactiveStatus: types.Int64Value(compartment.InactiveStatus),
			IsAccessible:   types.BoolValue(compartment.IsAccessible),
		}
		setFreeformTagsState(ctx, compartment.FreeformTags, &compartmentTFSDK.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, compartment.DefinedTags, &compartmentTFSDK.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Compartments = append(state.Compartments, compartmentTFSDK)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_get_oci_compartments.go -> Read]["+id+"]")
}

func (d *dataSourceGetOCICompartments) fetchCompartments(ctx context.Context, id string,
	payload models.GetOCICompartmentsPayloadJSON, diags *diag.Diagnostics) *models.GetOCICompartmentsJSON {

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/get-compartments", payloadJSON)
	if err != nil {
		msg := "Error reading OCI compartments."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	var ociCompartments models.GetOCICompartmentsJSON
	err = json.Unmarshal([]byte(response), &ociCompartments)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	return &ociCompartments
}
