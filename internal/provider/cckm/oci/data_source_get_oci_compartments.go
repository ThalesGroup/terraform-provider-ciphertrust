package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
							Description: "The parent compartment's OCID.",
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
										Computed:    true,
										Description: "The tag's namespace.",
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
										Description: "The key:value pairs associated with the tag.",
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

// Read retrieves all OCI compartments available to the connection,
// automatically paginating until all results are collected.
func (d *dataSourceGetOCICompartments) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_get_oci_compartments.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_get_oci_compartments.go -> Read][" + id + "]")

	var state models.GetOCICompartmentsDataSourceModelTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := models.GetOCICompartmentsPayloadJSON{
		Connection: state.Connection.ValueString(),
	}

	var data []models.GetOCICompartmentJSON
	for {
		page := d.fetchCompartments(ctx, id, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if page == nil {
			break
		}
		data = append(data, page.Data...)
		if page.NextPage == "" {
			break
		}
		np := page.NextPage
		payload.NextPage = &np
	}

	state.Compartments = []models.GetOCICompartmentTFSDK{}
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
}

// fetchCompartments marshals payload into JSON, calls the CM OCI get-compartments
// endpoint, and unmarshals the response. Returns nil and appends an error on any failure.
func (d *dataSourceGetOCICompartments) fetchCompartments(ctx context.Context, id string,
	payload models.GetOCICompartmentsPayloadJSON, diags *diag.Diagnostics) *models.GetOCICompartmentsJSON {

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/get-compartments", payloadJSON)
	if err != nil {
		msg := "Error reading OCI compartments."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	var ociCompartments models.GetOCICompartmentsJSON
	err = json.Unmarshal([]byte(response), &ociCompartments)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	return &ociCompartments
}
