package cckm

import (
	"context"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The offline plan test reproduces the plan Terraform asks for right after an apply, without any cloud
// access. It builds the state the way Read does (from a fake API response), builds the config the way the
// native acceptance test writes it, mimics the proposed new state Terraform core sends, and sends it through
// the real framework server (PlanResourceChange).
//
// The fake API values are assumptions, not captured values. Edit azureCertOfflineResponse so that it matches
// what CipherTrust Manager returned in the failing run.

const (
	azureCertOfflineKindDefaults = "defaults"
	azureCertOfflineKindRich     = "rich"
	azureCertOfflineKindBare     = "bare"

	azureCertOfflineName     = "tf-native-offline"
	azureCertOfflineSubject  = "CN=tf-native-offline"
	azureCertOfflineVaultID  = "11111111-2222-3333-4444-555555555555"
	azureCertOfflineTypeName = "ciphertrust_azure_certificate"
)

// azureCertOfflineProvider is the smallest provider that serves the certificate resource.
type azureCertOfflineProvider struct{}

func (p *azureCertOfflineProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ciphertrust"
}

func (p *azureCertOfflineProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = providerschema.Schema{}
}

func (p *azureCertOfflineProvider) Configure(_ context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	resp.ResourceData = &common.Client{Log: hclog.NewNullLogger()}
}

func (p *azureCertOfflineProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *azureCertOfflineProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewResourceCCKMAzureCertificate}
}

func azureCertOfflineStrings(values ...string) types.List {
	elements := make([]attr.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	return types.ListValueMust(types.StringType, elements)
}

func azureCertOfflineConfigModel(kind string) AzureCertificateTFSDK {
	return AzureCertificateTFSDK{
		Name:        types.StringValue(azureCertOfflineName),
		VaultID:     types.StringValue(azureCertOfflineVaultID),
		AzureParams: azureCertOfflineConfigParams(kind),
	}
}
