package cckm

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// azureCertOfflineRunKind plans one scenario and reports every attribute that is unknown or changed.
func azureCertOfflineRunKind(ctx context.Context, t *testing.T, server tfprotov6.ProviderServer, s schema.Schema, kind string) {
	t.Helper()
	schemaType := s.Type().TerraformType(ctx)

	configModel := azureCertOfflineConfigModel(kind)
	stateModel := azureCertOfflineConfigModel(kind)
	if err := azureCertificateSetState(azureCertOfflineResponse(t, kind), &stateModel); err != nil {
		t.Fatalf("[%s] building state failed: %v", kind, err)
	}
	configRaw := azureCertOfflineRaw(ctx, t, s, configModel)
	stateRaw := azureCertOfflineRaw(ctx, t, s, stateModel)

	proposedRaw, err := azureCertOfflinePropose(s.Attributes, configRaw, stateRaw)
	if err != nil {
		t.Fatalf("[%s] building the proposed state failed: %v", kind, err)
	}
	proposedDiffs := azureCertOfflineDiffs(proposedRaw, stateRaw)
	t.Logf("[%s] proposed new state differs from prior state at %d path(s)", kind, len(proposedDiffs))
	for _, line := range proposedDiffs {
		t.Logf("[%s]   proposed diff %s", kind, line)
	}

	resp, err := server.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
		TypeName:         azureCertOfflineTypeName,
		PriorState:       azureCertOfflineEncode(t, kind, schemaType, stateRaw),
		ProposedNewState: azureCertOfflineEncode(t, kind, schemaType, proposedRaw),
		Config:           azureCertOfflineEncode(t, kind, schemaType, configRaw),
	})
	if err != nil {
		t.Fatalf("[%s] PlanResourceChange failed: %v", kind, err)
	}
	azureCertOfflineCheckDiags(t, "["+kind+"] plan", resp.Diagnostics)
	if resp.PlannedState == nil {
		t.Fatalf("[%s] PlanResourceChange returned no planned state", kind)
	}
	plannedRaw, err := resp.PlannedState.Unmarshal(schemaType)
	if err != nil {
		t.Fatalf("[%s] decoding planned state failed: %v", kind, err)
	}
	plannedDiffs := azureCertOfflineDiffs(plannedRaw, stateRaw)
	t.Logf("[%s] planned state differs from prior state at %d path(s)", kind, len(plannedDiffs))
	for _, line := range plannedDiffs {
		t.Logf("[%s]   planned diff %s", kind, line)
	}
	if len(plannedDiffs) > 0 {
		t.Errorf("[%s] the plan after apply is not empty: %s", kind, strings.Join(plannedDiffs, "; "))
	}
}

// TestAzureCertificatePlanOffline needs no Azure or CipherTrust Manager access. Run it with:
// go test ./internal/provider/cckm/azure -run TestAzureCertificatePlanOffline -v
func TestAzureCertificatePlanOffline(t *testing.T) {
	ctx := context.Background()

	res := &resourceCCKMAzureCertificate{}
	schemaResp := &resource.SchemaResponse{}
	res.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	server := providerserver.NewProtocol6(&azureCertOfflineProvider{})()
	providerType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	providerConfig := azureCertOfflineEncode(t, "provider", providerType, tftypes.NewValue(providerType, map[string]tftypes.Value{}))
	configureResp, err := server.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: providerConfig})
	if err != nil {
		t.Fatalf("ConfigureProvider failed: %v", err)
	}
	azureCertOfflineCheckDiags(t, "configure", configureResp.Diagnostics)

	azureCertOfflineRunKind(ctx, t, server, schemaResp.Schema, azureCertOfflineKindDefaults)
	azureCertOfflineRunKind(ctx, t, server, schemaResp.Schema, azureCertOfflineKindRich)
	azureCertOfflineRunKind(ctx, t, server, schemaResp.Schema, azureCertOfflineKindBare)
}
