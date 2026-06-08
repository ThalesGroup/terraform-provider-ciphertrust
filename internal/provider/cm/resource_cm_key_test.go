package cm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestUnitCMKey_readNonFatal confirms that a non-404 API error from Read() surfaces as
// a Terraform diagnostic error and does NOT remove the resource from state (i.e. the
// resource is preserved so the user can investigate rather than silently losing state).
func TestUnitCMKey_readNonFatal(t *testing.T) {
	// Arrange: HTTP server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Token:          "test-token",
	}

	rk := &resourceCMKey{client: client}
	ctx := context.Background()

	// Build the schema so we can construct a proper tfsdk.State.
	var schemaResp resource.SchemaResponse
	rk.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	// Build a minimal state containing only the required id field.
	// All other fields are set to their null/zero framework values so that
	// tfsdk.State.Set does not complain about missing required fields.
	initState := CMKeyTFSDK{
		ID:                       types.StringValue("test-key-id"),
		ActivationDate:           types.StringNull(),
		Algorithm:                types.StringNull(),
		ArchiveDate:              types.StringNull(),
		AssignSelfAsOwner:        types.BoolNull(),
		CertType:                 types.StringNull(),
		CompromiseDate:           types.StringNull(),
		CompromiseOccurrenceDate: types.StringNull(),
		Curveid:                  types.StringNull(),
		DeactivationDate:         types.StringNull(),
		DefaultIV:                types.StringNull(),
		Description:              types.StringNull(),
		DestroyDate:              types.StringNull(),
		EmptyMaterial:            types.BoolNull(),
		Encoding:                 types.StringNull(),
		Format:                   types.StringNull(),
		GenerateKeyId:            types.BoolNull(),
		IDSize:                   types.Int64Null(),
		KeyId:                    types.StringNull(),
		MacSignBytes:             types.StringNull(),
		MacSignKeyIdentifier:     types.StringNull(),
		MacSignKeyIdentifierType: types.StringNull(),
		Material:                 types.StringNull(),
		MUID:                     types.StringNull(),
		ObjectType:               types.StringNull(),
		Name:                     types.StringNull(),
		Padded:                   types.BoolNull(),
		Password:                 types.StringNull(),
		ProcessStartDate:         types.StringNull(),
		ProtectStopDate:          types.StringNull(),
		RevocationReason:         types.StringNull(),
		RevocationMessage:        types.StringNull(),
		RotationFrequencyDays:    types.StringNull(),
		SecretDataEncoding:       types.StringNull(),
		SecretDataLink:           types.StringNull(),
		SigningAlgo:              types.StringNull(),
		Size:                     types.Int64Null(),
		UnExportable:             types.BoolNull(),
		UnDeletable:              types.BoolNull(),
		State:                    types.StringNull(),
		TemplateID:               types.StringNull(),
		UsageMask:                types.Int64Null(),
		UUID:                     types.StringNull(),
		WrapKeyIDType:            types.StringNull(),
		WrapKeyName:              types.StringNull(),
		WrapPublicKey:            types.StringNull(),
		WrapPublicKeyPadding:     types.StringNull(),
		WrappingEncryptionAlgo:   types.StringNull(),
		WrappingHashAlgo:         types.StringNull(),
		WrappingMethod:           types.StringNull(),
		XTS:                      types.BoolNull(),
		Labels:                   types.MapNull(types.StringType),
		AllVersions:              types.BoolNull(),
		RemoveFromStateOnDestroy: types.BoolNull(),
		// Pointer fields remain nil (null nested attributes).
	}

	tfState := tfsdk.State{Schema: schemaResp.Schema}
	diags := tfState.Set(ctx, initState)
	if diags.HasError() {
		t.Fatalf("failed to construct initial state: %v", diags)
	}

	// Act: call Read with a client that will return 500.
	readResp := &resource.ReadResponse{State: tfState}
	rk.Read(ctx, resource.ReadRequest{State: tfState}, readResp)

	// Assert: diagnostics must contain an error.
	if !readResp.Diagnostics.HasError() {
		t.Error("expected Read() to surface a diagnostic error for HTTP 500 response, but no error was reported")
	}
	// Assert: state must NOT be removed (RemoveResource sets Raw to null).
	if readResp.State.Raw.IsNull() {
		t.Error("expected Read() to preserve state on non-404 error, but resp.State.RemoveResource was called")
	}
}
