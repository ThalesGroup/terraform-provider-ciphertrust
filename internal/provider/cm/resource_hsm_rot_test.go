package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// Test_CM_HsmRot_SchemaAttributesSensitive verifies that conn_info and
// initial_config carry Sensitive: true, so secrets never surface in plan output.
func Test_CM_HsmRot_SchemaAttributesSensitive(t *testing.T) {
	r := &resourceHSMRootOfTrust{}
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)

	connInfo, ok := schemaResp.Schema.Attributes["conn_info"]
	if !ok {
		t.Fatal("conn_info attribute not found in schema")
	}
	if m, ok := connInfo.(schema.MapAttribute); !ok || !m.Sensitive {
		t.Error("conn_info must have Sensitive: true")
	}

	initialConfig, ok := schemaResp.Schema.Attributes["initial_config"]
	if !ok {
		t.Fatal("initial_config attribute not found in schema")
	}
	if m, ok := initialConfig.(schema.MapAttribute); !ok || !m.Sensitive {
		t.Error("initial_config must have Sensitive: true")
	}
}
