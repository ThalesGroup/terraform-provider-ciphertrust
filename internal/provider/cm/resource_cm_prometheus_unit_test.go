package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func Test_CM_PrometheusResourceSchema_TokenSensitive(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMPrometheus{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	attr, ok := resp.Schema.Attributes["token"]
	if !ok {
		t.Fatal("token attribute not found in prometheus resource schema")
	}
	strAttr, ok := attr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("token attribute is not a StringAttribute, got %T", attr)
	}
	if !strAttr.Sensitive {
		t.Error("token attribute must have Sensitive: true in resource schema")
	}
}
