package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

func Test_CM_PrometheusSchema_TokenSensitive(t *testing.T) {
	var resp datasource.SchemaResponse
	(&dataSourcePrometheus{}).Schema(context.Background(), datasource.SchemaRequest{}, &resp)

	attr, ok := resp.Schema.Attributes["token"]
	if !ok {
		t.Fatal("token attribute not found in prometheus schema")
	}
	strAttr, ok := attr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("token attribute is not a StringAttribute, got %T", attr)
	}
	if !strAttr.Sensitive {
		t.Error("token attribute must have Sensitive: true")
	}
}
