package validators_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
)

func TestProxyURL(t *testing.T) {
	v := validators.ProxyURL()

	accepted := []string{
		"http://user:pass@10.171.30.20:3300",     // full URL with credentials
		"https://proxy.example.com:8080",         // full URL no credentials
		"proxy-user:ssl12345@10.171.30.20:3300",  // schemeless with credentials (CM Scenario 3)
		"cckmdev-proxy-13110.sjinternal.com:443", // schemeless host:port
		"10.171.30.20:3300",                      // bare host:port
		"proxy.example.com",                      // bare hostname
	}
	for _, val := range accepted {
		req := validator.StringRequest{ConfigValue: types.StringValue(val)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("ProxyURL() rejected valid value %q: %s", val, resp.Diagnostics[0].Detail())
		}
	}

	rejected := []string{
		"",
		"   ",
		"http://host with spaces",
		"http://host\twith\ttabs",
	}
	for _, val := range rejected {
		req := validator.StringRequest{ConfigValue: types.StringValue(val)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("ProxyURL() accepted invalid value %q but should have rejected it", val)
		}
	}
}
