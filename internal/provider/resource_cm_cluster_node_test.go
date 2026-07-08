package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCipherTrust_ClusterNode_ImmutableFields verifies that host, port, member_host, and
// member_port are immutable on ciphertrust_cluster_node. Requires a real two-node CM cluster.
func TestCipherTrust_ClusterNode_ImmutableFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CM_CLUSTER_NODE_HOST") == "" {
		t.Skip("CM_CLUSTER_NODE_HOST not set — skipping cluster_node immutability test (requires real two-node cluster)")
	}
	if os.Getenv("CM_CLUSTER_NODE_PUBLIC_ADDRESS") == "" {
		t.Skip("CM_CLUSTER_NODE_PUBLIC_ADDRESS not set — skipping cluster_node immutability test")
	}
	if os.Getenv("CM_CLUSTER_MEMBER_HOST") == "" {
		t.Skip("CM_CLUSTER_MEMBER_HOST not set — skipping cluster_node immutability test")
	}

	nodeHost := os.Getenv("CM_CLUSTER_NODE_HOST")
	publicAddr := os.Getenv("CM_CLUSTER_NODE_PUBLIC_ADDRESS")
	memberHost := os.Getenv("CM_CLUSTER_MEMBER_HOST")

	baseConfig := func(host, port, pubAddr, mHost, mPort string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cluster_node" "test" {
  host           = %q
  port           = %s
  public_address = %q
  member_host    = %q
  member_port    = %s
}
`, host, port, pubAddr, mHost, mPort)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: real Apply — writes non-null prior state for all immutable fields
			{
				Config: baseConfig(nodeHost, "5432", publicAddr, memberHost, "5432"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.test", "host", nodeHost),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.test", "member_host", memberHost),
				),
			},
			// Step 2: change host — must fail at plan time
			{
				Config:      baseConfig("changed-host.example.com", "5432", publicAddr, memberHost, "5432"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
			// Step 3: change port — must fail at plan time
			{
				Config:      baseConfig(nodeHost, "5433", publicAddr, memberHost, "5432"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
			// Step 4: change member_host — must fail at plan time
			{
				Config:      baseConfig(nodeHost, "5432", publicAddr, "other-node.example.com", "5432"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
			// Step 5: change member_port — must fail at plan time
			{
				Config:      baseConfig(nodeHost, "5432", publicAddr, memberHost, "5433"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}
