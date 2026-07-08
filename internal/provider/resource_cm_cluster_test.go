package provider

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type clusterNode struct {
	host, addr, public, password string
}

// checkStep wraps check functions with step-level logging so it is always
// clear which logical stage is being verified and whether it passed or failed.
func checkStep(t *testing.T, label string, checks ...resource.TestCheckFunc) resource.TestCheckFunc {
	t.Helper()
	return func(s *terraform.State) error {
		fmt.Printf("\n======== CHECK: %s ========\n", label)
		err := resource.ComposeAggregateTestCheckFunc(checks...)(s)
		if err != nil {
			fmt.Printf("======== FAILED: %s ========\n%v\n", label, err)
		} else {
			fmt.Printf("======== PASSED: %s ========\n", label)
		}
		return err
	}
}

// bareHost strips scheme and trailing slash: "https://1.2.3.4/" → "1.2.3.4".
func bareHost(address string) string {
	s := strings.TrimPrefix(address, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

// node1Coords returns the primary node's host and public-address values.
// Skips t if CIPHERTRUST_ADDRESS is not set.
func node1Coords(t *testing.T) (host, public string) {
	t.Helper()
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	if address == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping cluster test")
	}
	host = os.Getenv("CLUSTER_NODE1_HOST")
	if host == "" {
		host = bareHost(address)
	}
	public = os.Getenv("CLUSTER_NODE1_PUBLIC")
	if public == "" {
		public = host
	}
	return
}

// node2Coords returns the second node's coordinates.
// Skips t if any CLUSTER_NODE2_* variable is unset.
func node2Coords(t *testing.T) clusterNode {
	t.Helper()
	n := clusterNode{
		host:     os.Getenv("CLUSTER_NODE2_HOST"),
		addr:     os.Getenv("CLUSTER_NODE2_ADDRESS"),
		public:   os.Getenv("CLUSTER_NODE2_PUBLIC"),
		password: os.Getenv("CLUSTER_NODE2_PASSWORD"),
	}
	for _, e := range []struct{ name, val string }{
		{"CLUSTER_NODE2_HOST", n.host},
		{"CLUSTER_NODE2_ADDRESS", n.addr},
		{"CLUSTER_NODE2_PUBLIC", n.public},
		{"CLUSTER_NODE2_PASSWORD", n.password},
	} {
		if e.val == "" {
			t.Skipf("%s not set; skipping test", e.name)
		}
	}
	return n
}

// node3Coords returns the third node's coordinates.
// Skips t if any CLUSTER_NODE3_* variable is unset.
func node3Coords(t *testing.T) clusterNode {
	t.Helper()
	n := clusterNode{
		host:     os.Getenv("CLUSTER_NODE3_HOST"),
		addr:     os.Getenv("CLUSTER_NODE3_ADDRESS"),
		public:   os.Getenv("CLUSTER_NODE3_PUBLIC"),
		password: os.Getenv("CLUSTER_NODE3_PASSWORD"),
	}
	for _, e := range []struct{ name, val string }{
		{"CLUSTER_NODE3_HOST", n.host},
		{"CLUSTER_NODE3_ADDRESS", n.addr},
		{"CLUSTER_NODE3_PUBLIC", n.public},
		{"CLUSTER_NODE3_PASSWORD", n.password},
	} {
		if e.val == "" {
			t.Skipf("%s not set; skipping test", e.name)
		}
	}
	return n
}

func clusterUsername() string {
	if u := os.Getenv("CIPHERTRUST_USERNAME"); u != "" {
		return u
	}
	return "admin"
}

// cfgPrimary — single-node cluster, no public_address.
func cfgPrimary(n1Host string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cluster" "primary" {
  local_node_host = %q
  local_node_port = 5432
}
`, n1Host)
}

// cfgPrimaryPublic — single-node cluster with public_address set.
func cfgPrimaryPublic(n1Host, n1Public string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cluster" "primary" {
  local_node_host = %q
  local_node_port = 5432
  public_address  = %q
}
`, n1Host, n1Public)
}

// cfgNodeBlock — HCL resource block for one cluster_node.
// memberHost is the primary node's internal IP (used in CM API payloads).
func cfgNodeBlock(resourceName, nodeHost, nodePublic, memberHost, nodeAddr, username, password string) string {
	return fmt.Sprintf(`
resource "ciphertrust_cluster_node" %q {
  depends_on = [ciphertrust_cluster.primary]

  host           = %q
  port           = 5432
  public_address = %q
  member_host    = %q
  member_port    = 5432

  credentials = {
    address  = %q
    username = %q
    password = %q
  }
}
`, resourceName, nodeHost, nodePublic, memberHost, nodeAddr, username, password)
}

// cfg2Node — primary + node2.
func cfg2Node(n1Host, n1Public string, n2 clusterNode, username string) string {
	return cfgPrimaryPublic(n1Host, n1Public) +
		cfgNodeBlock("node2", n2.host, n2.public, n1Host, n2.addr, username, n2.password)
}

// cfg3Node — primary + node2 + node3.
// node2 and node3 both depend_on the primary cluster but not on each other;
// the provider-level mutex (clusterJoinMu) serialises concurrent joins.
func cfg3Node(n1Host, n1Public string, n2, n3 clusterNode, username string) string {
	return cfgPrimaryPublic(n1Host, n1Public) +
		cfgNodeBlock("node2", n2.host, n2.public, n1Host, n2.addr, username, n2.password) +
		cfgNodeBlock("node3", n3.host, n3.public, n1Host, n3.addr, username, n3.password)
}

// Test_CM_ResourceCMCluster runs the full cluster lifecycle as one sequential test:
// create a 1-node cluster, add/remove/swap nodes up to 3, update a node's
// public_address, then destroy the full cluster.
func Test_CM_ResourceCMCluster(t *testing.T) {
	t.Skip("skipping cluster test")
	n1Host, n1Public := node1Coords(t)
	n2 := node2Coords(t)
	n3 := node3Coords(t)
	username := clusterUsername()

	// n3DNS — node3 with its DNS name used as public_address instead of its IP.
	n3DNS := clusterNode{
		host:     n3.host,
		addr:     n3.addr,
		public:   n3.addr,
		password: n3.password,
	}

	// node2ID is captured in step 4 and compared in step 5 to confirm the
	// swap produced a genuinely new node rather than reusing the old one.
	var node2ID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create 1-node cluster
			{
				Config: cfgPrimary(n1Host),
				Check: checkStep(t, "Step 1: 1-node cluster created",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "node_id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster.primary", "local_node_host", n1Host),
					resource.TestCheckResourceAttr("ciphertrust_cluster.primary", "local_node_port", "5432"),
					resource.TestCheckResourceAttr("ciphertrust_cluster.primary", "status_code", "r"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "status_description"),
				),
			},

			// Step 2: Add node2 (1 → 2)
			{
				Config: cfg2Node(n1Host, n1Public, n2, username),
				Check: checkStep(t, "Step 2: node2 joined (2-node)",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node2", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node2", "node_id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node2", "host", n2.host),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node2", "status_code", "r"),
				),
			},

			// Step 3: Add node3 (2 → 3)
			{
				Config: cfg3Node(n1Host, n1Public, n2, n3, username),
				Check: checkStep(t, "Step 3: node3 joined (3-node)",
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node2", "status_code", "r"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node3", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node3", "status_code", "r"),
				),
			},

			// Step 4: Remove node3 (3 → 2)
			{
				Config: cfg2Node(n1Host, n1Public, n2, username),
				Check: checkStep(t, "Step 4: node3 removed (2-node)",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node2", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node2", "status_code", "r"),
					resource.TestCheckResourceAttrWith("ciphertrust_cluster_node.node2", "id", func(v string) error {
						node2ID = v
						return nil
					}),
				),
			},

			// Step 5: Swap node2 → node3 (simultaneous add + remove, 2 → 2)
			{
				Config: cfgPrimaryPublic(n1Host, n1Public) +
					cfgNodeBlock("node3", n3.host, n3.public, n1Host, n3.addr, username, n3.password),
				Check: checkStep(t, "Step 5: swap produced new node (2-node)",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node3", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node3", "status_code", "r"),
					resource.TestCheckResourceAttrWith("ciphertrust_cluster_node.node3", "id", func(v string) error {
						if node2ID != "" && v == node2ID {
							return fmt.Errorf("node3 ID %s matches removed node2 ID — swap did not produce a new node", v)
						}
						return nil
					}),
				),
			},

			// Step 6: Update public_address of node3 (IP → DNS)
			{
				Config: cfgPrimaryPublic(n1Host, n1Public) +
					cfgNodeBlock("node3", n3DNS.host, n3DNS.public, n1Host, n3DNS.addr, username, n3DNS.password),
				Check: checkStep(t, "Step 6: node3 public_address updated",
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node3", "public_address", n3.addr),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node3", "status_code", "r"),
				),
			},

			// Step 7: Re-add node2 — 3-node state before teardown
			{
				Config: cfgPrimaryPublic(n1Host, n1Public) +
					cfgNodeBlock("node2", n2.host, n2.public, n1Host, n2.addr, username, n2.password) +
					cfgNodeBlock("node3", n3DNS.host, n3DNS.public, n1Host, n3DNS.addr, username, n3DNS.password),
				Check: checkStep(t, "Step 7: 3-node cluster before teardown",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node2", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node2", "status_code", "r"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster_node.node3", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cluster_node.node3", "status_code", "r"),
				),
			},

			// Step 8: Destroy full 3-node cluster.
			// Applying provider-only config removes all three resources in dependency order.
			{Config: providerConfig},
		},
	})
}

// cfgPrimaryAltHost produces a single-node cluster config with a different local_node_host
// than cfgPrimary, used to test that ImmutableString() blocks host changes.
func cfgPrimaryAltHost(n1Host string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cluster" "primary" {
  local_node_host = %q
  local_node_port = 5432
}
`, "different-host-"+n1Host)
}

// cfgPrimaryAltPort produces a single-node cluster config with local_node_port changed to 5433,
// used to test that ImmutableInt64() blocks port changes.
func cfgPrimaryAltPort(n1Host string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cluster" "primary" {
  local_node_host = %q
  local_node_port = 5433
}
`, n1Host)
}

// Test_CM_CipherTrust_CMCluster_DriftDetection verifies computed fields populate without
// perpetual diffs, local_node_host/local_node_port are immutable at plan time, and
// node_count OOB drift is surfaced by Read() when CM_SECOND_NODE_HOST is set.
func Test_CM_CipherTrust_CMCluster_DriftDetection(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CLUSTER_ENABLED") != "1" {
		t.Skip("CLUSTER_ENABLED not set to 1; skipping cluster drift detection test — requires a cluster-capable CM instance")
	}
	n1Host, _ := node1Coords(t)
	var capturedNodeID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step A: Apply and verify all Computed fields are populated; capture node_id.
			{
				Config: cfgPrimary(n1Host),
				Check: checkStep(t, "computed-fields-set",
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "node_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "node_count"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "status_code"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "status_description"),
					resource.TestCheckResourceAttrSet("ciphertrust_cluster.primary", "raft_status"),
					func(s *terraform.State) error {
						capturedNodeID = s.RootModule().Resources["ciphertrust_cluster.primary"].Primary.Attributes["node_id"]
						return nil
					},
				),
				ExpectNonEmptyPlan: false,
			},
			// Step B: Changing local_node_host must produce an "Attribute is immutable" plan error.
			{
				Config:      cfgPrimaryAltHost(n1Host),
				ExpectError: regexp.MustCompile("Attribute is immutable"),
			},
			// Step C: Changing local_node_port must produce an "Attribute is immutable" plan error.
			{
				Config:      cfgPrimaryAltPort(n1Host),
				ExpectError: regexp.MustCompile("Attribute is immutable"),
			},
			// Step D: OOB node_count drift visibility — gated on CM_SECOND_NODE_HOST.
			// When set, a second CM node must have been manually joined before this test run.
			// Read() is expected to surface the changed node_count as a non-empty plan.
			{
				PreConfig: func() {
					if os.Getenv("CM_SECOND_NODE_HOST") == "" {
						t.Skip("CM_SECOND_NODE_HOST not set; skipping node_count OOB drift test — " +
							"requires a second CM node pre-joined before the test run")
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
	// Suppress unused variable warning — capturedNodeID is assigned in Step A's closure.
	_ = capturedNodeID
}
