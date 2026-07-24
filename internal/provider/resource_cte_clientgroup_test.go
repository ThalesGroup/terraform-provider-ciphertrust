// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCTEClientGroupResource walks a client group through create -> attribute
// update -> add-clients -> remove-clients -> import. name and cluster_type are
// immutable; attribute edits use op_type = "update".
func TestCTEClientGroupResource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-" + suffix
	c1 := "tf-cg-c1-" + suffix
	c2 := "tf-cg-c2-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName)

	updateCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  op_type               = "update"
  communication_enabled = true
  client_locked         = true
}
`, cgName)

	clientsBlock := fmt.Sprintf(`
resource "ciphertrust_cte_client" "c1" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
  communication_enabled    = true
  client_locked            = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
  communication_enabled    = true
  client_locked            = true
}
`, c1, c2)

	addCfg := providerConfig + clientsBlock + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  communication_enabled = true
  client_locked         = true
  op_type               = "add-client"
  client_list           = [ciphertrust_cte_client.c1.name, ciphertrust_cte_client.c2.name]
  inherit_attributes    = true
}
`, cgName)

	removeCfg := providerConfig + clientsBlock + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  communication_enabled = true
  client_locked         = true
  op_type               = "remove-client"
  client_list           = []
}
`, cgName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "client_group: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", cgName),
					resource.TestCheckResourceAttr(rn, "description", "Initial create"),
				),
			},
			{
				Config: updateCfg,
				Check: checkStep(t, "client_group: update attributes",
					resource.TestCheckResourceAttr(rn, "description", "Updated via TF"),
				),
			},
			{
				Config: addCfg,
				Check: checkStep(t, "client_group: add clients",
					resource.TestCheckResourceAttr(rn, "client_list.#", "2"),
				),
			},
			{
				Config: removeCfg,
				Check: checkStep(t, "client_group: remove clients",
					resource.TestCheckResourceAttr(rn, "client_list.#", "0"),
				),
			},
			// Import: passthrough id; op_type/client_list are action fields not
			// returned by Read, so ImportStateCheck is used instead of Verify.
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestCTEClientGroupResource_nameImmutable verifies a name change is rejected.
func TestCTEClientGroupResource_nameImmutable(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-imm-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	renamed := func(name string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
  op_type      = "update"
}
`, name)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName),
				Check: checkStep(t, "client_group immutable: create",
					resource.TestCheckResourceAttr(rn, "name", cgName),
				),
			},
			{
				Config:      renamed(cgName + "-renamed"),
				ExpectError: regexp.MustCompile(`(?i)cannot change client group name|immutable`),
			},
		},
	})
}

// TestCTEClientGroupResource_clusterTypeImmutable verifies a change to the
// (immutable) cluster_type is rejected.
func TestCTEClientGroupResource_clusterTypeImmutable(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-ctimm-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	cfg := func(clusterType, op string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = %q
  description  = "ct immutable"
%s}
`, cgName, clusterType, op)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("NON-CLUSTER", ""),
				Check: checkStep(t, "client_group cluster_type immutable: create",
					resource.TestCheckResourceAttr(rn, "cluster_type", "NON-CLUSTER"),
				),
			},
			{
				Config:      cfg("HDFS", "  op_type = \"update\"\n"),
				ExpectError: regexp.MustCompile(`(?i)cannot change client group cluster_type|immutable`),
			},
		},
	})
}

// TestCTEClientGroupResource_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestCTEClientGroupResource_drift(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-drift-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Drift original"
}
`, cgName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "client_group drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Drift original"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_CLIENT_GROUP, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
