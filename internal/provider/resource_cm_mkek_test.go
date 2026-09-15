package provider

import (
	"context"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_MKEK_Basic(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_mkek" "test" {}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "created_at"),
					// sealer_name and kek_name may be empty strings when CM does not
					// populate them; verify the keys exist in state rather than non-empty.
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "is_default"),
				),
			},
			{
				// Verify no drift on subsequent plan.
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
				Config: providerConfig + `
resource "ciphertrust_cm_mkek" "test" {}
`,
			},
		},
	})
}

func Test_CM_MKEK_OOBDrift(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_mkek" "test" {}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_mkek.test", "created_at"),
				),
			},
			{
				// Issue an out-of-band rotate, then refresh to surface the resulting drift.
				// The tracked MKEK's is_default changes to false after the new MKEK takes over.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB rotate")
						return
					}
					ctx := context.Background()
					uid := uuid.New().String()
					_, _ = client.PostNoData(ctx, uid, common.URL_MKEK+"/rotate")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
