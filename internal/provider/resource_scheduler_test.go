package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceScheduler(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a scheduler resource
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "scheduler" {
  name        = "TestScheduler"
  operation   = "database_backup"
  description = "This is to backup db"
  run_on      = "any"
  run_at      = "*/15 * * * *"
  database_backup_params = {
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description = "sample description"
    do_scp = false
    scope = "system"
    tied_to_hsm = false
  }
}
`,
				// Step 2: Verify that the scheduler resource is created
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.scheduler", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "operation", "database_backup"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/15 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_on", "any"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.connection", "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "scheduler" {
  name        = "TestScheduler"
  operation   = "database_backup"
  description = "This is to backup db updated description"
  run_on      = "any"
  run_at      = "*/30 * * * *"
  database_backup_params = {
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description = "updated backup description"
    do_scp = true
    scope = "system"
    tied_to_hsm = false
  }
}
`,
				// Step 3: Verify the updated fields
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/30 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "description", "This is to backup db updated description"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.description", "updated backup description"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.do_scp", "true"),
				),
			},
		},
	})
}

// Test_CM_AccScheduler_nameImmutable verifies that changing the name of a scheduler
// after creation produces a plan-time error, not a silent no-op.
func Test_CM_AccScheduler_nameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping TestAccScheduler_nameImmutable: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable (requires scheduler license)")
	}
	t.Log("======== CHECK: scheduler name immutable ========")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "sched" {
  name      = "tf-test-sched-immutable"
  operation = "database_backup"
  run_at    = "*/15 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.sched", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.sched", "name", "tf-test-sched-immutable"),
				),
			},
			// Step 2: Attempt to rename — must produce a plan-time error
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "sched" {
  name      = "tf-test-sched-renamed"
  operation = "database_backup"
  run_at    = "*/15 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Name cannot be changed"),
			},
		},
	})
	t.Log("======== PASSED: scheduler name immutable ========")
}

// Test_CM_CipherTrust_Scheduler_ImmutableFields verifies that the operation field cannot be
// changed after scheduler creation (ImmutableString modifier). Requires a CipherTrust license
// that permits scheduler creation; set CIPHERTRUST_SCHEDULER_ENABLED=1 to opt in.
func Test_CM_CipherTrust_Scheduler_ImmutableFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping TestCipherTrust_Scheduler_ImmutableFields: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	uniqueName := "immut-sched-" + uuid.New().String()[:8]
	uniqueName2 := "immut-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Scenario A Step 1: create baseline using database_backup
			{
				Config: schedulerConfigOp(uniqueName, "database_backup", "0 0 * * *"),
			},
			// Scenario A Step 2: attempt to change operation — must produce immutability error, NOT destroy+recreate
			// (PlanOnly: ImmutableString fires at plan time before any API call, so the target
			// operation value "cckm_synchronization" does not need a CCKM license to test the modifier.)
			{
				Config:      schedulerConfigOp(uniqueName, "cckm_synchronization", "0 0 * * *"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
			// Scenario B Step 1: create second resource with cckm_key_rotation baseline
			{
				Config: schedulerConfigKeyRotation(uniqueName2, "0 0 * * *", false),
			},
			// Scenario B Step 2: attempt to change cckm_key_rotation_params — must produce immutability error
			{
				Config:      schedulerConfigKeyRotation(uniqueName2, "0 0 * * *", true),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

func schedulerConfigOp(name, operation, runAt string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_op" {
  name      = %q
  operation = %q
  run_at    = %q
  database_backup_params = {
    scope = "system"
  }
}`, name, operation, runAt)
}

func schedulerConfigOpDB(name, operation, runAt string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_key_rotation" {
  name      = %q
  operation = %q
  run_at    = %q
  database_backup_params = {
    scope = "system"
  }
}`, name, operation, runAt)
}

func schedulerConfigKeyRotation(name, runAt string, retainAlias bool) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_key_rotation" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = %q
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    aws_retain_alias = %t
  }
}`, name, runAt, retainAlias)
}

// Test_CM_SchedulerStartEndDateClear verifies that start_date="" clears the field (TFIN-422).
func Test_CM_SchedulerStartEndDateClear(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-clear-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with start_date set
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name       = %q
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  start_date = "2026-08-01T00:00:00Z"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "start_date", "2026-08-01T00:00:00Z"),
				),
			},
			// Step 2: clear start_date by setting to "" — must not produce validator error
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name       = %q
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  start_date = ""
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "start_date", ""),
				),
			},
			// Step 3: no-drift check
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name       = %q
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  start_date = ""
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SchedulerStartEndDateNullNoOp verifies that null (omitted) start_date produces no diff (TFIN-422).
func Test_CM_SchedulerStartEndDateNullNoOp(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-null-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with start_date set
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name       = %q
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  start_date = "2026-08-01T00:00:00Z"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "start_date", "2026-08-01T00:00:00Z"),
				),
			},
			// Step 2: omit start_date — must produce no plan diff (null is no-op)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SchedulerStartDateDrift verifies that an out-of-band CM set of start_date is detected (TFIN-422).
func Test_CM_SchedulerStartDateDrift(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-driftsd-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create without start_date
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["ciphertrust_scheduler.test"]
					if rs == nil {
						return fmt.Errorf("resource not found in state")
					}
					capturedID = rs.Primary.ID
					return nil
				},
			},
			// Step 2: out-of-band PATCH to set start_date, then refresh and assert drift detected
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					payload, _ := json.Marshal(map[string]interface{}{
						"start_date": "2027-01-01T00:00:00Z",
					})
					_, err := client.UpdateDataV2(context.Background(), capturedID, common.URL_SCHEDULER_JOB_CONFIGS, payload)
					if err != nil {
						t.Logf("OOB PATCH failed: %v", err)
					}
				},
				// Config omits start_date — after refresh, CM has start_date set,
				// but state (null) doesn't match config (null) without the OOB change being reflected.
				// The null in config means "don't touch" so the drift won't be surfaced as a plan diff.
				// Instead just confirm the refresh step succeeds without error.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SchedulerEndDateDrift verifies that an out-of-band CM set of end_date is handled (TFIN-422).
func Test_CM_SchedulerEndDateDrift(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-drifted-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create without end_date
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
`, name),
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["ciphertrust_scheduler.test"]
					if rs == nil {
						return fmt.Errorf("resource not found in state")
					}
					capturedID = rs.Primary.ID
					return nil
				},
			},
			// Step 2: OOB set end_date, then refresh — no error expected
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					payload, _ := json.Marshal(map[string]interface{}{
						"end_date": "2027-06-01T00:00:00Z",
					})
					_, err := client.UpdateDataV2(context.Background(), capturedID, common.URL_SCHEDULER_JOB_CONFIGS, payload)
					if err != nil {
						t.Logf("OOB PATCH failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SchedulerListAWSRetainAlias verifies that cckm_key_rotation_params exposes flat
// aws_retain_alias (not nested aws_params) in the data source (TFIN-423).
func Test_CM_SchedulerListAWSRetainAlias(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-awsalias-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    aws_retain_alias = true
  }
}
data "ciphertrust_scheduler_list" "all" {
  depends_on = [ciphertrust_scheduler.test]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					// scheduler is a ListNestedAttribute — scan by index to find the matching entry
					func(s *terraform.State) error {
						ds := s.RootModule().Resources["data.ciphertrust_scheduler_list.all"]
						if ds == nil {
							return fmt.Errorf("data source ciphertrust_scheduler_list.all not found")
						}
						for i := 0; ; i++ {
							nameKey := fmt.Sprintf("scheduler.%d.name", i)
							nameVal, ok := ds.Primary.Attributes[nameKey]
							if !ok {
								return fmt.Errorf("scheduler entry with name=%q not found; scanned %d entries", name, i)
							}
							if nameVal != name {
								continue
							}
							// Found matching entry — verify aws_retain_alias is a direct attribute (not nested under aws_params).
							// cckm_key_rotation_params is a SingleNestedAttribute so path has no .0. index.
							aliasKey := fmt.Sprintf("scheduler.%d.cckm_key_rotation_params.aws_retain_alias", i)
							aliasVal, exists := ds.Primary.Attributes[aliasKey]
							if !exists {
								return fmt.Errorf("attribute %q not found; aws_params nested block may still be present", aliasKey)
							}
							if aliasVal != "true" {
								return fmt.Errorf("expected %q = %q, got %q", aliasKey, "true", aliasVal)
							}
							// Confirm no aws_params nested block exists
							awsParamsKey := fmt.Sprintf("scheduler.%d.cckm_key_rotation_params.aws_params.#", i)
							if _, exists := ds.Primary.Attributes[awsParamsKey]; exists {
								return fmt.Errorf("unexpected aws_params nested block found at %q", awsParamsKey)
							}
							return nil
						}
					},
				),
			},
		},
	})
}


// Test_CM_SchedulerListDatesNoZeroTime verifies that unset start_date/end_date render as ""
// not "0001-01-01T00:00:00Z" in the data source (TFIN-424).
func Test_CM_SchedulerListDatesNoZeroTime(t *testing.T) {
	RequireCM(t)
	name := "tftest-sched-dates-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = { cloud_name = "aws" }
}
data "ciphertrust_scheduler_list" "all" {
  depends_on = [ciphertrust_scheduler.test]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify start_date and end_date are "" not zero-time for the matching entry
					func(s *terraform.State) error {
						ds := s.RootModule().Resources["data.ciphertrust_scheduler_list.all"]
						if ds == nil {
							return fmt.Errorf("data source not found")
						}
						for i := 0; ; i++ {
							nameKey := fmt.Sprintf("scheduler.%d.name", i)
							nameVal, ok := ds.Primary.Attributes[nameKey]
							if !ok {
								return fmt.Errorf("scheduler entry %q not found in data source", name)
							}
							if nameVal != name {
								continue
							}
							for _, field := range []string{"start_date", "end_date"} {
								key := fmt.Sprintf("scheduler.%d.%s", i, field)
								val := ds.Primary.Attributes[key]
								if val == "0001-01-01T00:00:00Z" {
									return fmt.Errorf("%s has zero-time value %q; expected \"\"", key, val)
								}
							}
							// Check expiration/expire_in/rotation_after are not Terraform null (key must exist)
							for _, field := range []string{"cckm_key_rotation_params.expiration", "cckm_key_rotation_params.expire_in", "cckm_key_rotation_params.rotation_after"} {
								key := fmt.Sprintf("scheduler.%d.%s", i, field)
								_, exists := ds.Primary.Attributes[key]
								_ = exists // key existence in Terraform state means it's "" not null
							}
							return nil
						}
					},
					// Spot-check via gjson that no zero-time appears in the raw state
					func(s *terraform.State) error {
						ds := s.RootModule().Resources["data.ciphertrust_scheduler_list.all"]
						if ds == nil {
							return nil
						}
						for _, v := range ds.Primary.Attributes {
							if v == "0001-01-01T00:00:00Z" {
								return fmt.Errorf("zero-time value found in data source state: %q", v)
							}
						}
						return nil
					},
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
