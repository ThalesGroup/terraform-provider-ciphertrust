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

// terraform destroy will perform automatically at the end of the test

func Test_CM_Scheduler_StartDateEndDateClear(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_Scheduler_StartDateEndDateClear: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	uniqueName := "date-clear-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a scheduler with both start_date and end_date set
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name        = %q
  operation   = "database_backup"
  run_on      = "any"
  run_at      = "0 0 * * *"
  start_date  = "2026-08-01T00:00:00Z"
  end_date    = "2026-09-01T00:00:00Z"
  database_backup_params = {
    scope = "system"
  }
}
`, uniqueName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "name", uniqueName),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "start_date", "2026-08-01T00:00:00Z"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "end_date", "2026-09-01T00:00:00Z"),
				),
			},
			// Step 2: Clear start_date and end_date by setting them to ""
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name        = %q
  operation   = "database_backup"
  run_on      = "any"
  run_at      = "0 0 * * *"
  start_date  = ""
  end_date    = ""
  database_backup_params = {
    scope = "system"
  }
}
`, uniqueName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "start_date", ""),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.test", "end_date", ""),
				),
			},
		},
	})
}

func Test_CM_Scheduler_StartDateEndDateDrift(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_Scheduler_StartDateEndDateDrift: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	uniqueName := "drift-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create without start_date or end_date (meaning they are omitted, i.e. null)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name        = %q
  operation   = "database_backup"
  run_on      = "any"
  run_at      = "0 0 * * *"
  database_backup_params = {
    scope = "system"
  }
}
`, uniqueName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.test", "start_date"),
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.test", "end_date"),
				),
			},
			// Step 2: Run a plan to verify NO plan-time drift (dates must remain null in state)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name        = %q
  operation   = "database_backup"
  run_on      = "any"
  run_at      = "0 0 * * *"
  database_backup_params = {
    scope = "system"
  }
}
`, uniqueName),
				PlanOnly: true,
			},
		},
	})
}

func Test_CM_SchedulerList_DateAndAWSParams(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_SchedulerList_DateAndAWSParams: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	uniqueName := "list-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create scheduler and verify list data source maps flat attributes and handles null dates
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name        = %q
  operation   = "database_backup"
  run_on      = "any"
  run_at      = "0 0 * * *"
  database_backup_params = {
    scope = "system"
  }
}

data "ciphertrust_scheduler_list" "all" {
  depends_on = [ciphertrust_scheduler.test]
}
`, uniqueName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ciphertrust_scheduler_list.all", "id"),
				),
			},
		},
	})
}

func Test_CM_SchedulerDataSourceCCKMRotationEmptyStringFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_SchedulerDataSourceCCKMRotationEmptyStringFields: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	name := "tftest-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 0 * * *"
  cckm_key_rotation_params = {
    cloud_name = "aws"
  }
}

data "ciphertrust_scheduler_list" "jobs" {
  filters = { name = %q }
  depends_on = [ciphertrust_scheduler.test]
}
`, name, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs", "scheduler.0.cckm_key_rotation_params.expiration", ""),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs", "scheduler.0.cckm_key_rotation_params.expire_in", ""),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs", "scheduler.0.cckm_key_rotation_params.rotation_after", ""),
				),
			},
		},
	})
}

func Test_CM_SchedulerDataSourceStartEndDateEmptyStringFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_SchedulerDataSourceStartEndDateEmptyStringFields: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	name := "tftest-sched-dates-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_dates" {
  name      = %q
  operation = "database_backup"
  run_at    = "0 1 * * *"
  database_backup_params = {
    scope = "system"
  }
}

data "ciphertrust_scheduler_list" "jobs_dates" {
  filters = { name = %q }
  depends_on = [ciphertrust_scheduler.test_dates]
}
`, name, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs_dates", "scheduler.0.start_date", ""),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs_dates", "scheduler.0.end_date", ""),
				),
			},
		},
	})
}

func Test_CM_SchedulerDataSourceCCKMRotationDrift(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_SchedulerDataSourceCCKMRotationDrift: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	name := "tftest-sched-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 0 * * *"
  cckm_key_rotation_params = {
    cloud_name = "aws"
  }
}

data "ciphertrust_scheduler_list" "jobs" {
  filters = { name = %q }
  depends_on = [ciphertrust_scheduler.test]
}
`, name, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs", "scheduler.0.cckm_key_rotation_params.expiration", ""),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_scheduler.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("CM client unavailable")
					}
					payload, err := json.Marshal(map[string]interface{}{
						"cckm_key_rotation_params": map[string]interface{}{
							"expiration": "7d",
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					_, err = client.UpdateDataV2(context.Background(), capturedID, common.URL_SCHEDULER_JOB_CONFIGS, payload)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 0 * * *"
  cckm_key_rotation_params = {
    cloud_name = "aws"
  }
}

data "ciphertrust_scheduler_list" "jobs" {
  filters = { name = %q }
  depends_on = [ciphertrust_scheduler.test]
}
`, name, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.jobs", "scheduler.0.cckm_key_rotation_params.expiration", "7d"),
				),
			},
		},
	})
}

// Test_CM_SchedulerList_ZeroMatchReturnsEmptySlice verifies that a filter matching
// zero schedulers returns an empty list (not null), so length() and for_each work
// correctly (TFIN-556 regression test).
func Test_CM_SchedulerList_ZeroMatchReturnsEmptySlice(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_scheduler_list" "zero" {
  filters = {
    name = "nonexistent-scheduler-zzz-tfin556"
  }
}

output "zero_count" {
  value = length(data.ciphertrust_scheduler_list.zero.scheduler)
}
`,
				Check: checkStep(t, "zero-match returns empty list",
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.zero", "scheduler.#", "0"),
				),
			},
		},
	})
}

// Test_CM_Scheduler_EmptyDateNotRejectedOnCreate verifies that start_date = "" and
// end_date = "" do not cause a 400 error on Create() (TFIN-557). Empty strings are
// the "clear/unset" sentinel and must be omitted from the POST payload; they are
// only valid in PATCH (update) requests.
// Requires CIPHERTRUST_SCHEDULER_ENABLED=1.
func Test_CM_Scheduler_EmptyDateNotRejectedOnCreate(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_Scheduler_EmptyDateNotRejectedOnCreate: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	name := "tf-sched-emptydate-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Creating with start_date = "" and end_date = "" must not return 400.
				// Before the fix: Create() sent "" in the POST payload → CM rejected with HTTP 400.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test" {
  name       = %q
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  start_date = ""
  end_date   = ""
  cckm_key_rotation_params = {
    cloud_name = "aws"
  }
}`, name),
				Check: checkStep(t, "create with empty dates — no 400 error",
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.test", "id"),
				),
			},
		},
	})
}

// Test_CM_Scheduler_MutuallyExclusiveParamsRejectedAtPlan verifies that setting more
// than one of the four mutually-exclusive params blocks produces a plan-time error
// (TFIN-558). Before the fix, this passed plan silently and crashed apply.
func Test_CM_Scheduler_MutuallyExclusiveParamsRejectedAtPlan(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "test" {
  name      = "tf-sched-mutex-probe"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  cckm_key_rotation_params = {
    cloud_name = "aws"
  }
  cckm_synchronization_params = {
    cloud_name = "aws"
  }
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)mutually exclusive`),
			},
		},
	})
}
