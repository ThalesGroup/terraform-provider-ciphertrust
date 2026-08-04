# Conventions

The patterns to follow when writing code in this repo. If you find yourself unsure how something is usually done, this file (or grepping any existing resource in the same subsystem) is the answer.

## Framework
- **terraform-plugin-framework**, not the legacy `terraform-plugin-sdk/v2`.
- Resources implement `resource.Resource` + `resource.ResourceWithConfigure`. Data sources implement `datasource.DataSource`. The compile-time check is:
  ```go
  var (
      _ resource.Resource              = &resourceFoo{}
      _ resource.ResourceWithConfigure = &resourceFoo{}
  )
  ```

## Resource skeleton (the house style)
```go
package <subsystem>

import (
    "context"
    "encoding/json"
    "fmt"

    common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
    "github.com/google/uuid"
    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
    "github.com/hashicorp/terraform-plugin-framework/types"
    "github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
    _ resource.Resource              = &resourceFoo{}
    _ resource.ResourceWithConfigure = &resourceFoo{}
)

func NewResourceFoo() resource.Resource { return &resourceFoo{} }

type resourceFoo struct {
    client *common.Client
}

func (r *resourceFoo) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_foo"
}

func (r *resourceFoo) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
    if req.ProviderData == nil {
        return
    }
    client, ok := req.ProviderData.(*common.Client)
    if !ok {
        resp.Diagnostics.AddError(
            "Error in fetching client from provider",
            fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
        )
        return
    }
    r.client = client
}

func (r *resourceFoo) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) { /* ... */ }
func (r *resourceFoo) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) { /* ... */ }
func (r *resourceFoo) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) { /* ... */ }
func (r *resourceFoo) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) { /* ... */ }
func (r *resourceFoo) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) { /* ... */ }
```

`id`/computed identifier attribute usually has:
```go
PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
```

## HTTP client helpers — `*common.Client` methods in [common/requests.go](../../internal/provider/common/requests.go)

| Method | Signature (essentials) | When to use |
|---|---|---|
| `GetById` | `(ctx, uuid, id, endpoint) (string, error)` | Read a single resource by id, returns full JSON body |
| `GetAll` | `(ctx, uuid, endpoint) (string, error)` | List all under an endpoint, returns `resources` field |
| `ListWithFilters` | `(ctx, uuid, endpoint, url.Values) (string, error)` | List with query string filters |
| `ReadDataByParam` | `(ctx, uuid, id, endpoint) (string, error)` | Read by query-string param instead of path |
| `PostData` | `(ctx, uuid, endpoint, []byte, idJSONPath) (string, error)` | Create — returns the value at the supplied JSON path (usually the new id) |
| `PostDataV2` | `(ctx, uuid, endpoint, []byte) (string, error)` | Create — returns full response body |
| `PostNoData` | `(ctx, uuid, endpoint) (string, error)` | Trigger an action with no body |
| `PutData` | `(ctx, uuid, endpoint, []byte) (string, error)` | PUT — full replacement |
| `UpdateData` | `(ctx, uuid, endpoint, []byte, id) (string, error)` | PATCH-style update by id, returns response body |
| `UpdateDataV2` | `(ctx, uuid, endpoint, []byte) (string, error)` | Update where endpoint already contains the id |
| `UpdateDataFullURL` | `(ctx, uuid, endpoint, []byte, id) (string, error)` | Update at a full URL (not appended to base) |
| `DeleteByID` | `(ctx, method, uuid, url, []byte) (string, error)` | Delete — caller supplies method (usually `"DELETE"`) and full URL |
| `DeleteByURL` | `(ctx, uuid, endpoint) (string, error)` | Delete by endpoint (relative to base URL) |

**Every write method sleeps `c.ReplicationDelay` ms after the call** so cluster nodes have time to replicate. Don't double-sleep in callers.

## API source-of-truth — swagger splits
The CipherTrust Manager API is fully specified in [definition-beta.json](../../definition-beta.json) (~14.8 MB / ~3.7M tokens — **never load directly**). Pre-split + deduplicated files live under [.claude/swagger/](../swagger/):
- Grep [.claude/swagger/operations.md](../swagger/operations.md) for the keyword → find the area
- Read [.claude/swagger/areas/<area>.json](../swagger/areas/) for request/response schemas
- Resolve `"$ref": "../definitions.json#/D####"` by greping [.claude/swagger/definitions.json](../swagger/definitions.json) for `"D####":`

When adding a new resource, this is where you discover field names, required params, response shapes, and the URL to put in `urls.go`.

## URL constants — [common/urls.go](../../internal/provider/common/urls.go)
All CM API endpoints are constants like `URL_USER_MANAGEMENT`, `URL_AWS_KMS`, `URL_OCI_CONNECTION`. **Add new endpoints here** instead of inlining URL strings. Highlights:

| Constant | Endpoint |
|---|---|
| `URL_USER_MANAGEMENT` | `api/v1/usermgmt/users` |
| `URL_KEY_MANAGEMENT` | `api/v1/vault/keys2` |
| `URL_AWS_CONNECTION` | `api/v1/connectionmgmt/services/aws/connections` |
| `URL_AWS_KMS` | `api/v1/cckm/aws/kms` |
| `URL_AWS_KEY` | `api/v1/cckm/aws/keys` |
| `URL_AWS_XKS` | `api/v1/cckm/aws/custom-key-stores` |
| `URL_AWS_XKS_KEY` | `api/v1/cckm/aws/create-hyok-key` |
| `URL_AWS_POLICY_TEMPLATES` | `api/v1/cckm/aws/templates` |
| `URL_AZURE_CONNECTION` | `api/v1/connectionmgmt/services/azure/connections` |
| `URL_GCP_CONNECTION` | `api/v1/connectionmgmt/services/gcp/connections` |
| `URL_OCI_CONNECTION` | `api/v1/connectionmgmt/services/oci/connections` |
| `URL_OCI` | `api/v1/cckm/oci` |
| `URL_SCP_CONNECTION` | `api/v1/connectionmgmt/services/scp/connections` |
| `URL_SCHEDULER_JOB_CONFIGS` | `api/v1/scheduler/job-configs` |

Full list (60 constants) is in [common/urls.go](../../internal/provider/common/urls.go).

## Logging convention — `tflog` from `github.com/hashicorp/terraform-plugin-log`
```go
id := uuid.New().String()
tflog.Trace(ctx, common.MSG_METHOD_START+"[<file>.go -> <Func>]["+id+"]")
defer tflog.Trace(ctx, common.MSG_METHOD_END+"[<file>.go -> <Func>]["+id+"]")
// ... and on error:
tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [<file>.go -> <Func>]["+id+"]")
```
The uuid is passed down to `c.GetById` / `c.PostData` etc. so request and response logs can be correlated. **Always generate a fresh uuid at the top of each CRUD method** — don't reuse one across calls.

## JSON parsing
- Use `github.com/tidwall/gjson` for extracting fields from response bodies:
  ```go
  id := gjson.Get(responseStr, "id").String()
  ```
- For structured unmarshalling, define a JSON model (often in [models/json_models.go](../../internal/provider/models/json_models.go) or alongside the resource) and `json.Unmarshal`.

## Diagnostics — error vs warning
- Surface unexpected failures with `resp.Diagnostics.AddError(summary, detail)` and **always return** after.
- For per-attribute issues, use `resp.Diagnostics.AddAttributeError(path.Root("foo"), summary, detail)`.
- Warn (don't fail) for advisory issues: `resp.Diagnostics.AddWarning(...)`.

## 404 behavior on Read / Update / Delete

**Read / Update 404 → `AddError` + preserve state** (do NOT call `resp.State.RemoveResource`).  
Rationale: a 404 during Read or Update is unexpected; the resource existed in state. Surfacing it as a hard error forces the operator to decide: `terraform state rm` to drop it, or re-apply to recreate it. Using a warning here risks silent drift going unnoticed.

**Delete 404 → `AddWarning` + return normally** (Terraform removes the resource from state automatically when Delete returns with no error).  
Rationale: if the resource is already gone, the desired state (absent) is achieved. An error would leave a phantom entry in state.

Use the common format strings from `common/diagnostics.go` (never write ad-hoc messages):
```go
// Read/Update 404:
resp.Diagnostics.AddError(
    fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "Resource Type"),
    fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "Resource Type", state.ID.ValueString()),
)

// Delete 404:
resp.Diagnostics.AddWarning(
    common.NotFoundDeleteWarningSummary,
    common.NotFoundDeleteWarningDetail,
)
```

Commit `43f3b14` ("Conservative approach: keep resources in state on 404 unless deleting target resource") established the state-preservation rule. The severity was later changed from Warning to Error for Read/Update to make drift explicit.

## Replica / long-running operations
- AWS replica creation can be slow → see `resource_aws_key.go` constants `replicaKeyCreatingException`, `longAwsKeyOpSleep`, `refreshTokenSeconds`.
- Provider-level `aws_operation_timeout` and `oci_operation_timeout` (both default 480s) configure how long to wait.
- Recent precedent: PR #114 added wait-for-replica-import; PR #113 added wait-for-replication on import-material failure.

## Common plan modifiers
- `stringplanmodifier.UseStateForUnknown()` — preserves a computed value across plans (use on `id`, generated names, etc.)
- `stringplanmodifier.RequiresReplace()` — force destroy/recreate when an immutable field changes
- Custom modifiers in [common/customModifierForListNestedAttribute.go](../../internal/provider/common/customModifierForListNestedAttribute.go) and [common/customModifierForSingleNestedAttribute.go](../../internal/provider/common/customModifierForSingleNestedAttribute.go)

## Mutex (CCKM)
For operations that must not race (e.g., concurrent updates to the same KMS), use the helpers in [cckm/mutex/mutex.go](../../internal/provider/cckm/mutex/mutex.go).

## Docs are generated
Don't write `docs/resources/foo.md` by hand. Add an example in `examples/resources/ciphertrust_foo/resource.tf`, ensure schema descriptions are populated, then `make generate`. The pipeline uses `terraform-plugin-docs` and templates in [templates/](../../templates/).
