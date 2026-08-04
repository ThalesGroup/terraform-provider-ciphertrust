package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// waitForReplication waits until ReplicationDelay milliseconds have elapsed,
// respecting ctx cancellation. It is a no-op when the provider is not running
// against a cluster or when ReplicationDelay is zero or negative.
func (c *Client) waitForReplication(ctx context.Context) error {
	if !c.IsClustered || c.ReplicationDelay <= 0 {
		return nil
	}

	timer := time.NewTimer(time.Duration(c.ReplicationDelay) * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) DeleteByID(ctx context.Context, method string, uuid string, url string, Body []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> DeleteByID]["+uuid+"]")
	reader := bytes.NewBuffer(Body)
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> DeleteByID]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> DeleteByID]["+uuid+"]")
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> DeleteByID]["+uuid+"]")
	return responseJson, nil
}

func (c *Client) DeleteByURL(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> DeleteByURL]["+uuid+"]")
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> DeleteByURL]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> DeleteByURL]["+uuid+"]")
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> DeleteByURL]["+uuid+"]")
	return responseJson, nil
}

func (c *Client) GetAll(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAll][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAll]["+uuid+"]")
	return responseJson, nil
}

func (c *Client) GetAllWithTotal(ctx context.Context, uuid string, endpoint string) (string, int64, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAllWithTotal][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAllWithTotal]["+uuid+"]")
		return "", 0, err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAllWithTotal]["+uuid+"]")
		return "", 0, err
	}

	bodyStr := string(body)
	responseJson := gjson.Get(bodyStr, "resources").String()
	total := gjson.Get(bodyStr, "total").Int()

	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAllWithTotal]["+uuid+"]")
	return responseJson, total, nil
}

// cteListPageSize is the number of results requested per page by GetAllPaged.
// It is intentionally large to minimise round-trips; CipherTrust Manager honours
// smaller server-side caps transparently because GetAllPaged advances by the
// number of results actually returned rather than by the requested limit.
const cteListPageSize = 256

// pagedListMaxIterations bounds GetAllPaged so a misbehaving server that keeps
// returning non-empty pages without advancing cannot loop forever.
const pagedListMaxIterations = 100000

// appendPagination appends skip/limit query parameters to endpoint, choosing the
// correct separator: "?" when endpoint has no query, "&" when it already has one,
// and "" when endpoint already ends in "?" or "&" (e.g. a pre-built filter chain).
func appendPagination(endpoint string, skip, limit int) string {
	sep := "?"
	if strings.Contains(endpoint, "?") {
		if strings.HasSuffix(endpoint, "?") || strings.HasSuffix(endpoint, "&") {
			sep = ""
		} else {
			sep = "&"
		}
	}
	return fmt.Sprintf("%s%sskip=%d&limit=%d", endpoint, sep, skip, limit)
}

// GetAllPaged pages through a CipherTrust Manager list endpoint via skip/limit,
// accumulating the "resources" array from every page, and returns the combined
// result as a JSON array string (drop-in compatible with GetAll's return value).
// Unlike GetAll, which fetches only the first server-side page, this walks every
// page so callers see the complete result set. An empty result set returns "[]".
func (c *Client) GetAllPaged(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAllPaged][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")

	resources := []json.RawMessage{}
	skip := 0
	for i := 0; i < pagedListMaxIterations; i++ {
		pagedEndpoint := appendPagination(endpoint, skip, cteListPageSize)
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, pagedEndpoint), nil)
		if err != nil {
			tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAllPaged]["+uuid+"]")
			return "", err
		}

		body, err := c.doRequest(ctx, uuid, req, nil)
		if err != nil {
			tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAllPaged]["+uuid+"]")
			return "", err
		}

		page := gjson.Get(string(body), "resources").Array()
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			resources = append(resources, json.RawMessage(r.Raw))
		}
		skip += len(page)

		// Prefer the server-reported total when present; otherwise keep paging
		// until an empty page is returned (the always-correct terminator).
		if total := gjson.Get(string(body), "total"); total.Exists() && skip >= int(total.Int()) {
			break
		}
	}

	out, err := json.Marshal(resources)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAllPaged]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAllPaged]["+uuid+"]")
	return string(out), nil
}

func (c *Client) ListWithFilters(ctx context.Context, uuid string, endpoint string, filters url.Values) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> ListWithFilters][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s?%s", c.CipherTrustURL, endpoint, filters.Encode()), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> ListWithFilters]["+uuid+"]")
		return "", err
	}
	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> ListWithFilters]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> ListWithFilters]["+uuid+"]")
	return string(body), nil
}

func (c *Client) GetById(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetById][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id)+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetById]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetById]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetById]["+uuid+"]")
	return string(body), err
}

func (c *Client) ReadDataByParam(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> ReadDataByParam][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id)+"]")
	var url string
	if id == "all" {
		url = fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)
	} else {
		url = fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> ReadDataByParam]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> ReadDataByParam]["+uuid+"]")
		return "", err
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> ReadDataByParam]["+uuid+"]")
	return string(body), err
}

func (c *Client) PostData(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostData]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, fmt.Sprintf("POST request to %s: payload size %d bytes", endpoint, len(data)))

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	jsonResult := gjson.Get(string(body), id)
	if !jsonResult.Exists() {
		return "", fmt.Errorf("creation successful on endpoint %q, but the expected identifier field %q is missing from the API response payload", endpoint, id)
	}

	ret := jsonResult.String()
	if ret == "" {
		return "", fmt.Errorf("creation successful on endpoint %q, but the expected identifier field %q has an empty string value in the API response payload", endpoint, id)
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostData]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return ret, nil
}

func (c *Client) PostDataV2(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostDataV2]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataV2]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataV2]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostDataV2]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) PostNoData(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostNoData]["+uuid+"]")

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostNoData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostNoData]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostNoData]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) PutData(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PutData]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PutData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PutData]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PutData]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) UpdateData(ctx context.Context, resourceID string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateData][resourceID: "+resourceID+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}
	//tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+string(payload)+"*****")

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, resourceID), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData][resourceID: "+resourceID+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, resourceID, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData][resourceID: "+resourceID+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id)
	if id != "" && len(body) > 0 && !ret.Exists() {
		return "", fmt.Errorf("UpdateData: field %q not found in PATCH response body", id)
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateData][resourceID: "+resourceID+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return ret.String(), nil
}

func (c *Client) UpdateDataV2(ctx context.Context, resourceID string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateDataV2][resourceID: "+resourceID+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, resourceID), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateDataV2][resourceID: "+resourceID+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, resourceID, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateDataV2][resourceID: "+resourceID+"]")
		return "", err
	}
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateDataV2][resourceID: "+resourceID+"]")
	return string(body), nil
}

func (c *Client) UpdateDataFullURL(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateDataFullURL]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}
	//tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+string(payload)+"*****")

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateDataFullURL]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateDataFullURL]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateDataFullURL]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return ret, nil
}

func (c *CMClientBootstrap) PostDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, fmt.Sprintf("POST Bootstrap request to %s: payload size %d bytes", endpoint, len(data)))

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequestBootstrap(ctx, uuid, req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataBootstrap]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostDataBootstrap]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *CMClientBootstrap) PatchDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PatchDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, fmt.Sprintf("PATCH Bootstrap request to %s: payload size %d bytes", endpoint, len(data)))

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PatchDataBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequestBootstrap(ctx, uuid, req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PatchDataBootstrap]["+uuid+"]")
		return "", err
	}

	ret := string(body)
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PatchDataBootstrap]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *CMClientBootstrap) GetByIdBootstrap(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetByIdBootstrap]["+uuid+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetByIdBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequestBootstrap(ctx, uuid, req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetByIdBootstrap]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetByIdBootstrap]["+uuid+"]")
	return string(body), nil
}

func (c *Client) PostDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostDataBootstrap]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostDataBootstrap]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return ret, nil
}

func (c *Client) PatchDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PatchDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PatchDataBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PatchDataBootstrap]["+uuid+"]")
		return "", err
	}

	ret := string(body)
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PatchDataBootstrap]["+uuid+"]")
	if err := c.waitForReplication(ctx); err != nil {
		return "", err
	}
	return ret, nil
}

func (c *Client) GetByIdBootstrap(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetByIdBootstrap]["+uuid+"]")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetByIdBootstrap]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetByIdBootstrap]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetByIdBootstrap]["+uuid+"]")
	return string(body), nil
}
