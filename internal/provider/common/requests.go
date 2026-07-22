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

func (c *Client) DeleteByID(ctx context.Context, method string, uuid string, url string, Body []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> DeleteByID]["+uuid+"]")
	reader := bytes.NewBuffer(Body)
	req, err := http.NewRequest(method, url, reader)
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
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return responseJson, nil
}

func (c *Client) DeleteByURL(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> DeleteByURL]["+uuid+"]")
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
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
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> DeleteByurl]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return responseJson, nil
}

func (c *Client) GetAll(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAll][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
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
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAll][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint)+"]")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s?%s", c.CipherTrustURL, endpoint, filters.Encode()), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}
	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAll]["+uuid+"]")
	return string(body), nil
}

func (c *Client) GetById(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetById][Request ID: "+uuid+
		"****** URL: "+fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id)+"]")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
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

	req, err := http.NewRequest("GET", url, nil)
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
	tflog.Debug(ctx, "*****POST data for*****"+endpoint+"*****"+reader.String()+"*****")

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostData]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *Client) PostDataV2(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostData]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostData]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return string(body), nil
}

func (c *Client) PostNoData(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostData]["+uuid+"]")

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostData]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
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

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
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
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return string(body), nil
}

func (c *Client) UpdateData(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateData]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}
	//tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+string(payload)+"*****")

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, uuid), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateData]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *Client) UpdateDataV2(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateData]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, uuid), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateData]["+uuid+"]")
	return string(body), nil
}

func (c *Client) UpdateDataFullURL(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateData]["+uuid+"]")
	var payload io.Reader
	if len(data) == 0 {
		payload = nil
	} else {
		payload = bytes.NewBuffer(data)
	}
	//tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+string(payload)+"*****")

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateData]["+uuid+"]")
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *CMClientBootstrap) PostDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, "*****POST data for*****"+endpoint+"*****"+reader.String()+"*****")

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
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
	tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+reader.String()+"*****")

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
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
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
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
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
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
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *Client) PatchDataBootstrap(ctx context.Context, uuid string, endpoint string, data []byte) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PatchDataBootstrap]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
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
	time.Sleep(time.Duration(c.ReplicationDelay) * time.Millisecond)
	return ret, nil
}

func (c *Client) GetByIdBootstrap(ctx context.Context, uuid string, id string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetByIdBootstrap]["+uuid+"]")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, id), nil)
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
