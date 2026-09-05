package connections

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/tidwall/gjson"
)

const (
	awsConnPageSize = 10
	scpConnPageSize = 10
)

func cloneValues(src url.Values) url.Values {
	dst := url.Values{}
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
	return dst
}

func fetchAllAWSConnections(ctx context.Context, client *common.Client, id string, filters url.Values) ([]map[string]any, error) {
	var all []map[string]any
	skip := int64(0)
	for {
		f := cloneValues(filters)
		f.Set("skip", strconv.FormatInt(skip, 10))
		f.Set("limit", strconv.FormatInt(awsConnPageSize, 10))
		body, err := client.ListWithFilters(ctx, id, common.URL_AWS_CONNECTION, f)
		if err != nil {
			return nil, err
		}
		raw := gjson.Get(body, "resources").Raw
		if raw == "" || raw == "null" {
			break
		}
		var page []map[string]any
		if err := json.Unmarshal([]byte(raw), &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		totalResult := gjson.Get(body, "total")
		if totalResult.Exists() && skip+int64(len(page)) >= totalResult.Int() {
			break
		}
		skip += int64(len(page))
	}
	return all, nil
}

func fetchAllSCPConnections(ctx context.Context, client *common.Client, id string, filters url.Values) ([]map[string]any, error) {
	var all []map[string]any
	skip := int64(0)
	for {
		f := cloneValues(filters)
		f.Set("skip", strconv.FormatInt(skip, 10))
		f.Set("limit", strconv.FormatInt(scpConnPageSize, 10))
		body, err := client.ListWithFilters(ctx, id, common.URL_SCP_CONNECTION, f)
		if err != nil {
			return nil, err
		}
		raw := gjson.Get(body, "resources").Raw
		if raw == "" || raw == "null" {
			break
		}
		var page []map[string]any
		if err := json.Unmarshal([]byte(raw), &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		totalResult := gjson.Get(body, "total")
		if totalResult.Exists() && skip+int64(len(page)) >= totalResult.Int() {
			break
		}
		skip += int64(len(page))
	}
	return all, nil
}
