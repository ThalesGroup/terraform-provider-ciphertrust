package common

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

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
	return ret, nil
}
