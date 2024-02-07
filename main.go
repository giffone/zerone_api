package go_01_edu_api

import (
	"encoding/json"
	"fmt"
)

func CreateClient(domain, accessToken string) *Client {
	return &Client{
		domain:      domain,
		accessToken: accessToken,
	}
}

type Client struct {
	domain, accessToken string
	storage             storage
}

func (c *Client) Run(query string, variables map[string]interface{}) (map[string]interface{}, error) {
	// prepare graphql query
	form, err := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	// get jwt token
	if err := c.storage.getToken(c.domain, c.accessToken); err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	// make request
	headers := map[string]string{
		"Authorization":  "Bearer " + c.storage.pendingToken.base64,
		"Content-Type":   "application/json",
		"Content-Length": fmt.Sprint(len(form)),
	}

	resp, err := sendRequest(c.domain, "/api/graphql-engine/v1/graphql", headers, form)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}

	defer resp.Body.Close()

	var response map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}

	if errors, ok := response["errors"]; ok {
		return nil, fmt.Errorf("error: %s", errors.([]interface{})[0].(map[string]interface{})["message"])
	}

	return response["data"].(map[string]interface{}), nil
}
