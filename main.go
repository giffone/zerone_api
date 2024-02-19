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

func (c *Client) Run(query string, variables map[string]interface{}) ([]byte, error) {
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

	var response struct {
		Errors []struct {
			Message string `json:"message,omitempty"`
		} `json:"errors,omitempty"`
		Data json.RawMessage `json:"data,omitempty"`
	}

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}

	if len(response.Errors) > 0 && response.Errors[0].Message != "" {
		return nil, fmt.Errorf("graphql: %s", response.Errors[0].Message)
	}

	return response.Data, nil
}


