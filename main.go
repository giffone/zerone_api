package zero

import (
	"encoding/json"
	"fmt"
	"sync"
)

func CreateClient(domain, accessToken string) (cli *Client, err error) {
	cli = &Client{
		request: NewRequestToken(domain, accessToken),
	}

	// get jwt token
	cli.storage.token, err = cli.request.getToken()
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	return
}

type Client struct {
	storage struct {
		mu    sync.RWMutex
		token *token
	}
	request *RequestToken
}

func (c *Client) Run(query string, variables map[string]interface{}) ([]byte, error) {
	// prepare graphql query
	form, err := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	c.storage.mu.RLock()
	expired := isExpired(c.storage.token.payload.Exp)
	base := c.storage.token.base64
	c.storage.mu.RUnlock()

	if expired {
		// check jwt token
		token, err := c.request.refreshToken(base)
		if err != nil {
			return nil, fmt.Errorf("refresh token: %w", err)
		}
		c.storage.mu.Lock()
		c.storage.token = token
		c.storage.mu.Unlock()
	}

	// make request
	headers := map[string]string{
		"Authorization":  "Bearer " + base,
		"Content-Type":   "application/json",
		"Content-Length": fmt.Sprint(len(form)),
	}

	resp, err := c.request.sendRequest(c.request.domain, "/api/graphql-engine/v1/graphql", headers, form)
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


