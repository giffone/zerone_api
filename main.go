package zero

import (
	"encoding/json"
	"fmt"
	"sync"
)

type Client interface {
	Run(query string, variables map[string]interface{}) ([]byte, error)
}

func CreateClient(domain, accessToken string) (Client, error) {
	var err error

	c := client{
		request: newRequestToken(domain, accessToken),
	}

	// get new jwt token
	c.storage.token, err = c.request.getNewToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	return &c, nil
}

type client struct {
	storage struct {
		mu    sync.RWMutex
		token *token
	}
	request *requestToken
}

// Run makes query request
func (c *client) Run(query string, variables map[string]interface{}) ([]byte, error) {
	// prepare graphql query
	form, err := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	// check if token is expired
	c.storage.mu.RLock()
	expired := isExpired(c.storage.token.payload.Exp)
	base := c.storage.token.base64
	c.storage.mu.RUnlock()

	if expired {
		// get refreshed jwt token
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

	resp, err := c.request.sendRequest("/api/graphql-engine/v1/graphql", headers, form)
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


