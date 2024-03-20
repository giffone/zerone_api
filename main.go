package zero

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Client interface {
	Run(query string, variables map[string]interface{}) ([]byte, error)
	TokenBase() (int64, string, error)
}

func CreateClient(domain, accessToken string, debug bool) (Client, error) {
	debugging = debug
	logDebug(msgArgs, domain, accessToken)

	var err error

	c := client{request: newRequestToken(domain)}

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

// TokenBase return encrypted token
func (c *client) TokenBase() (int64, string, error) {
	return c.check()
}

// Run makes query request
func (c *client) Run(query string, variables map[string]interface{}) ([]byte, error) {
	// prepare graphql query
	form, err := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	if err != nil {
		return nil, errDebug(errMashalQuery, query, variables, err)
	}

	// check if token is expired
	_, base, err := c.check()
	if err != nil {
		return nil, err
	}

	// make request
	headers := map[string]string{
		"Authorization":  "Bearer " + base,
		"Content-Type":   "application/json",
		"Content-Length": fmt.Sprint(len(form)),
	}

	path := "/api/graphql-engine/v1/graphql"

	resp, err := c.request.sendRequest(path, headers, form)
	if err != nil {
		return nil, errDebug(errSendReq, path, headers, form, err)
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
		return nil, errDebug(errRespDecodeBody, path, headers, form, err)
	}

	// if graphql returned an error
	if len(response.Errors) > 0 && response.Errors[0].Message != "" {
		msg := response.Errors[0].Message
		return nil, errDebug(errRespGraphqlErr, path, headers, form, msg)
	}

	return response.Data, nil
}

func (c *client) check() (int64, string, error) {
	c.storage.mu.RLock()
	expireDate := c.storage.token.preNotify
	base := c.storage.token.base64
	c.storage.mu.RUnlock()

	if isExpired(expireDate) {
		// get refreshed jwt token
		token, err := c.request.refreshToken(base)
		if err != nil {
			ed := time.Unix(expireDate, 0).Format("2006-01-02 15:04:05 MST")
			return expireDate, base, errDebug(errRefreshToken, ed, base, err)
		}
		// refresh
		c.storage.mu.Lock()
		c.storage.token = token
		base = c.storage.token.base64
		expireDate = c.storage.token.preNotify
		c.storage.mu.Unlock()
	}
	return expireDate, base, nil
}
