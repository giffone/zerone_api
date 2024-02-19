package zero

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type RequestToken struct {
	domain, accessToken string
	cli                 *http.Client
}

func NewRequestToken(domain, accessToken string) *RequestToken {
	return &RequestToken{
		domain:      domain,
		accessToken: accessToken,
		cli: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 60 * time.Second,
		},
	}
}

func (rt *RequestToken) sendRequest(domain, path string, headers map[string]string, data []byte) (*http.Response, error) {
	method := "GET"
	if data != nil {
		method = "POST"
	}

	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", domain, path), bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := rt.cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	return resp, nil
}

func (rt *RequestToken) getToken() (*token, error) {
	resp, err := rt.sendRequest(
		rt.domain,
		fmt.Sprintf("/api/auth/token?token=%s", rt.accessToken),
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("do: %s", err)
	}

	return read(resp)
}

func (rt *RequestToken) refreshToken(base string) (*token, error) {
	resp, err := rt.sendRequest(
		rt.domain,
		"/api/auth/refresh",
		map[string]string{"x-jwt-token": base},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("do: %s", err)
	}

	return read(resp)
}

func read(resp *http.Response) (*token, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	t := token{base64: strings.ReplaceAll(string(body), "\"", "")}

	if err := t.decode(); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return &t, nil
}

func unmrshl(resp *http.Response) (map[string]interface{}, error) {
	defer resp.Body.Close()

	var response map[string]interface{}

	err := json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}

	if errors, ok := response["errors"]; ok {
		return nil, fmt.Errorf("error: %s", errors.([]interface{})[0].(map[string]interface{})["message"])
	}

	return response["data"].(map[string]interface{}), nil
}

func isExpired(date int64) bool {
	diff := date - time.Now().Add(-100*time.Hour).Unix()/1000 // renew 100 hours before the deadline
	return diff <= 0
}
