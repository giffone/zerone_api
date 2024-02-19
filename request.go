package zero

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type requestToken struct {
	domain string
	cli    *http.Client
}

func newRequestToken(domain, accessToken string) *requestToken {
	return &requestToken{
		domain:      domain,
		cli: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 60 * time.Second,
		},
	}
}

func (rt *requestToken) sendRequest(path string, headers map[string]string, data []byte) (*http.Response, error) {
	method := "GET"
	if data != nil {
		method = "POST"
	}

	var body io.Reader

	if data != nil {
		body = bytes.NewBuffer(data)
	} else {
		body = nil
	}

	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", rt.domain, path), body)
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

func (rt *requestToken) getNewToken(accessToken string) (*token, error) {
	resp, err := rt.sendRequest(
		fmt.Sprintf("/api/auth/token?token=%s", accessToken),
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("sendRequest: %s", err)
	}

	return read(resp)
}

func (rt *requestToken) refreshToken(base string) (*token, error) {
	resp, err := rt.sendRequest(
		"/api/auth/refresh",
		map[string]string{"x-jwt-token": base},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("sendRequest: %s", err)
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

func isExpired(date int64) bool {
	diff := date - time.Now().Add(-100*time.Hour).Unix()/1000 // renew 100 hours before the deadline
	return diff <= 0
}
