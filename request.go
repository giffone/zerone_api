package zero

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"log"
)

type requestToken struct {
	debug  bool
	domain string
	cli    *http.Client
}

func newRequestToken(domain, accessToken string, debug bool) *requestToken {
	return &requestToken{
		debug:  debug,
		domain: domain,
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

	url := fmt.Sprintf("https://%s%s", rt.domain, path)

	if rt.debug {
		log.Printf(`
{
	"send request": {
		"url": "%s",
		"headers": "%v",
		"body": "%v"
	}
}`,
			url, headers, string(data))
	}

	req, err := http.NewRequest(method, url, body)
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
	path := fmt.Sprintf("/api/auth/token?token=%s", accessToken)

	resp, err := rt.sendRequest(path, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("sendRequest: %s", err)
	}

	return rt.read(resp)
}

func (rt *requestToken) refreshToken(base string) (*token, error) {
	path := "/api/auth/refresh"
	headers := map[string]string{"x-jwt-token": base}

	resp, err := rt.sendRequest(path, headers, nil)
	if err != nil {
		return nil, fmt.Errorf("sendRequest: %s", err)
	}

	return rt.read(resp)
}

func (rt *requestToken) read(resp *http.Response) (*token, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	strBody := string(body)
	bodyUnquoted := strings.ReplaceAll(strBody, "\"", "")

	if rt.debug {
		log.Printf(`
{
	"response body": {
		"body": "%s",
		"unquoted": "%s"
	}
}`,
			strBody, bodyUnquoted)
	}

	t := token{base64: bodyUnquoted}

	if err := t.decode(rt.debug); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return &t, nil
}

func isExpired(date int64) bool {
	diff := date - time.Now().Add(-100*time.Hour).Unix() // renew 100 hours before the deadline
	return diff <= 0
}
