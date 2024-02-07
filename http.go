package go_01_edu_api

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func sendRequest(domain, path string, headers map[string]string, data []byte) (*http.Response, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 60 * time.Second,
	}

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

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	return resp, nil
}
