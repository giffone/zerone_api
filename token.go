package go_01_edu_api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type token struct {
	// encrypted
	base64 string
	// decrypted
	payload struct {
		Sub    string `json:"sub"`
		Iat    int64  `json:"iat"`
		IP     string `json:"ip"`
		Exp    int64  `json:"exp"` // expire
		Claims struct {
			XHasuraAllowedRoles []string `json:"x-hasura-allowed-roles"`
			XHasuraCampuses     string   `json:"x-hasura-campuses"`
			XHasuraDefaultRole  string   `json:"x-hasura-default-role"`
			XHasuraUserID       string   `json:"x-hasura-user-id"`
			XHasuraTokenID      string   `json:"x-hasura-token-id"`
		} `json:"https://hasura.io/jwt/claims"`
	}
}

func (t *token) decode() error {
	parts := strings.Split(t.base64, ".")

	if len(parts) <= 1 {
		return fmt.Errorf("the token length is incorrect")
	}

	payload, err := base64.RawURLEncoding.DecodeString(base64urlUnescape(parts[1]))
	if err != nil {
		return fmt.Errorf("base64: decode string: %w", err)
	}

	json.Unmarshal(payload, &t.payload)

	return nil
}

func base64urlUnescape(str string) string {
	padding := 4 - (len(str) % 4)
	if padding == 4 {
		padding = 0
	}
	str += strings.Repeat("=", padding)
	str = strings.ReplaceAll(str, "-", "+")
	str = strings.ReplaceAll(str, "_", "/")
	return str
}

type requestToken struct {
	domain, urlPath string
	headers         map[string]string
	data            []byte
}

func (rt *requestToken) do() (*token, error) {
	resp, err := sendRequest(rt.domain, rt.urlPath, rt.headers, rt.data)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}

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
