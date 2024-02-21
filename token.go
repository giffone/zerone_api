package zero

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func (t *token) decode(debug bool) error {
	parts := strings.Split(t.base64, ".")

	if len(parts) <= 1 {
		if debug {
			return fmt.Errorf("the token length is incorrect: %v", parts)
		}
		return fmt.Errorf("the token length is incorrect")
	}

	unesc := base64urlUnescape(parts[1])

	payload, err := base64.RawURLEncoding.DecodeString(unesc)
	if err != nil {
		if debug {
			return fmt.Errorf("base64: decode string: part [1]:%s\n unescape [add '='; '-'->'+'; '_'->'/']:%s\nerror: %w", parts[1], unesc, err)
		}
		return fmt.Errorf("base64: decode string: %w", err)
	}

	err = json.Unmarshal(payload, &t.payload)
	if err != nil {
		if debug {
			return fmt.Errorf("unmarshal: payload:%s\nerror %w", string(payload), err)
		}
		return fmt.Errorf("unmarshal: %w", err)
	}

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
