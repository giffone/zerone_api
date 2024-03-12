package zero

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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
		Exp    int64  `json:"exp"`
		Claims struct {
			XHasuraAllowedRoles []string `json:"x-hasura-allowed-roles"`
			XHasuraCampuses     string   `json:"x-hasura-campuses"`
			XHasuraDefaultRole  string   `json:"x-hasura-default-role"`
			XHasuraUserID       string   `json:"x-hasura-user-id"`
			XHasuraTokenID      string   `json:"x-hasura-token-id"`
		} `json:"https://hasura.io/jwt/claims"`
	}
	preNotify int64 // expire date minus n hours
}

func (t *token) decode(debug bool) error {
	parts := strings.Split(t.base64, ".")

	if debug {
		log.Printf(`
{
	"parts": {
		"length": %d,
		"list": "%v"
	}
}`,
			len(parts), parts)
	}

	if len(parts) <= 1 {
		return fmt.Errorf("the token length is incorrect")
	}

	// raw encoding witout padding
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if debug {
			log.Printf(`
{
	"RawURLEncoding": {
		"error": "%s",
	}
}`,
				err)
		}
		var err2 error
		// try standard encoding with padding
		payload, err2 = base64.StdEncoding.DecodeString(base64urlUnescape(parts[1], debug))
		if err2 != nil {
			return fmt.Errorf("decode: raw url: %w std: %w", err, err2)
		}
	}

	if debug {
		log.Printf(`
{
	"payload": %s
}`,
			string(payload))
	}

	// parse data
	err = json.Unmarshal(payload, &t.payload)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	t.preNotify = t.payload.Exp - 360000 // minus 100 hours for pre notify

	return nil
}

func base64urlUnescape(str string, debug bool) string {
	padding := 4 - (len(str) % 4)
	if padding == 4 {
		padding = 0
	}

	str += strings.Repeat("=", padding)

	str = strings.ReplaceAll(str, "-", "+")
	str = strings.ReplaceAll(str, "_", "/")

	if debug {
		log.Printf(`
{
"StdEncoding": "%s"
}`,
			str)
	}

	return str
}
