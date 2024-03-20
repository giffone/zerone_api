package zero

import (
	"errors"
	"fmt"
	"log"
)

var debugging = false

const (
	msgSendReq = `
{
	"send request": {
		"url": "%s",
		"headers": "%v",
		"body": "%v"
	}
}`

	msgArgs = `
{
	"domain": "%s",
	"accessToken": "%s"
}`

	msgRespBody = `
{
	"response body": {
		"body": "%s",
		"unquoted": "%s"
	}
}`

	msgTokenParts = `
{
	"parts": {
		"length": %d,
		"list": "%v"
	}
}`

	msgRawURLEncErr = `
{
	"RawURLEncoding": {
		"error": "%s"
	}
}`

	msgStdEnc = `
{
	"StdEncoding": "%s"
}`

	msgTokenPayload = `
{
	"payload": %s
}`
)

var (
	errMashalQuery = [2]string{`
{
	"marshal":{
		"query": %s,
		"variables":%v,
		"error": %w
	}
}`, "marshal: %w"}

	errSendReq = [2]string{`
{
	"sendRequest": {
		"path": %s,
		"headers": %v,
		"body": %v,
		"error": %s
	}
}`, "sendRequest: %w"}

	errRespDecodeBody = [2]string{`
{
	"response": {
		"decode body": {
			"path": %s,
			"headers": %v,
			"body": %v,
			"error": %s
			}
		}
	}`, "response: decode body: %w"}

	errRespGraphqlErr = [2]string{`
{
	"response": {
		"graphql": {
			"path": %s,
			"headers": %v,
			"body": %v,
			"error": %s
			}
		}
	}`, "response: graphql: %s"}

	errRefreshToken = [2]string{`
{
	"refresh token": {
		"exp date": %s,
		"base": %v,
		"error": %s
		}
	}`, "refresh token: %w"}
)

func logDebug(message string, v ...any) {
	if debugging {
		log.Printf(message, v...)
	}
}

func errDebug(message [2]string, v ...any) error {
	if debugging {
		return fmt.Errorf(message[0], v...)
	}
	if len(v) > 0 {
		return fmt.Errorf(message[1], v[len(v)-1])
	}
	return errors.New(message[1])
}
