package zero

import (
	"fmt"
	"testing"
)

func Test(t *testing.T) {
	domain := "dev.01-edu.org"
	accessToken := "427faa391a0d73a68b69d4d3b65796fd798e9156"

	client := CreateClient(domain, accessToken)

	query := `query newUsers($latest: timestamptz!) {
		newUsers: user(where: { createdAt: { _gt: $latest } }) {
		  createdAt
		  login
		  email
		}
	}`
	
	variables := map[string]interface{}{"latest": "2023-01-01"}

	result, err := client.Run(query, variables)
	if err != nil {
		t.Errorf("run: %s", err)
	}

	fmt.Println(result)
	if client.storage.pendingToken != nil {
		fmt.Println(client.storage.pendingToken.base64)
	}
}
