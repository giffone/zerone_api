package zero

import (
	"fmt"
	"testing"
)

func Test(t *testing.T) {
	domain := "dev.01-edu.org"
	accessToken := "427faa391a0d73a68b69d4d3b65796fd798e9156"

	client, err := CreateClient(domain, accessToken)
	if err != nil {
		t.Fatalf("Create client: %s", err)
	}

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
		t.Fatalf("run: %s", err)
	}

	fmt.Println(string(result))
}
