# 01-edu-api library in golang

01-edu-api library that gives read-only access using graphql queries to 01 edu database

To get an accessToken you need to log in as an administrator on the gitea platform and in **Settings** - **Applications** - **Manage Access Tokens** and generate the token:

```go
domain := "dev.01-edu.org"
accessToken := "c45cd0ba337548gh24c5a76b0f63d6d1ed4fh784g84"
```

### Example

```go
domain := "dev.01-edu.org"
accessToken := "c45cd0ba337548gh24c5a76b0f63d6d1ed4fh784g84"

client := CreateClient(domain, accessToken)

// example graphql query
query := `query newUsers($latest: timestamptz!) {
    newUsers: user(where: { createdAt: { _gt: $latest } }) {
        createdAt
        login
        email
    }
}`

// varialbles for query
variables := map[string]interface{}{"latest": "2023-01-01"}

result, err := client.Run(query, variables)
if err != nil {
    fmt.Errorf("run: %s", err)
}
```