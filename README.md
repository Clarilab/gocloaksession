# gocloak-session

This client is uses: [gocloak](https://github.com/Nerzal/gocloak) and [resty](https://github.com/go-resty/resty)

## Installation
```shell
go get github.com/clarilab/gocloak-session/v1
```

## Importing
```go
import "github.com/clarilab/gocloak/v1"
```

## Features
```go
// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// Sets the Authentication Header for the response
	AddAuthTokenToRequest(*resty.Client) error
}

```
See https://github.com/Nerzal/gocloak/blob/master/token.go for complete JWT struct.

# Example
```go
// Create a new session
session := NewSession(clientId, clientSecret, realm, uri)

// Authenticate or refresh the token
token, err := session.GetKeycloakAuthToken()

// Optionally, set the AuthToken for a resty.Client
err = session.AddAuthTokenToRequest(&restyClient)
```

## Developing & Testing
For local testing you need to start a docker container. Simply run following commands prior to starting the tests:

```shell
docker pull quay.io/keycloak/keycloak
docker run -d \
	-e KEYCLOAK_USER=admin \
	-e KEYCLOAK_PASSWORD=secret \
	-e KEYCLOAK_IMPORT=/tmp/gocloak-realm.json \
	-v "`pwd`/testdata/gocloak-realm.json:/tmp/gocloak-realm.json" \
	-p 8080:8080 \
	--name gocloak-test \
	quay.io/keycloak/keycloak:latest -Dkeycloak.profile.feature.upload_scripts=enabled

go test
```

To remove running docker container after completion of tests:

```shell
docker stop gocloak-test
docker rm gocloak-test
```