# gocloaksession

This client uses: [gocloak](https://github.com/Nerzal/gocloak) and [resty](https://github.com/go-resty/resty)

## Installation
```shell
go get github.com/Clarilab/gocloaksession
```

## Importing
```go
import "github.com/Clarilab/gocloaksession"
```

## Features
```go
// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// Sets the Authentication Header for the response
	// Can be used as Middleware in resty
	AddAuthTokenToRequest(*resty.Client, *resty.Request) error

	// GetGoCloakInstance returns the currently used GoCloak instance.
	GetGoCloakInstance() gocloak.GoCloak

	// ForceAuthenticate ignores all checks and executes an authentication.
	ForceAuthenticate() error

	// ForceRefresh ignores all checks and executes a refresh.
	ForceRefresh() error
}

```
See https://github.com/Nerzal/gocloak/blob/master/token.go for complete JWT struct.

## Example
```go
// Create a new session
session := NewSession(clientId, clientSecret, realm, uri)

// Authenticate or refresh the token
token, err := session.GetKeycloakAuthToken()
```

If you want to use it as middleware in resty, you can use the following example
```go
session := NewSession(clientId, clientSecret, realm, uri)

restyClient.OnBeforeRequest(session.AddAuthTokenToRequest)
```

In case you need the GoCloak instance to execute your own commands.
```go
gocloakInstance := session.GetGoCloakInstance()
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