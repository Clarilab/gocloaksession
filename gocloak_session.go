package gocloak_session

import (
	"github.com/Nerzal/gocloak/v7"
	"github.com/go-resty/resty/v2"
)

// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// Sets the Authentication Header for the response
	AddAuthTokenToRequest(*resty.Client, *resty.Request) error
}
