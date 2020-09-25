package gocloaksession

import (
	"github.com/Nerzal/gocloak/v7"
	"github.com/go-resty/resty/v2"
)

// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// AddAuthTokenToRequest sets the Authentication Header for the response
	AddAuthTokenToRequest(*resty.Client, *resty.Request) error

	// GetGoCloakInstance returns the currently used GoCloak instance.
	GetGoCloakInstance() *gocloak.GoCloak

	// ForceRefresh returns the currently used GoCloak instance.
	ForceRefresh() error
}
