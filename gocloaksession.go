package gocloaksession

import (
	"github.com/Nerzal/gocloak/v13"
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

	// ForceAuthenticate ignores all checks and executes an authentication.
	ForceAuthenticate() error

	// ForceRefresh ignores all checks and executes a refresh.
	ForceRefresh() error
}
