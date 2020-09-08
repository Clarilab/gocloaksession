package gocloak_session

import "github.com/Nerzal/gocloak/v7"

// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more
	GetKeycloakAuthToken() (*gocloak.JWT, error)
}
