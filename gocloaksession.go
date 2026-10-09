package gocloaksession

import (
	"github.com/Nerzal/gocloak/v13"
	"github.com/go-resty/resty/v2"
	"google.golang.org/grpc"
)

// GoCloakSession manages a Keycloak client token and keeps it valid
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a valid JWT, refreshing the token or
	// re-authenticating if needed.
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// AddAuthTokenToRequest is a middleware for resty that sets the
	// Authorization header on the request.
	AddAuthTokenToRequest(client *resty.Client, request *resty.Request) error

	// GRPCUnaryAuthenticate is a unary client interceptor that sets the
	// Authorization header on gRPC requests.
	GRPCUnaryAuthenticate() grpc.UnaryClientInterceptor

	// GRPCStreamAuthenticate is a stream client interceptor that sets the
	// Authorization header on gRPC requests.
	GRPCStreamAuthenticate() grpc.StreamClientInterceptor

	// GetGoCloakInstance returns the currently used GoCloak instance.
	GetGoCloakInstance() *gocloak.GoCloak

	// ForceAuthenticate authenticates against Keycloak, even if the current token
	// is still valid.
	ForceAuthenticate() error

	// ForceRefresh refreshes the token, even if the current token is still valid.
	ForceRefresh() error
}
