package gocloaksession

import (
	"github.com/Nerzal/gocloak/v13"
	"github.com/go-resty/resty/v2"
	"google.golang.org/grpc"
)

// GoCloakSession holds all callable methods
type GoCloakSession interface {
	// GetKeycloakAuthToken returns a JWT object, containing the AccessToken and more.
	GetKeycloakAuthToken() (*gocloak.JWT, error)

	// AddAuthTokenToRequest is a middleware for resty that sets the
	// Authorization header on the request.
	AddAuthTokenToRequest(*resty.Client, *resty.Request) error

	// GRPCUnaryAuthenticate is an unary client interceptor for setting the
	// Authorization Header on gRPC requests.
	GRPCUnaryAuthenticate() grpc.UnaryClientInterceptor

	// GRPCUnaryAuthenticate is a stream client interceptor for that setting the
	// Authorization Header on gRPC requests.
	GRPCStreamAuthenticate() grpc.StreamClientInterceptor

	// GetGoCloakInstance returns the currently used GoCloak instance.
	GetGoCloakInstance() *gocloak.GoCloak

	// ForceAuthenticate ignores all checks and executes an authentication.
	ForceAuthenticate() error

	// ForceRefresh ignores all checks and executes a refresh.
	ForceRefresh() error
}
