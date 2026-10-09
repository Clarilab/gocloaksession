package gocloaksession

import (
	"context"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	headerAuthorization = "Authorization"
)

// FunctionalOption configures a Session
type FunctionalOption func(*goCloakSession) error

// RequestSkipper is a function signature that can be used to skip a certain
// request if needed.
type RequestSkipper func(*resty.Request) bool

// SubstringRequestSkipper is a RequestSkipper that skips a request when the
// URL of the request contains the given substring
func SubstringRequestSkipper(subStr string) RequestSkipper {
	return func(r *resty.Request) bool {
		return strings.Contains(r.URL, subStr)
	}
}

// RequestSkipperCallOption appends a RequestSkipper to the skipConditions
func RequestSkipperCallOption(requestSkipper RequestSkipper) FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.skipConditions = append(gcs.skipConditions, requestSkipper)

		return nil
	}
}

// PrematureRefreshThresholdOption sets how long before their expiry the access
// and refresh tokens are considered expired and get renewed
func PrematureRefreshThresholdOption(accessToken, refreshToken time.Duration) FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.prematureRefreshTokenRefreshThreshold = int(refreshToken.Seconds())
		gcs.prematureAccessTokenRefreshThreshold = int(accessToken.Seconds())

		return nil
	}
}

// WithWildFlySupport initializes gocloak client with legacy wildfly support.
func WithWildFlySupport(uri string) FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.gocloak = gocloak.NewClient(uri, gocloak.SetLegacyWildFlySupport())

		return nil
	}
}

// SetGocloak manually sets the GoCloak client.
func SetGocloak(gc *gocloak.GoCloak) FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.gocloak = gc

		return nil
	}
}

// SetSkipRefreshToken configures the session to never use the refresh token
// and always re-authenticate once the access token has expired.
func SetSkipRefreshToken() FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.skipRefresh = true

		return nil
	}
}

// WithScopes sets the scopes requested when logging in the client.
func WithScopes(scopes ...string) FunctionalOption {
	return func(gcs *goCloakSession) error {
		gcs.scopes = scopes

		return nil
	}
}

type goCloakSession struct {
	clientID                              string
	clientSecret                          string
	realm                                 string
	gocloak                               *gocloak.GoCloak
	token                                 *gocloak.JWT
	lastRequest                           *time.Time
	skipConditions                        []RequestSkipper
	prematureRefreshTokenRefreshThreshold int
	prematureAccessTokenRefreshThreshold  int
	skipRefresh                           bool
	scopes                                []string
}

// NewSession returns a new GoCloakSession for the given client credentials,
// realm and Keycloak URI
func NewSession(clientID, clientSecret, realm, uri string, option ...FunctionalOption) (GoCloakSession, error) {
	session := &goCloakSession{
		clientID:                              clientID,
		clientSecret:                          clientSecret,
		realm:                                 realm,
		gocloak:                               gocloak.NewClient(uri),
		prematureAccessTokenRefreshThreshold:  0,
		prematureRefreshTokenRefreshThreshold: 0,
	}

	for _, option := range option {
		err := option(session)
		if err != nil {
			return nil, errors.Wrap(err, "error while applying option")
		}
	}

	return session, nil
}

func (s *goCloakSession) ForceAuthenticate() error {
	return s.authenticate()
}

func (s *goCloakSession) ForceRefresh() error {
	return s.refreshToken()
}

func (s *goCloakSession) GetKeycloakAuthToken() (*gocloak.JWT, error) {
	if s.isAccessTokenValid() {
		return s.token, nil
	}

	if !s.skipRefresh && s.isRefreshTokenValid() {
		err := s.refreshToken()
		if err == nil {
			return s.token, nil
		}
	}

	err := s.authenticate()
	if err != nil {
		return nil, err
	}

	return s.token, nil
}

func (s *goCloakSession) AddAuthTokenToRequest(_ *resty.Client, request *resty.Request) error {
	for _, shouldSkip := range s.skipConditions {
		if shouldSkip(request) {
			return nil
		}
	}

	token, err := s.GetKeycloakAuthToken()
	if err != nil {
		return err
	}

	tokenType := parseTokenType(token)

	request.Header.Set(headerAuthorization, tokenType+" "+token.AccessToken)

	return nil
}

func (s *goCloakSession) GRPCUnaryAuthenticate() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		token, err := s.GetKeycloakAuthToken()
		if err != nil {
			return err
		}

		tokenType := parseTokenType(token)

		ctx = metadata.AppendToOutgoingContext(ctx, headerAuthorization, tokenType+" "+token.AccessToken)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (s *goCloakSession) GRPCStreamAuthenticate() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		token, err := s.GetKeycloakAuthToken()
		if err != nil {
			return nil, err
		}

		tokenType := parseTokenType(token)

		ctx = metadata.AppendToOutgoingContext(ctx, headerAuthorization, tokenType+" "+token.AccessToken)

		return streamer(ctx, desc, cc, method, opts...)
	}
}

// GetGoCloakInstance returns the underlying GoCloak client.
func (s *goCloakSession) GetGoCloakInstance() *gocloak.GoCloak {
	return s.gocloak
}

func (s *goCloakSession) isAccessTokenValid() bool {
	if s.token == nil {
		return false
	}

	if s.lastRequest.IsZero() {
		return false
	}

	sessionExpiry := s.token.ExpiresIn - s.prematureAccessTokenRefreshThreshold
	if int(time.Since(*s.lastRequest).Seconds()) > sessionExpiry {
		return false
	}

	token, _, err := s.gocloak.DecodeAccessToken(context.Background(), s.token.AccessToken, s.realm)

	return err == nil && token.Valid
}

func (s *goCloakSession) isRefreshTokenValid() bool {
	if s.token == nil {
		return false
	}

	if s.lastRequest.IsZero() {
		return false
	}

	sessionExpiry := s.token.RefreshExpiresIn - s.prematureRefreshTokenRefreshThreshold

	return int(time.Since(*s.lastRequest).Seconds()) <= sessionExpiry
}

func (s *goCloakSession) refreshToken() error {
	if s.token == nil {
		return errors.New("could not refresh keycloak-token: no token to refresh")
	}

	now := time.Now()
	s.lastRequest = &now

	jwt, err := s.gocloak.RefreshToken(context.Background(), s.token.RefreshToken, s.clientID, s.clientSecret, s.realm)
	if err != nil {
		return errors.Wrap(err, "could not refresh keycloak-token")
	}

	s.token = jwt

	return nil
}

func (s *goCloakSession) authenticate() error {
	now := time.Now()
	s.lastRequest = &now

	jwt, err := s.gocloak.LoginClient(context.Background(), s.clientID, s.clientSecret, s.realm, s.scopes...)
	if err != nil {
		return errors.Wrap(err, "could not login to keycloak")
	}

	s.token = jwt

	return nil
}

// parseTokenType either correct lowercase Bearer token type, or returns current value.
func parseTokenType(token *gocloak.JWT) string {
	switch token.TokenType {
	case "bearer":
		return "Bearer"
	default:
		return token.TokenType
	}
}
