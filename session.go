package gocloaksession

import (
	"context"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v9"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

// CallOption configures a Session
type CallOption func(*goCloakSession) error

// RequestSkipper is a function signature that can be used to skip a certain
// request if needed.
type RequestSkipper func(*resty.Request) bool

// SubstringRequestSkipper is a RequestSkipper that skips a request when the
// url in the request contains a certain substring
func SubstringRequestSkipper(substr string) RequestSkipper {
	return func(r *resty.Request) bool {
		return strings.Contains(r.URL, substr)
	}
}

// RequestSkipperCallOption appends a RequestSkipper to the skipConditions
func RequestSkipperCallOption(requestSkipper RequestSkipper) CallOption {
	return func(gcs *goCloakSession) error {
		gcs.skipConditions = append(gcs.skipConditions, requestSkipper)
		return nil
	}
}

// PrematureRefreshThresholdOption sets the threshold for a premature token
// refresh
func PrematureRefreshThresholdOption(accessToken, refreshToken time.Duration) CallOption {
	return func(gcs *goCloakSession) error {
		gcs.prematureRefreshTokenRefreshThreshold = int(refreshToken.Seconds())
		gcs.prematureAccessTokenRefreshThreshold = int(accessToken.Seconds())
		return nil
	}
}

type goCloakSession struct {
	clientID                              string
	clientSecret                          string
	realm                                 string
	gocloak                               gocloak.GoCloak
	token                                 *gocloak.JWT
	lastRequest                           time.Time
	skipConditions                        []RequestSkipper
	prematureRefreshTokenRefreshThreshold int
	prematureAccessTokenRefreshThreshold  int
}

// NewSession returns a new instance of a gocloak Session
func NewSession(clientID, clientSecret, realm, uri string, calloptions ...CallOption) (GoCloakSession, error) {
	session := &goCloakSession{
		clientID:                              clientID,
		clientSecret:                          clientSecret,
		realm:                                 realm,
		gocloak:                               gocloak.NewClient(uri),
		prematureAccessTokenRefreshThreshold:  0,
		prematureRefreshTokenRefreshThreshold: 0,
	}

	for _, option := range calloptions {
		err := option(session)
		if err != nil {
			return nil, errors.Wrap(err, "error while applying option")
		}
	}

	return session, nil
}

func (session *goCloakSession) ForceAuthenticate() error {
	return session.authenticate()
}

func (session *goCloakSession) ForceRefresh() error {
	return session.refreshToken()
}

func (session *goCloakSession) GetKeycloakAuthToken() (*gocloak.JWT, error) {
	if session.isAccessTokenValid() {
		return session.token, nil
	}

	if session.isRefreshTokenValid() {
		err := session.refreshToken()
		if err == nil {
			return session.token, nil
		}
	}

	err := session.authenticate()
	if err != nil {
		return nil, err
	}

	return session.token, nil
}

func (session *goCloakSession) isAccessTokenValid() bool {
	if session.token == nil {
		return false
	}

	if session.lastRequest.IsZero() {
		return false
	}

	sessionExpiry := session.token.ExpiresIn - session.prematureAccessTokenRefreshThreshold
	if int(time.Since(session.lastRequest).Seconds()) > sessionExpiry {
		return false
	}

	token, _, err := session.gocloak.DecodeAccessToken(context.Background(), session.token.AccessToken, session.realm, "")
	return err == nil && token.Valid
}

func (session *goCloakSession) isRefreshTokenValid() bool {
	if session.token == nil {
		return false
	}

	if session.lastRequest.IsZero() {
		return false
	}

	sessionExpiry := session.token.RefreshExpiresIn - session.prematureRefreshTokenRefreshThreshold
	if int(time.Since(session.lastRequest).Seconds()) > sessionExpiry {
		return false
	}

	return true
}

func (session *goCloakSession) refreshToken() error {
	session.lastRequest = time.Now()

	jwt, err := session.gocloak.RefreshToken(context.Background(), session.token.RefreshToken, session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not refresh keycloak-token")
	}

	session.token = jwt

	return nil
}

func (session *goCloakSession) authenticate() error {
	session.lastRequest = time.Now()

	jwt, err := session.gocloak.LoginClient(context.Background(), session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not login to keycloak")
	}

	session.token = jwt

	return nil
}

func (session *goCloakSession) AddAuthTokenToRequest(client *resty.Client, request *resty.Request) error {
	for _, shouldSkip := range session.skipConditions {
		if shouldSkip(request) {
			return nil
		}
	}

	token, err := session.GetKeycloakAuthToken()
	if err != nil {
		return err
	}

	if token.TokenType != "bearer" {
		request.SetAuthScheme(token.TokenType)
	}
	request.SetAuthToken(token.AccessToken)

	return nil
}

func (session *goCloakSession) GetGoCloakInstance() *gocloak.GoCloak {
	return &session.gocloak
}
