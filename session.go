package gocloak_session

import (
	"context"
	"time"

	"github.com/Nerzal/gocloak/v7"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

type goCloakSession struct {
	clientID     string
	clientSecret string
	realm        string
	gocloak      gocloak.GoCloak
	token        *gocloak.JWT
	lastRequest  time.Time
}

func NewSession(clientId, clientSecret, realm, uri string) GoCloakSession {
	return &goCloakSession{
		clientID:     clientId,
		clientSecret: clientSecret,
		realm:        realm,
		gocloak:      gocloak.NewClient(uri),
	}
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

	if int(time.Since(session.lastRequest).Seconds()) > session.token.ExpiresIn {
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

	if int(time.Since(session.lastRequest).Seconds()) > session.token.RefreshExpiresIn {
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
