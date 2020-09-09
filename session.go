package gocloak_session

import (
	"context"

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
	if session.token != nil {
		token, _, err := session.gocloak.DecodeAccessToken(context.Background(), session.token.AccessToken, session.realm, "")
		if err == nil && token.Valid {
			return session.token, nil
		}

		err = session.refreshToken()
		if err != nil {
			err = session.authenticate()
			if err != nil {
				return nil, err
			}
		}
	} else {
		err := session.authenticate()
		if err != nil {
			return nil, err
		}
	}

	return session.token, nil
}

func (session *goCloakSession) refreshToken() error {
	jwt, err := session.gocloak.RefreshToken(context.Background(), session.token.RefreshToken, session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not refresh keycloak-token")
	}

	session.token = jwt

	return nil
}

func (session *goCloakSession) authenticate() error {
	jwt, err := session.gocloak.LoginClient(context.Background(), session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not login to keycloak")
	}

	session.token = jwt

	return nil
}

func (session *goCloakSession) AddAuthTokenToRequest(client *resty.Client) error {
	if session.token == nil || session.token.AccessToken == "" {
		return errors.New("The session does not contain an AccessToken")
	}

	if session.token.TokenType != "bearer" {
		client.SetAuthScheme(session.token.TokenType)
	}
	client.SetAuthToken(session.token.AccessToken)

	return nil
}
