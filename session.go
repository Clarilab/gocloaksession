package main

import (
	"context"

	"github.com/Nerzal/gocloak/v7"
	"github.com/pkg/errors"
)

type GoCloakSession struct {
	clientID     string
	clientSecret string
	realm        string
	gocloak      gocloak.GoCloak
	token        *gocloak.JWT
}

func NewSession(clientId, clientSecret, realm, uri string) *GoCloakSession {
	return &GoCloakSession{
		clientID:     clientId,
		clientSecret: clientSecret,
		realm:        realm,
		gocloak:      gocloak.NewClient(uri),
	}
}

func (session *GoCloakSession) GetKeycloakAuthToken() (*gocloak.JWT, error) {
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

func (session *GoCloakSession) refreshToken() error {
	jwt, err := session.gocloak.RefreshToken(context.Background(), session.token.RefreshToken, session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not refresh keycloak-token")
	}

	session.token = jwt

	return nil
}

func (session *GoCloakSession) authenticate() error {
	jwt, err := session.gocloak.LoginClient(context.Background(), session.clientID, session.clientSecret, session.realm)
	if err != nil {
		return errors.Wrap(err, "could not login to keycloak")
	}

	session.token = jwt

	return nil
}
