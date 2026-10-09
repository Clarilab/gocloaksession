package gocloaksession_test

import (
	"testing"

	"github.com/Clarilab/gocloaksession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	gocloakHostname     = "http://localhost:8080"
	gocloakRealm        = "gocloak"
	gocloakClientID     = "gocloak"
	gocloakClientSecret = "gocloak-secret"
)

func initializeSession(tb testing.TB) gocloaksession.GoCloakSession {
	tb.Helper()

	session, err := gocloaksession.NewSession(gocloakClientID, gocloakClientSecret, gocloakRealm, gocloakHostname)
	if err != nil {
		tb.Log(err)
		tb.FailNow()
	}

	return session
}

func Test_Integration_GetKeycloakAuthToken_Authentication(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	token, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "Login failed")
	assert.NotEmpty(t, token.AccessToken, "Token is not set")
}

func Test_Integration_GetKeycloakAuthToken_StillValid(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	_ = session.ForceAuthenticate()

	oldToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "failed to retrieve old token")
	require.NotNil(t, oldToken, "Token is not set")
	require.NotEmpty(t, oldToken.AccessToken, "AccessToken is not set")
	require.NotEmpty(t, oldToken.RefreshToken, "RefreshToken is not set")

	newToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "failed to retrieve new token")

	assert.Equal(t, oldToken.AccessToken, newToken.AccessToken, "New AccessToken given, but expecting the old is still valid")
}

func Test_Integration_GetKeycloakAuthToken_Refresh(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	_ = session.ForceAuthenticate()

	oldToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "Failed to retrieve token")

	require.NotNil(t, oldToken, "Token is not set")
	require.NotEmpty(t, oldToken.AccessToken, "Token is not set")
	require.NotEmpty(t, oldToken.RefreshToken, "Token is not set")

	oldToken.AccessToken = ""

	newToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "failed to retrieve token")

	assert.NotEqual(t, oldToken.AccessToken, newToken.AccessToken, "No new AccessToken given")
}

func Test_Integration_refreshToken(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	_ = session.ForceAuthenticate()

	oldToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "Failed to retrieve token")

	require.NotNil(t, oldToken, "Token is not set")
	require.NotEmpty(t, oldToken.AccessToken, "Token is not set")
	require.NotEmpty(t, oldToken.RefreshToken, "Token is not set")

	err = session.ForceRefresh()
	require.NoError(t, err, "Failed to refresh token")

	newToken, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "Failed to retrieve token")

	assert.NotEqual(t, oldToken.AccessToken, newToken.AccessToken, "No new AccessToken given")
}

func Test_Integration_authenticate(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	err := session.ForceAuthenticate()
	require.NoError(t, err, "authenticate failed")

	token, err := session.GetKeycloakAuthToken()
	require.NoError(t, err, "Failed to retrieve token")

	assert.NotEmpty(t, token.AccessToken, "Token is not set")
}

func Test_ForceRefresh_WithoutToken(t *testing.T) {
	t.Parallel()

	session := initializeSession(t)

	err := session.ForceRefresh()
	assert.Error(t, err, "expected an error when refreshing without a token")
}
