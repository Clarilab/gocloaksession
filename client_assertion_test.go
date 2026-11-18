package gocloaksession_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Clarilab/gocloaksession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKeycloak is a token endpoint that accepts only the given assertion
// and/or secret, recording every request's form values.
type fakeKeycloak struct {
	acceptAssertion string
	acceptSecret    string

	mu       sync.Mutex
	requests []map[string]string
}

func (f *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/realms/test/protocol/openid-connect/token" || r.ParseForm() != nil {
		http.NotFound(w, r)

		return
	}

	form := map[string]string{}
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}

	if _, secret, ok := r.BasicAuth(); ok { // gocloak sends the secret via basic auth
		form["client_secret"] = secret
	}

	f.mu.Lock()
	f.requests = append(f.requests, form)
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	ok := (f.acceptAssertion != "" && form["client_assertion"] == f.acceptAssertion) ||
		(f.acceptSecret != "" && form["client_secret"] == f.acceptSecret)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		err := json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "Invalid client credentials"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		return
	}

	err := json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-" + form["client_assertion"] + form["client_secret"],
		"token_type":   "bearer",
		"expires_in":   300,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
}

func (f *fakeKeycloak) lastRequest(t *testing.T) map[string]string {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	require.NotEmpty(t, f.requests)

	return f.requests[len(f.requests)-1]
}

func writeAssertion(t *testing.T, path, content string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte(content+"\n"), 0o600))
}

func newAssertionSession(t *testing.T, kc *fakeKeycloak, secret, assertionPath string) gocloaksession.GoCloakSession {
	t.Helper()

	server := httptest.NewServer(kc)
	t.Cleanup(server.Close)

	session, err := gocloaksession.NewSession("prime_be", secret, "test", server.URL,
		gocloaksession.WithClientAssertionFile(assertionPath))
	require.NoError(t, err)

	return session
}

func Test_ClientAssertion_SendsFileContent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeAssertion(t, path, "jwt-1")

	kc := &fakeKeycloak{acceptAssertion: "jwt-1"}
	session := newAssertionSession(t, kc, "", path)

	token, err := session.GetKeycloakAuthToken()
	require.NoError(t, err)

	assert.Equal(t, "access-jwt-1", token.AccessToken)
	req := kc.lastRequest(t)
	assert.Equal(t, "client_credentials", req["grant_type"])
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", req["client_assertion_type"])
	assert.Equal(t, "jwt-1", req["client_assertion"], "trailing newline must be trimmed")
	assert.Empty(t, req["client_secret"])
}

func Test_ClientAssertion_RereadsFileOnEveryLogin(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeAssertion(t, path, "jwt-1")

	kc := &fakeKeycloak{acceptAssertion: "jwt-2"}
	session := newAssertionSession(t, kc, "", path)

	require.Error(t, session.ForceAuthenticate(), "jwt-1 is not accepted")

	writeAssertion(t, path, "jwt-2") // kubelet rotated the token
	require.NoError(t, session.ForceAuthenticate())
	assert.Equal(t, "jwt-2", kc.lastRequest(t)["client_assertion"])
}

func Test_ClientAssertion_FallsBackToSecretOnInvalidClient(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeAssertion(t, path, "jwt-1")

	kc := &fakeKeycloak{acceptSecret: "secret"}
	session := newAssertionSession(t, kc, "secret", path)

	token, err := session.GetKeycloakAuthToken()
	require.NoError(t, err)

	assert.Equal(t, "access-secret", token.AccessToken)
	assert.Len(t, kc.requests, 2, "assertion first, then secret")
	assert.Equal(t, "jwt-1", kc.requests[0]["client_assertion"])
}

func Test_ClientAssertion_NoFallbackWithoutSecret(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeAssertion(t, path, "jwt-1")

	kc := &fakeKeycloak{acceptSecret: "secret"}
	session := newAssertionSession(t, kc, "", path)

	_, err := session.GetKeycloakAuthToken()
	require.ErrorContains(t, err, "invalid_client")
	assert.Len(t, kc.requests, 1)
}

func Test_ClientAssertion_MissingFileFails(t *testing.T) {
	t.Parallel()

	kc := &fakeKeycloak{acceptSecret: "secret"}
	session := newAssertionSession(t, kc, "secret", filepath.Join(t.TempDir(), "missing"))

	_, err := session.GetKeycloakAuthToken()
	require.ErrorContains(t, err, "could not read client assertion")
	assert.Empty(t, kc.requests, "a missing file is a deployment error, not a reason to fall back")
}
