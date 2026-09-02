package server

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"log/slog"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Issuer:            "https://identity.example.test",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		Identity: IdentityConfig{
			UserHeader:   "X-NetBird-User",
			GroupsHeader: "X-NetBird-Groups",
			Mappings: map[string]IdentityEntry{
				"alice@example.test": {Subject: "authentik-alice", Email: "alice@example.test", Name: "Alice", PreferredUsername: "alice", Groups: []string{"engineering"}},
			},
		},
		Clients:    map[string]Client{"client": {Secret: "secret", RedirectURIs: []string{"https://app.example.test/callback"}}},
		SessionTTL: 3600,
		CodeTTL:    60,
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(config, key, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestIdentityFromRequestRequiresTrustedPeer(t *testing.T) {
	server := testServer(t)

	request := httptest.NewRequest(http.MethodGet, "https://identity.example.test", nil)
	request.RemoteAddr = "10.20.30.40:1234"
	request.Header.Set("X-NetBird-User", "alice@example.test")
	request.Header.Set("X-NetBird-Groups", "engineering, platform")
	identity, ok := server.identityFromRequest(request)
	if !ok || identity.Subject != "authentik-alice" || identity.Groups[0] != "engineering" {
		t.Fatalf("unexpected trusted identity: %#v, %v", identity, ok)
	}

	request.RemoteAddr = "192.0.2.10:1234"
	if _, ok := server.identityFromRequest(request); ok {
		t.Fatal("untrusted peer was allowed to supply an identity")
	}
}

func TestIdentityFromRequestRejectsUnknownMappingByDefault(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "https://identity.example.test", nil)
	request.RemoteAddr = "10.20.30.40:1234"
	request.Header.Set("X-NetBird-User", "unknown@example.test")
	if _, ok := server.identityFromRequest(request); ok {
		t.Fatal("unknown identity was accepted")
	}
}

func TestAuthorizeAndTokenAreOneTime(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "https://identity.example.test/oauth2/authorize?client_id=client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&response_type=code&state=state&nonce=nonce", nil)
	request.RemoteAddr = "10.20.30.40:1234"
	request.Header.Set("X-NetBird-User", "alice@example.test")

	response := httptest.NewRecorder()
	server.authorize(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("authorize returned %d: %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" || location.Query().Get("state") != "state" {
		t.Fatalf("unexpected authorization redirect: %s", location)
	}

	tokenRequest := httptest.NewRequest(http.MethodPost, "https://identity.example.test/oauth2/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"client"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.test/callback"},
	}.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	server.token(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK || !strings.Contains(tokenResponse.Body.String(), "access_token") {
		t.Fatalf("token exchange failed: %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}

	replayResponse := httptest.NewRecorder()
	server.token(replayResponse, tokenRequest)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("authorization code was reusable: %d", replayResponse.Code)
	}
}

func TestPKCE(t *testing.T) {
	code := authorizationCode{CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256"}
	if !verifyPKCE(code, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") {
		t.Fatal("valid PKCE verifier was rejected")
	}
	if verifyPKCE(code, "wrong-verifier") {
		t.Fatal("invalid PKCE verifier was accepted")
	}
}

func TestAuthorizeRejectsUnmappedTrustedIdentity(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "https://identity.example.test/oauth2/authorize?client_id=client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&response_type=code", nil)
	request.RemoteAddr = "10.20.30.40:1234"
	request.Header.Set("X-NetBird-User", "unknown@example.test")
	response := httptest.NewRecorder()
	server.authorize(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unmapped identity returned %d", response.Code)
	}
}

func TestJWKSAndDiscovery(t *testing.T) {
	server := testServer(t)
	handler := server.Handler()

	for _, path := range []string{"/.well-known/openid-configuration", "/oauth2/jwks.json", "/healthz"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, response.Code)
		}
	}
}
