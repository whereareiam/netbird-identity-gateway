package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func testServer(t *testing.T) *Server {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Issuer: "https://identity.example.test", TrustedProxyCIDRs: []string{"10.1.2.3/32"}, Principals: []string{"account:user"}, Client: Client{ID: "authentik", Secret: strings.Repeat("s", 32), RedirectURI: "https://auth.example.test/source/oauth/callback/netbird/"}, SigningKey: "/test/key", CodeTTL: 60, TokenTTL: 60, MaxCodes: 8}
	s, e := NewServer(c, k, nil)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func authQuery(s *Server) url.Values {
	h := sha256.Sum256([]byte(testVerifier))
	return url.Values{"client_id": {s.config.Client.ID}, "redirect_uri": {s.config.Client.RedirectURI}, "response_type": {"code"}, "scope": {"openid"}, "state": {"browser-state"}, "nonce": {"browser-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "code_challenge_method": {"S256"}}
}
func authorizeRequest(s *Server, q url.Values, peer string, headers []string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://identity.example.test/oauth2/authorize?"+q.Encode(), nil)
	r.RemoteAddr = peer
	for _, h := range headers {
		r.Header.Add(principalHeader, h)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func issue(t *testing.T, s *Server) string {
	t.Helper()
	w := authorizeRequest(s, authQuery(s), "10.1.2.3:80", []string{"account:user"})
	if w.Code != 302 {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("state") != "browser-state" {
		t.Fatal("state lost")
	}
	return u.Query().Get("code")
}
func exchange(s *Server, code, verifier string) *httptest.ResponseRecorder {
	q := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.config.Client.RedirectURI}, "code_verifier": {verifier}}
	r := httptest.NewRequest("POST", "http://backchannel/oauth2/token", strings.NewReader(q.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(s.config.Client.ID, s.config.Client.Secret)
	w := httptest.NewRecorder()
	s.BackchannelHandler().ServeHTTP(w, r)
	return w
}
func TestIdentityOnlyRoundTrip(t *testing.T) {
	s := testServer(t)
	code := issue(t, s)
	w := exchange(s, code, testVerifier)
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	var tokens map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &tokens); e != nil {
		t.Fatal(e)
	}
	o, e := jose.ParseSigned(tokens["id_token"].(string), []jose.SignatureAlgorithm{jose.RS256})
	if e != nil {
		t.Fatal(e)
	}
	payload, e := o.Verify(s.publicKey)
	if e != nil {
		t.Fatal(e)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["sub"] != "netbird:account:user" || claims["aud"] != "authentik" || claims["iss"] != s.config.Issuer || claims["nonce"] != "browser-nonce" {
		t.Fatalf("wrong claims: %v", claims)
	}
	for _, k := range []string{"groups", "email", "name", "entitlements", "forgejo_role"} {
		if _, ok := claims[k]; ok {
			t.Fatalf("unexpected claim %s", k)
		}
	}
	for _, test := range []struct {
		token  string
		status int
	}{{tokens["access_token"].(string), 200}, {tokens["id_token"].(string), 401}, {"invalid", 401}} {
		r := httptest.NewRequest("GET", "http://backchannel/oauth2/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		s.BackchannelHandler().ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("userinfo: %d", w.Code)
		}
		if w.Code == 200 && strings.TrimSpace(w.Body.String()) != `{"sub":"netbird:account:user"}` {
			t.Fatal(w.Body.String())
		}
	}
	if w := exchange(s, code, testVerifier); w.Code != 400 {
		t.Fatal("replayed code accepted")
	}
}
func TestPrincipalBoundary(t *testing.T) {
	s := testServer(t)
	for _, x := range []struct {
		peer    string
		headers []string
	}{{"192.0.2.1:80", []string{"account:user"}}, {"10.1.2.3:80", nil}, {"10.1.2.3:80", []string{"alice@example.com"}}, {"10.1.2.3:80", []string{"account:machine"}}, {"10.1.2.3:80", []string{"other:user"}}, {"10.1.2.3:80", []string{"account:user", "account:user"}}, {"10.1.2.3:80", []string{"account:user,account:user"}}} {
		if w := authorizeRequest(s, authQuery(s), x.peer, x.headers); w.Code != 403 {
			t.Fatalf("accepted principal %v from %s", x.headers, x.peer)
		}
	}
	r := httptest.NewRequest("GET", "http://backchannel/oauth2/authorize?"+authQuery(s).Encode(), nil)
	r.Header.Set(principalHeader, "account:user")
	r.RemoteAddr = "10.1.2.3:80"
	w := httptest.NewRecorder()
	s.BackchannelHandler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("backchannel authenticates headers")
	}
}
func TestAuthorizationValidation(t *testing.T) {
	s := testServer(t)
	for k, v := range map[string]string{"client_id": "other", "redirect_uri": "https://evil.test", "scope": "openid groups", "response_type": "token", "code_challenge": "", "code_challenge_method": "plain", "state": "", "prompt": "login"} {
		q := authQuery(s)
		q.Set(k, v)
		if w := authorizeRequest(s, q, "10.1.2.3:80", []string{"account:user"}); w.Code != 400 {
			t.Fatalf("accepted %s", k)
		}
	}
	q := authQuery(s)
	q.Add("client_id", "authentik")
	if w := authorizeRequest(s, q, "10.1.2.3:80", []string{"account:user"}); w.Code != 400 {
		t.Fatal("duplicate accepted")
	}
	q = authQuery(s)
	q.Del("nonce")
	if w := authorizeRequest(s, q, "10.1.2.3:80", []string{"account:user"}); w.Code != 302 {
		t.Fatal("Authentik source without nonce rejected")
	}
}
func TestCodeSecurity(t *testing.T) {
	s := testServer(t)
	code := issue(t, s)
	if w := exchange(s, code, strings.Repeat("x", 43)); w.Code != 400 {
		t.Fatal("wrong proof accepted")
	}
	code = issue(t, s)
	c := s.codes[code]
	c.ExpiresAt = time.Now().Add(-time.Second)
	s.codes[code] = c
	if w := exchange(s, code, testVerifier); w.Code != 400 {
		t.Fatal("expired code accepted")
	}
	code = issue(t, s)
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if exchange(s, code, testVerifier).Code == 200 {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("successful redemptions: %d", success.Load())
	}
}
func TestTokenRequestBoundary(t *testing.T) {
	s := testServer(t)
	for _, body := range []string{"client_id=authentik", "grant_type=authorization_code&grant_type=authorization_code", strings.Repeat("x", 4097)} {
		r := httptest.NewRequest("POST", "http://backchannel/oauth2/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(s.config.Client.ID, s.config.Client.Secret)
		w := httptest.NewRecorder()
		s.BackchannelHandler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("bad body accepted")
		}
	}
	r := httptest.NewRequest("POST", "http://backchannel/oauth2/token?code=bad", strings.NewReader("grant_type=authorization_code"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.BackchannelHandler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("token query accepted")
	}
	code := issue(t, s)
	r = httptest.NewRequest("POST", "http://backchannel/oauth2/token", strings.NewReader("grant_type=authorization_code&code="+code))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("authentik", "wrong")
	w = httptest.NewRecorder()
	s.BackchannelHandler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("wrong client accepted")
	}
	if exchange(s, code, testVerifier).Code != 200 {
		t.Fatal("unauthenticated request consumed code")
	}
}
func TestBoundedStore(t *testing.T) {
	s := testServer(t)
	s.config.MaxCodes = 1
	code := issue(t, s)
	if w := authorizeRequest(s, authQuery(s), "10.1.2.3:80", []string{"account:user"}); w.Code != 503 {
		t.Fatal("capacity not enforced")
	}
	c := s.codes[code]
	c.ExpiresAt = time.Now().Add(-time.Second)
	s.codes[code] = c
	s.nextCleanup = time.Time{}
	_ = issue(t, s)
	if len(s.codes) != 1 {
		t.Fatal("expired state not reclaimed")
	}
}
func TestRemovedRoutes(t *testing.T) {
	s := testServer(t)
	for _, h := range []http.Handler{s.Handler(), s.BackchannelHandler()} {
		for _, path := range []string{"/logout", "/auth/verify", "/oauth2/callback"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 404 {
				t.Fatalf("old route %s remains", path)
			}
		}
	}
}
func TestStrictConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, []byte("fallback_oidc: {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(p); e == nil {
		t.Fatal("obsolete config accepted")
	}
	s := testServer(t)
	c := s.config
	c.Client.Secret = ""
	if _, e := NewServer(c, &rsa.PrivateKey{}, nil); e == nil {
		t.Fatal("public client accepted")
	}
}

func TestEncodedExternalPrincipal(t *testing.T) {
	s := testServer(t)
	principal := base64.RawURLEncoding.EncodeToString([]byte("account")) + ":" + base64.RawURLEncoding.EncodeToString([]byte("auth0|"+strings.Repeat("x", 150)))
	c := s.config
	c.Principals = []string{principal}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	s.principals = map[string]bool{principal: true}
	if w := authorizeRequest(s, authQuery(s), "10.1.2.3:80", []string{principal}); w.Code != 302 {
		t.Fatalf("encoded identity rejected: %d", w.Code)
	}
}

func TestTrustedAccountAdmission(t *testing.T) {
	s := testServer(t)
	s.principals = map[string]bool{}
	s.trustedAccounts = map[string]bool{base64.RawURLEncoding.EncodeToString([]byte("account")): true}
	for _, x := range []struct {
		principal, peer string
		status          int
	}{
		{"YWNjb3VudA:bmV3LXVzZXI", "10.1.2.3:80", 302},
		{"b3RoZXI:bmV3LXVzZXI", "10.1.2.3:80", 403},
		{"YWNjb3VudA:bmV3LXVzZXI", "192.0.2.1:80", 403},
		{"YWNjb3VudA:one:two", "10.1.2.3:80", 403},
	} {
		if w := authorizeRequest(s, authQuery(s), x.peer, []string{x.principal}); w.Code != x.status {
			t.Fatalf("%s: %d", x.principal, w.Code)
		}
	}
	c := s.config
	c.Principals = nil
	c.TrustedAccounts = []string{"account"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.TrustedAccounts = nil
	if err := c.Validate(); err == nil {
		t.Fatal("empty trust accepted")
	}
}
