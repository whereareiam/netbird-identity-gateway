package server

import (
	"crypto/subtle"
	"io"
	"mime"
	"net/http"
	"net/url"
)

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, name string) { s.writeJSON(w, status, map[string]string{"error": name}) }
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		fail(400, "invalid_request")
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if e != nil {
		fail(400, "invalid_request")
		return
	}
	q, e := url.ParseQuery(string(b))
	if e != nil {
		fail(400, "invalid_request")
		return
	}
	for k, v := range q {
		if len(v) != 1 || len(v[0]) > 512 {
			fail(400, "invalid_request")
			return
		}
		switch k {
		case "grant_type", "code", "redirect_uri", "code_verifier":
		default:
			fail(400, "invalid_request")
			return
		}
	}
	id, secret, ok := r.BasicAuth()
	if !ok || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(id), []byte(s.config.Client.ID)) != 1 || subtle.ConstantTimeCompare([]byte(secret), []byte(s.config.Client.Secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="identity-gateway"`)
		fail(401, "invalid_client")
		return
	}
	if q.Get("grant_type") != "authorization_code" {
		fail(400, "unsupported_grant_type")
		return
	}
	c, ok := s.redeemCode(q.Get("code"), q.Get("redirect_uri"), q.Get("code_verifier"))
	if !ok {
		fail(400, "invalid_grant")
		return
	}
	access, e := s.signToken(c, "access")
	if e != nil {
		fail(500, "server_error")
		return
	}
	idToken, e := s.signToken(c, "id")
	if e != nil {
		fail(500, "server_error")
		return
	}
	s.writeJSON(w, 200, map[string]any{"access_token": access, "id_token": idToken, "token_type": "Bearer", "expires_in": s.config.TokenTTL, "scope": "openid"})
}
