package server

import (
	"github.com/go-jose/go-jose/v4"
	"net/http"
)

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok\n"))
}
func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, 200, map[string]any{
		"issuer": s.config.Issuer, "authorization_endpoint": s.config.Issuer + "/oauth2/authorize", "token_endpoint": s.config.Issuer + "/oauth2/token", "userinfo_endpoint": s.config.Issuer + "/oauth2/userinfo", "jwks_uri": s.config.Issuer + "/oauth2/jwks.json",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid"}, "claims_supported": []string{"sub", "iss", "aud", "iat", "exp", "nonce"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
}
func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: s.publicKey, Use: "sig", Algorithm: "RS256", KeyID: keyID(s.publicKey)}}})
}
