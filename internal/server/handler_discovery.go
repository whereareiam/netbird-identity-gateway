package server

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("ok\n"))
}

func (server *Server) discovery(writer http.ResponseWriter, _ *http.Request) {
	server.writeJSON(writer, http.StatusOK, map[string]any{
		"issuer":                                server.config.Issuer,
		"authorization_endpoint":                server.config.Issuer + "/oauth2/authorize",
		"token_endpoint":                        server.config.Issuer + "/oauth2/token",
		"userinfo_endpoint":                     server.config.Issuer + "/oauth2/userinfo",
		"jwks_uri":                              server.config.Issuer + "/oauth2/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "preferred_username", "groups"},
	})
}

func (server *Server) jwks(writer http.ResponseWriter, _ *http.Request) {
	key := jose.JSONWebKey{Key: server.publicKey, Use: "sig", Algorithm: string(jose.RS256), KeyID: keyID(server.publicKey)}
	server.writeJSON(writer, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
}
