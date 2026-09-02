package server

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

type authorizationCode struct {
	ClientID            string
	RedirectURI         string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Identity            identity
	ExpiresAt           time.Time
}

func (server *Server) validateAuthorization(query url.Values) (string, string, error) {
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	challenge := query.Get("code_challenge")
	method := query.Get("code_challenge_method")
	if challenge != "" && method != "S256" {
		return "", "", errors.New("only S256 PKCE is supported")
	}
	if query.Get("response_type") != "code" || clientID == "" || redirectURI == "" || !server.clientRedirectAllowed(clientID, redirectURI) {
		return "", "", errors.New("invalid authorization request")
	}
	return clientID, redirectURI, nil
}

func (server *Server) issueCode(clientID, redirectURI, nonce, challenge, challengeMethod string, current identity) (string, error) {
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	server.mu.Lock()
	server.cleanupExpiredLocked(now)
	server.codes[code] = authorizationCode{ClientID: clientID, RedirectURI: redirectURI, Nonce: nonce, CodeChallenge: challenge, CodeChallengeMethod: challengeMethod, Identity: current, ExpiresAt: now.Add(time.Duration(server.config.CodeTTL) * time.Second)}
	server.mu.Unlock()
	return code, nil
}

func (server *Server) consumeCode(value string) (authorizationCode, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()
	code, ok := server.codes[value]
	if ok {
		delete(server.codes, value)
	}
	return code, ok && time.Now().Before(code.ExpiresAt)
}

func (server *Server) redirectWithCode(writer http.ResponseWriter, request *http.Request, redirectURI, state, code string) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(writer, "invalid redirect URI", http.StatusInternalServerError)
		return
	}
	query := redirect.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}
