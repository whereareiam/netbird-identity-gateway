package server

import (
	"net/http"
	"time"
)

type loginState struct {
	ClientID            string
	RedirectURI         string
	State               string
	ClientNonce         string
	UpstreamNonce       string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

func (server *Server) consumeLoginState(value string) (loginState, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()
	state, ok := server.states[value]
	if ok {
		delete(server.states, value)
	}
	return state, ok && time.Now().Before(state.ExpiresAt)
}

func (server *Server) startFallbackLogin(writer http.ResponseWriter, request *http.Request, clientID, redirectURI string) {
	state, err := randomToken(32)
	if err != nil {
		http.Error(writer, "could not create login state", http.StatusInternalServerError)
		return
	}
	upstreamNonce, err := randomToken(32)
	if err != nil {
		http.Error(writer, "could not create login nonce", http.StatusInternalServerError)
		return
	}
	query := request.URL.Query()
	now := time.Now()
	server.mu.Lock()
	server.cleanupExpiredLocked(now)
	server.states[state] = loginState{ClientID: clientID, RedirectURI: redirectURI, State: query.Get("state"), ClientNonce: query.Get("nonce"), UpstreamNonce: upstreamNonce, CodeChallenge: query.Get("code_challenge"), CodeChallengeMethod: query.Get("code_challenge_method"), ExpiresAt: now.Add(5 * time.Minute)}
	server.mu.Unlock()
	authURL := server.fallback.oauth.AuthCodeURL(state, withFallbackOptions(query, upstreamNonce)...)
	http.Redirect(writer, request, authURL, http.StatusFound)
}
