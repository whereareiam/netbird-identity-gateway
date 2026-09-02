package server

import "net/http"

func (server *Server) callback(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if server.fallback == nil {
		http.Error(writer, "fallback OIDC is not configured", http.StatusNotFound)
		return
	}
	state, ok := server.consumeLoginState(request.URL.Query().Get("state"))
	if !ok {
		http.Error(writer, "invalid or expired login state", http.StatusBadRequest)
		return
	}
	if request.URL.Query().Get("error") != "" {
		http.Error(writer, "upstream authentication failed", http.StatusUnauthorized)
		return
	}
	current, err := server.exchangeFallbackIdentity(request, state.UpstreamNonce)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := server.setSession(writer, current); err != nil {
		http.Error(writer, "could not create gateway session", http.StatusInternalServerError)
		return
	}
	code, err := server.issueCode(state.ClientID, state.RedirectURI, state.ClientNonce, state.CodeChallenge, state.CodeChallengeMethod, current)
	if err != nil {
		http.Error(writer, "could not issue authorization code", http.StatusInternalServerError)
		return
	}
	server.redirectWithCode(writer, request, state.RedirectURI, state.State, code)
}
