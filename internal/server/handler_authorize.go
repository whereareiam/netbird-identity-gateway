package server

import "net/http"

func (server *Server) authorize(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := request.URL.Query()
	clientID, redirectURI, err := server.validateAuthorization(query)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if current, ok := server.identityFromRequest(request); ok {
		server.authorizeIdentity(writer, request, clientID, redirectURI, current)
		return
	}
	if server.hasTrustedIdentity(request) {
		http.Error(writer, "trusted identity is not mapped", http.StatusForbidden)
		return
	}
	if current, ok := server.sessionFromRequest(request); ok {
		server.authorizeIdentity(writer, request, clientID, redirectURI, current)
		return
	}
	if server.fallback == nil {
		http.Error(writer, "no trusted identity and no fallback OIDC provider configured", http.StatusUnauthorized)
		return
	}
	server.startFallbackLogin(writer, request, clientID, redirectURI)
}

func (server *Server) authorizeIdentity(writer http.ResponseWriter, request *http.Request, clientID, redirectURI string, current identity) {
	query := request.URL.Query()
	code, err := server.issueCode(clientID, redirectURI, query.Get("nonce"), query.Get("code_challenge"), query.Get("code_challenge_method"), current)
	if err != nil {
		http.Error(writer, "could not issue authorization code", http.StatusInternalServerError)
		return
	}
	server.redirectWithCode(writer, request, redirectURI, query.Get("state"), code)
}
