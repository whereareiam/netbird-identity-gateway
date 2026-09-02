package server

import "net/http"

func (server *Server) token(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	if request.Form.Get("grant_type") != "authorization_code" {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	clientID := clientIDFromRequest(request)
	if !server.clientAuthenticated(request, clientID) {
		server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code, ok := server.consumeCode(request.Form.Get("code"))
	if !ok || !server.validCodeExchange(code, request, clientID) {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	accessToken, err := server.signToken(code.Identity, code.ClientID, "")
	if err != nil {
		http.Error(writer, "could not sign access token", http.StatusInternalServerError)
		return
	}
	idToken, err := server.signToken(code.Identity, code.ClientID, code.Nonce)
	if err != nil {
		http.Error(writer, "could not sign ID token", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600, "id_token": idToken, "scope": "openid profile email groups"})
}
