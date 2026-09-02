package server

import (
	"net/http"
	"strings"
)

func (server *Server) userinfo(writer http.ResponseWriter, request *http.Request) {
	value := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	claims, err := server.verifyToken(value)
	if err != nil {
		server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	server.writeJSON(writer, http.StatusOK, claims)
}
