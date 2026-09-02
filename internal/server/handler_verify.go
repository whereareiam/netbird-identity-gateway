package server

import (
	"net/http"
	"strings"
)

func (server *Server) verify(writer http.ResponseWriter, request *http.Request) {
	current, ok := server.identityFromRequest(request)
	if !ok && server.hasTrustedIdentity(request) {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	if !ok {
		current, ok = server.sessionFromRequest(request)
	}
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="identity-gateway"`)
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	writer.Header().Set("X-Identity-Subject", current.Subject)
	writer.Header().Set("X-Identity-Email", current.Email)
	writer.Header().Set("X-Identity-Name", current.Name)
	writer.Header().Set("X-Identity-Preferred-Username", current.PreferredUsername)
	writer.Header().Set("X-Identity-Groups", strings.Join(current.Groups, ","))
	writer.WriteHeader(http.StatusOK)
}

func (server *Server) logout(writer http.ResponseWriter, request *http.Request) {
	server.clearSession(writer)
	redirect := request.URL.Query().Get("post_logout_redirect_uri")
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(writer, request, redirect, http.StatusFound)
}
