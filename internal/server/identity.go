package server

import (
	"net"
	"net/http"
	"strings"
)

type identity struct {
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	Groups            []string
	Claims            map[string]any
}

func (server *Server) identityFromRequest(request *http.Request) (identity, bool) {
	if !server.isTrustedProxy(request) {
		return identity{}, false
	}
	value := strings.TrimSpace(request.Header.Get(server.config.Identity.UserHeader))
	if value == "" {
		return identity{}, false
	}
	if mapped, ok := server.config.Identity.Mappings[value]; ok {
		if mapped.Subject == "" {
			return identity{}, false
		}
		if mapped.PreferredUsername == "" {
			mapped.PreferredUsername = mapped.Email
		}
		return identity{
			Subject:           mapped.Subject,
			Email:             mapped.Email,
			Name:              mapped.Name,
			PreferredUsername: mapped.PreferredUsername,
			Groups:            mapped.Groups,
			Claims:            mapped.Claims,
		}, true
	}
	if !server.config.Identity.AllowUnmapped || strings.ContainsAny(value, "\r\n") {
		return identity{}, false
	}
	return identity{
		Subject:           value,
		Email:             value,
		PreferredUsername: value,
		Groups:            splitGroups(request.Header.Get(server.config.Identity.GroupsHeader)),
	}, true
}

func (server *Server) hasTrustedIdentity(request *http.Request) bool {
	return server.isTrustedProxy(request) && strings.TrimSpace(request.Header.Get(server.config.Identity.UserHeader)) != ""
}

func (server *Server) isTrustedProxy(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range server.proxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
