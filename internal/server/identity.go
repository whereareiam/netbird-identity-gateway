package server

import (
	"net"
	"net/http"
)

const principalHeader = "X-NetBird-Principal"

func (s *Server) identityFromRequest(r *http.Request) (string, bool) {
	if !s.isTrustedProxy(r) {
		return "", false
	}
	values := r.Header.Values(principalHeader)
	if len(values) != 1 || !principalPattern.MatchString(values[0]) || !s.principals[values[0]] {
		return "", false
	}
	return "netbird:" + values[0], true
}
func (s *Server) isTrustedProxy(r *http.Request) bool {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return false
	}
	ip := net.ParseIP(host)
	for _, n := range s.proxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
