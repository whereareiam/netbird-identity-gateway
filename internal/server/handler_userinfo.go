package server

import (
	"net/http"
	"strings"
)

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		s.writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	c, e := s.verifyAccessToken(strings.TrimPrefix(values[0], "Bearer "))
	if e != nil {
		s.writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	s.writeJSON(w, 200, map[string]string{"sub": c.Subject})
}
