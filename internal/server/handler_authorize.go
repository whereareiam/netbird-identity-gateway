package server

import (
	"net/http"
	"net/url"
)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 4096 {
		http.Error(w, "request too large", http.StatusRequestURITooLong)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		http.Error(w, "invalid query", 400)
		return
	}
	if e = s.validateAuthorization(q); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	subject, ok := s.identityFromRequest(r)
	if !ok {
		http.Error(w, "verified linked NetBird principal required", 403)
		return
	}
	code, e := s.issueCode(q, subject)
	if e != nil {
		http.Error(w, "authorization temporarily unavailable", 503)
		return
	}
	s.redirectWithCode(w, r, q.Get("state"), code)
}
