package server

import (
	"net/http"
	"time"
)

type session struct {
	Identity  identity
	ExpiresAt time.Time
}

func (server *Server) setSession(writer http.ResponseWriter, current identity) error {
	value, err := randomToken(32)
	if err != nil {
		return err
	}
	now := time.Now()
	server.mu.Lock()
	server.cleanupExpiredLocked(now)
	server.sessions[value] = session{Identity: current, ExpiresAt: now.Add(time.Duration(server.config.SessionTTL) * time.Second)}
	server.mu.Unlock()
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", MaxAge: server.config.SessionTTL, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return nil
}

func (server *Server) sessionFromRequest(request *http.Request) (identity, bool) {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		return identity{}, false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	value, ok := server.sessions[cookie.Value]
	if ok && time.Now().After(value.ExpiresAt) {
		delete(server.sessions, cookie.Value)
		ok = false
	}
	return value.Identity, ok
}

func (server *Server) clearSession(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
