package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

func (server *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		start := time.Now()
		next.ServeHTTP(writer, request)
		server.logger.Info("request", "method", request.Method, "path", request.URL.Path, "duration", time.Since(start).String())
	})
}

func (server *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func keyID(key *rsa.PublicKey) string {
	hash := sha256.Sum256(append(key.N.Bytes(), byte(key.E>>8), byte(key.E)))
	return base64.RawURLEncoding.EncodeToString(hash[:12])
}

func (server *Server) cleanupExpiredLocked(now time.Time) {
	for value, code := range server.codes {
		if now.After(code.ExpiresAt) {
			delete(server.codes, value)
		}
	}
	for value, state := range server.states {
		if now.After(state.ExpiresAt) {
			delete(server.states, value)
		}
	}
	for value, currentSession := range server.sessions {
		if now.After(currentSession.ExpiresAt) {
			delete(server.sessions, value)
		}
	}
}
