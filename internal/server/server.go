package server

import (
	"crypto/rsa"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server proves linked NetBird identities. It owns no users or entitlements.
type Server struct {
	config      Config
	signer      jose.Signer
	publicKey   *rsa.PublicKey
	logger      *slog.Logger
	proxyNets   []*net.IPNet
	principals  map[string]bool
	mu          sync.Mutex
	codes       map[string]authorizationCode
	nextCleanup time.Time
}

// NewServer validates the complete configuration before accepting requests.
func NewServer(c Config, key *rsa.PrivateKey, logger *slog.Logger) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if key == nil || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA signing key of at least 2048 bits required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	signer, e := newSigner(key)
	if e != nil {
		return nil, e
	}
	s := &Server{config: c, signer: signer, publicKey: &key.PublicKey, logger: logger, codes: map[string]authorizationCode{}, principals: map[string]bool{}}
	for _, p := range c.Principals {
		s.principals[p] = true
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		_, n, _ := net.ParseCIDR(cidr)
		s.proxyNets = append(s.proxyNets, n)
	}
	return s, nil
}

// Handler is the proxy-only front channel. It cannot exchange or inspect tokens.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.health)
	m.HandleFunc("GET /oauth2/authorize", s.authorize)
	return s.withSecurityHeaders(s.withRequestLog(m))
}

// BackchannelHandler serves Authentik and cannot authenticate request headers.
func (s *Server) BackchannelHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.health)
	m.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	m.HandleFunc("GET /oauth2/jwks.json", s.jwks)
	m.HandleFunc("POST /oauth2/token", s.token)
	m.HandleFunc("GET /oauth2/userinfo", s.userinfo)
	return s.withSecurityHeaders(s.withRequestLog(m))
}
