package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const sessionCookie = "nig_session"

// Server provides an OIDC issuer with trusted-proxy authentication and an optional upstream OIDC fallback.
type Server struct {
	config    Config
	signer    jose.Signer
	publicKey *rsa.PublicKey
	logger    *slog.Logger
	proxyNets []*net.IPNet
	fallback  *fallbackProvider

	mu       sync.Mutex
	codes    map[string]authorizationCode
	states   map[string]loginState
	sessions map[string]session
}

type fallbackProvider struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewServer creates a gateway from validated configuration and a signing key.
func NewServer(config Config, key *rsa.PrivateKey, logger *slog.Logger) (*Server, error) {
	if key == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	signer, err := newSigner(key)
	if err != nil {
		return nil, err
	}
	server := &Server{
		config:    config,
		signer:    signer,
		publicKey: &key.PublicKey,
		logger:    logger,
		codes:     make(map[string]authorizationCode),
		states:    make(map[string]loginState),
		sessions:  make(map[string]session),
	}
	for _, cidr := range config.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy CIDR: %w", err)
		}
		server.proxyNets = append(server.proxyNets, network)
	}
	if err := server.configureFallback(context.Background()); err != nil {
		return nil, err
	}
	return server, nil
}

func (server *Server) configureFallback(ctx context.Context) error {
	if server.config.Fallback.Issuer == "" {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, server.config.Fallback.Issuer)
	if err != nil {
		return fmt.Errorf("discover fallback OIDC provider: %w", err)
	}
	scopes := server.config.Fallback.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	server.fallback = &fallbackProvider{
		oauth: oauth2.Config{
			ClientID:     server.config.Fallback.ClientID,
			ClientSecret: server.config.Fallback.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  server.config.Fallback.RedirectURL,
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: server.config.Fallback.ClientID}),
	}
	return nil
}

// Handler returns the HTTP handler for all gateway endpoints.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc("/.well-known/openid-configuration", server.discovery)
	mux.HandleFunc("/oauth2/authorize", server.authorize)
	mux.HandleFunc("/oauth2/callback", server.callback)
	mux.HandleFunc("/oauth2/token", server.token)
	mux.HandleFunc("/oauth2/userinfo", server.userinfo)
	mux.HandleFunc("/oauth2/jwks.json", server.jwks)
	mux.HandleFunc("/auth/verify", server.verify)
	mux.HandleFunc("/logout", server.logout)
	return server.withSecurityHeaders(server.withRequestLog(mux))
}
