package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config describes the gateway's network, identity, upstream OIDC, and client settings.
type Config struct {
	Listen            string            `yaml:"listen"`
	Issuer            string            `yaml:"issuer"`
	TrustedProxyCIDRs []string          `yaml:"trusted_proxy_cidrs"`
	Identity          IdentityConfig    `yaml:"identity"`
	Fallback          FallbackConfig    `yaml:"fallback_oidc"`
	Clients           map[string]Client `yaml:"clients"`
	SigningKey        string            `yaml:"signing_key"`
	SessionKey        string            `yaml:"session_key"`
	SessionTTL        int               `yaml:"session_ttl_seconds"`
	CodeTTL           int               `yaml:"authorization_code_ttl_seconds"`
}

// IdentityConfig defines the headers and explicit mapping used by a trusted proxy.
type IdentityConfig struct {
	UserHeader    string                   `yaml:"user_header"`
	GroupsHeader  string                   `yaml:"groups_header"`
	AllowUnmapped bool                     `yaml:"allow_unmapped"`
	Mappings      map[string]IdentityEntry `yaml:"mappings"`
}

// IdentityEntry is the canonical identity emitted in downstream OIDC claims and headers.
type IdentityEntry struct {
	Subject           string         `yaml:"subject"`
	Email             string         `yaml:"email"`
	Name              string         `yaml:"name"`
	PreferredUsername string         `yaml:"preferred_username"`
	Groups            []string       `yaml:"groups"`
	Claims            map[string]any `yaml:"claims"`
}

// FallbackConfig configures the OIDC provider used when trusted identity is unavailable.
type FallbackConfig struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

// Client identifies an application registered with the gateway OIDC issuer.
type Client struct {
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

// LoadConfig reads and validates a gateway configuration.
func LoadConfig(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := yaml.Unmarshal(contents, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config *Config) Validate() error {
	if config.Listen == "" {
		config.Listen = ":8080"
	}
	if config.Issuer == "" {
		return errors.New("issuer is required")
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return errors.New("issuer must be an absolute HTTPS URL")
	}
	if len(config.TrustedProxyCIDRs) == 0 {
		return errors.New("at least one trusted_proxy_cidrs entry is required")
	}
	for _, cidr := range config.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
	}
	if config.Identity.UserHeader == "" {
		config.Identity.UserHeader = "X-NetBird-User"
	}
	if config.Identity.GroupsHeader == "" {
		config.Identity.GroupsHeader = "X-NetBird-Groups"
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = 8 * 60 * 60
	}
	if config.CodeTTL == 0 {
		config.CodeTTL = 60
	}
	if config.SessionTTL < 60 || config.CodeTTL < 10 {
		return errors.New("session and authorization code TTLs are too short")
	}
	for clientID, client := range config.Clients {
		if clientID == "" || len(client.RedirectURIs) == 0 {
			return fmt.Errorf("client %q must have at least one redirect URI", clientID)
		}
		for _, redirectURI := range client.RedirectURIs {
			parsed, err := url.Parse(redirectURI)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return fmt.Errorf("client %q has invalid redirect URI %q", clientID, redirectURI)
			}
		}
	}
	fallbackFields := []string{config.Fallback.Issuer, config.Fallback.ClientID, config.Fallback.RedirectURL}
	setFallbackFields := 0
	for _, field := range fallbackFields {
		if strings.TrimSpace(field) != "" {
			setFallbackFields++
		}
	}
	if setFallbackFields != 0 && setFallbackFields != len(fallbackFields) {
		return errors.New("fallback_oidc requires issuer, client_id, and redirect_url together")
	}
	return nil
}

// ParsePrivateKey parses a PEM-encoded PKCS#1 or PKCS#8 RSA private key.
func ParsePrivateKey(contents []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not RSA")
	}
	return rsaKey, nil
}

func splitGroups(value string) []string {
	parts := strings.Split(value, ",")
	groups := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			groups = append(groups, part)
		}
	}
	return groups
}
