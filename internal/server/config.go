package server

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Config configures an identity-only OIDC source for Authentik.
// The two listeners must have separate network policies: only the NetBird
// proxy may reach Listen, while Authentik uses BackchannelListen.
type Config struct {
	Listen            string   `yaml:"listen"`
	BackchannelListen string   `yaml:"backchannel_listen"`
	Issuer            string   `yaml:"issuer"`
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`
	Principals        []string `yaml:"principals"`
	Client            Client   `yaml:"client"`
	SigningKey        string   `yaml:"signing_key"`
	CodeTTL           int      `yaml:"authorization_code_ttl_seconds"`
	TokenTTL          int      `yaml:"token_ttl_seconds"`
	MaxCodes          int      `yaml:"max_pending_codes"`
}

// Client is the single confidential Authentik OIDC source registration.
type Client struct {
	ID          string `yaml:"id"`
	Secret      string `yaml:"secret"`
	RedirectURI string `yaml:"redirect_uri"`
}

var principalPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}:[A-Za-z0-9_-]{1,1000}$`)

// LoadConfig strictly parses one YAML document. Obsolete broker settings fail closed.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return Config{}, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("expected one YAML document")
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.BackchannelListen == "" {
		c.BackchannelListen = ":8081"
	}
	if c.Listen == c.BackchannelListen {
		return errors.New("listeners must differ")
	}
	if !httpsURL(c.Issuer) || strings.HasSuffix(c.Issuer, "/") {
		return errors.New("issuer must be a canonical HTTPS URL without trailing slash")
	}
	u, _ := url.Parse(c.Issuer)
	if u.Path != "" {
		return errors.New("issuer must not have a path")
	}
	if len(c.TrustedProxyCIDRs) == 0 {
		return errors.New("trusted_proxy_cidrs required")
	}
	for _, s := range c.TrustedProxyCIDRs {
		if _, n, e := net.ParseCIDR(s); e != nil {
			return e
		} else if ones, _ := n.Mask.Size(); ones == 0 {
			return errors.New("wildcard proxy trust is forbidden")
		}
	}
	if len(c.Principals) == 0 {
		return errors.New("explicit principals required")
	}
	seen := map[string]bool{}
	for _, p := range c.Principals {
		if !principalPattern.MatchString(p) || seen[p] {
			return errors.New("invalid or duplicate principal")
		}
		seen[p] = true
	}
	if c.Client.ID == "" || len(c.Client.ID) > 128 || len(c.Client.Secret) < 32 || !httpsURL(c.Client.RedirectURI) {
		return errors.New("client requires id, a secret of at least 32 bytes, and exact HTTPS redirect_uri")
	}
	if c.SigningKey == "" {
		return errors.New("stable signing_key path required")
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = 60
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 60
	}
	if c.MaxCodes == 0 {
		c.MaxCodes = 1024
	}
	if c.CodeTTL < 10 || c.CodeTTL > 120 || c.TokenTTL < 10 || c.TokenTTL > 300 || c.MaxCodes < 1 || c.MaxCodes > 10000 {
		return errors.New("invalid lifetime or capacity")
	}
	return nil
}
func httpsURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// ParsePrivateKey reads a PKCS#1 or PKCS#8 RSA key of at least 2048 bits.
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("invalid PEM")
	}
	k, e := x509.ParsePKCS1PrivateKey(b.Bytes)
	if e != nil {
		v, e := x509.ParsePKCS8PrivateKey(b.Bytes)
		if e != nil {
			return nil, e
		}
		var ok bool
		k, ok = v.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("RSA key required")
		}
	}
	if k.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too short")
	}
	return k, k.Validate()
}
