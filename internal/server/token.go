package server

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-jose/go-jose/v4"
	"time"
)

type tokenClaims struct {
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce,omitempty"`
	Purpose   string `json:"token_use"`
}

func newSigner(k *rsa.PrivateKey) (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID(&k.PublicKey)))
}
func (s *Server) signToken(c authorizationCode, purpose string) (string, error) {
	now := time.Now()
	claims := tokenClaims{Subject: c.Subject, Issuer: s.config.Issuer, Audience: s.config.Client.ID, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(s.config.TokenTTL) * time.Second).Unix(), Purpose: purpose}
	if purpose == "id" {
		claims.Nonce = c.Nonce
	}
	b, e := json.Marshal(claims)
	if e != nil {
		return "", e
	}
	o, e := s.signer.Sign(b)
	if e != nil {
		return "", e
	}
	return o.CompactSerialize()
}
func (s *Server) verifyAccessToken(value string) (tokenClaims, error) {
	if len(value) > 4096 {
		return tokenClaims{}, errors.New("oversized token")
	}
	o, e := jose.ParseSigned(value, []jose.SignatureAlgorithm{jose.RS256})
	if e != nil {
		return tokenClaims{}, e
	}
	b, e := o.Verify(s.publicKey)
	if e != nil {
		return tokenClaims{}, e
	}
	var c tokenClaims
	now := time.Now().Unix()
	if e = json.Unmarshal(b, &c); e != nil || c.Issuer != s.config.Issuer || c.Audience != s.config.Client.ID || c.Purpose != "access" || c.Subject == "" || c.ExpiresAt <= now || c.IssuedAt > now || c.ExpiresAt-c.IssuedAt > int64(s.config.TokenTTL) {
		return tokenClaims{}, errors.New("invalid access token")
	}
	return c, nil
}
func verifyPKCE(c authorizationCode, v string) bool {
	if !verifierPattern.MatchString(v) {
		return false
	}
	h := sha256.Sum256([]byte(v))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(h[:])), []byte(c.Challenge)) == 1
}
