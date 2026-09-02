package server

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type tokenClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Issuer            string   `json:"iss"`
	Audience          string   `json:"aud"`
	IssuedAt          int64    `json:"iat"`
	ExpiresAt         int64    `json:"exp"`
	Nonce             string   `json:"nonce,omitempty"`
}

func newSigner(key *rsa.PrivateKey) (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID(&key.PublicKey)))
}

func (server *Server) signToken(current identity, audience, nonce string) (string, error) {
	now := time.Now()
	claims := map[string]any{"sub": current.Subject, "iss": server.config.Issuer, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	addIdentityClaims(claims, current, nonce)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	object, err := server.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func addIdentityClaims(claims map[string]any, current identity, nonce string) {
	if current.Email != "" {
		claims["email"] = current.Email
	}
	if current.Name != "" {
		claims["name"] = current.Name
	}
	if current.PreferredUsername != "" {
		claims["preferred_username"] = current.PreferredUsername
	}
	if len(current.Groups) > 0 {
		claims["groups"] = current.Groups
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for key, value := range current.Claims {
		if _, exists := claims[key]; !exists {
			claims[key] = value
		}
	}
}

func (server *Server) verifyToken(value string) (tokenClaims, error) {
	object, err := jose.ParseSigned(value, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return tokenClaims{}, err
	}
	payload, err := object.Verify(server.publicKey)
	if err != nil {
		return tokenClaims{}, err
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != server.config.Issuer || claims.ExpiresAt <= time.Now().Unix() {
		return tokenClaims{}, errors.New("invalid token claims")
	}
	return claims, nil
}

func verifyPKCE(code authorizationCode, verifier string) bool {
	if code.CodeChallenge == "" {
		return verifier == ""
	}
	if code.CodeChallengeMethod != "S256" || verifier == "" {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(hash[:])), []byte(code.CodeChallenge)) == 1
}

func clientIDFromRequest(request *http.Request) string {
	if clientID, _, ok := request.BasicAuth(); ok {
		return clientID
	}
	return request.Form.Get("client_id")
}

func (server *Server) validCodeExchange(code authorizationCode, request *http.Request, clientID string) bool {
	redirectURI := request.Form.Get("redirect_uri")
	return code.ClientID == clientID && code.RedirectURI == redirectURI && server.clientRedirectAllowed(code.ClientID, redirectURI) && verifyPKCE(code, request.Form.Get("code_verifier"))
}

func (server *Server) clientAuthenticated(request *http.Request, clientID string) bool {
	client, ok := server.config.Clients[clientID]
	if !ok {
		return false
	}
	providedID, providedSecret, hasBasic := request.BasicAuth()
	if !hasBasic {
		providedID = request.Form.Get("client_id")
		providedSecret = request.Form.Get("client_secret")
	}
	if subtle.ConstantTimeCompare([]byte(providedID), []byte(clientID)) != 1 {
		return false
	}
	if client.Secret == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(providedSecret), []byte(client.Secret)) == 1
}

func (server *Server) clientRedirectAllowed(clientID, redirectURI string) bool {
	client, ok := server.config.Clients[clientID]
	if !ok {
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(redirectURI)) == 1 {
			return true
		}
	}
	return false
}
