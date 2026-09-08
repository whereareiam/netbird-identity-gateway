package server

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

type authorizationCode struct {
	Subject, ClientID, RedirectURI, Nonce, Challenge string
	ExpiresAt                                        time.Time
}

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func (s *Server) validateAuthorization(q url.Values) error {
	for k, v := range q {
		if len(v) != 1 || len(v[0]) > 512 {
			return errors.New("ambiguous or oversized parameter")
		}
		switch k {
		case "client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "login_hint":
		default:
			return errors.New("unsupported parameter")
		}
	}
	if q.Get("client_id") != s.config.Client.ID || q.Get("redirect_uri") != s.config.Client.RedirectURI || q.Get("response_type") != "code" || q.Get("scope") != "openid" {
		return errors.New("invalid client, callback, response type or scope")
	}
	if !challengePattern.MatchString(q.Get("code_challenge")) || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
		return errors.New("S256 PKCE and state required")
	}
	if p := q.Get("prompt"); p != "" && p != "none" {
		return errors.New("interactive authentication is not supported")
	}
	return nil
}
func (s *Server) issueCode(q url.Values, subject string) (string, error) {
	code, e := randomToken(32)
	if e != nil {
		return "", e
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.nextCleanup) {
		for k, c := range s.codes {
			if !now.Before(c.ExpiresAt) {
				delete(s.codes, k)
			}
		}
		s.nextCleanup = now.Add(time.Second)
	}
	if len(s.codes) >= s.config.MaxCodes {
		return "", errors.New("code capacity reached")
	}
	s.codes[code] = authorizationCode{Subject: subject, ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), ExpiresAt: now.Add(time.Duration(s.config.CodeTTL) * time.Second)}
	return code, nil
}
func (s *Server) redeemCode(value, redirect, verifier string) (authorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[value]
	if !ok {
		return c, false
	}
	delete(s.codes, value)
	return c, time.Now().Before(c.ExpiresAt) && c.ClientID == s.config.Client.ID && c.RedirectURI == redirect && verifyPKCE(c, verifier)
}
func (s *Server) redirectWithCode(w http.ResponseWriter, r *http.Request, state, code string) {
	u, _ := url.Parse(s.config.Client.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
