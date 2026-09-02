package server

import (
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func withFallbackOptions(query url.Values, nonce string) []oauth2.AuthCodeOption {
	options := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	for _, name := range []string{"prompt", "login_hint"} {
		if value := query.Get(name); value != "" {
			options = append(options, oauth2.SetAuthURLParam(name, value))
		}
	}
	return options
}

func (server *Server) exchangeFallbackIdentity(request *http.Request, expectedNonce string) (identity, error) {
	token, err := server.fallback.oauth.Exchange(request.Context(), request.URL.Query().Get("code"))
	if err != nil {
		return identity{}, errors.New("could not exchange authorization code")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity{}, errors.New("upstream did not return an ID token")
	}
	idToken, err := server.fallback.verifier.Verify(request.Context(), rawIDToken)
	if err != nil {
		return identity{}, errors.New("invalid upstream ID token")
	}
	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Name    string   `json:"name"`
		Groups  []string `json:"groups"`
		Nonce   string   `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.Nonce != expectedNonce {
		return identity{}, errors.New("invalid upstream identity claims")
	}
	current := identity{Subject: claims.Subject, Email: claims.Email, Name: claims.Name, PreferredUsername: claims.Email, Groups: claims.Groups}
	if current.Email == "" {
		current.PreferredUsername = current.Subject
	}
	return current, nil
}
