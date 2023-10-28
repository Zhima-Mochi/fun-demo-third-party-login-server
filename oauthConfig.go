package main

import "errors"

var (
	ErrNilOauthConfigParams = errors.New("oauth config params is nil")
)

type OauthConfigParams struct {
	RedirectURL  string
	ClientID     string
	ClientSecret string
}
