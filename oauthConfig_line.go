package main

import (
	"golang.org/x/oauth2"
)

func GetLineOauthConfig(params *OauthConfigParams) (*oauth2.Config, error) {
	if params == nil {
		return nil, ErrNilOauthConfigParams
	}

	return &oauth2.Config{
		RedirectURL:  params.RedirectURL,
		ClientID:     params.ClientID,
		ClientSecret: params.ClientSecret,
		Scopes:       []string{"profile", "openid", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://access.line.me/oauth2/v2.1/authorize",
			TokenURL: "https://api.line.me/oauth2/v2.1/token",
		},
	}, nil
}
