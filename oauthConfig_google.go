package main

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func GetGoogleOauthConfig(params *OauthConfigParams) (*oauth2.Config, error) {
	if params == nil {
		return nil, ErrNilOauthConfigParams
	}

	return &oauth2.Config{
		RedirectURL:  params.RedirectURL,
		ClientID:     params.ClientID,
		ClientSecret: params.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}, nil
}
