package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

var (
	googleOauthConfig   *oauth2.Config
	facebookOauthConfig *oauth2.Config
	lineOauthConfig     *oauth2.Config
	WEB_REDIRECT_URL    string
	SERVER_URL          string
	SERVER_PORT         string
)

func main() {
	apiAuthUrl := "/api/auth"
	WEB_REDIRECT_URL = os.Getenv("WEB_REDIRECT_URL")
	if WEB_REDIRECT_URL == "" {
		WEB_REDIRECT_URL = "http://localhost:3000"
	}
	SERVER_URL = os.Getenv("SERVER_URL")
	if SERVER_URL == "" {
		SERVER_URL = "http://localhost"
	}
	SERVER_PORT = os.Getenv("SERVER_PORT")
	if SERVER_PORT == "" {
		SERVER_PORT = "8080"
	}
	url := fmt.Sprintf("%s:%s", SERVER_URL, SERVER_PORT)

	googleOauthConfig, _ = GetGoogleOauthConfig(&OauthConfigParams{
		RedirectURL:  url + "/callback/google",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	})
	facebookOauthConfig, _ = GetFacebookOauthConfig(&OauthConfigParams{
		RedirectURL:  url + "/callback/facebook",
		ClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
		ClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),
	})
	lineOauthConfig, _ = GetLineOauthConfig(&OauthConfigParams{
		RedirectURL:  url + "/callback/line",
		ClientID:     os.Getenv("LINE_CLIENT_ID"),
		ClientSecret: os.Getenv("LINE_CLIENT_SECRET"),
	})

	loginUrl := fmt.Sprintf("%s/login", apiAuthUrl)
	http.HandleFunc(fmt.Sprintf("%s/google", loginUrl), handleGoogleLogin)
	http.HandleFunc(fmt.Sprintf("%s/facebook", loginUrl), handleFacebookLogin)
	http.HandleFunc(fmt.Sprintf("%s/line", loginUrl), handleLineLogin)

	callbackUrl := fmt.Sprintf("%s/callback", apiAuthUrl)
	http.HandleFunc(fmt.Sprintf("%s/google", callbackUrl), handleGoogleCallback)
	http.HandleFunc(fmt.Sprintf("%s/facebook", callbackUrl), handleFacebookCallback)
	http.HandleFunc(fmt.Sprintf("%s/line", callbackUrl), handleLineCallback)

	fmt.Printf("Server is listening at %s:%s\n", SERVER_URL, SERVER_PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil))
}

func getState(r *http.Request) string {
	redirectPath := r.URL.Query().Get("redirect")
	if redirectPath == "" {
		redirectPath = "/"
	}

	state := base64.URLEncoding.EncodeToString([]byte(redirectPath))

	return state
}

func getRedirectPATH(r *http.Request) string {
	state := r.URL.Query().Get("state")

	redirectPath, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		log.Printf("failed to decode state: %v", err)
		return "/"
	}

	return string(redirectPath)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := getState(r)
	url := googleOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code cannot be empty", http.StatusBadRequest)
		return
	}

	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get access token: %v", err), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token.AccessToken,
	})

	redirectURL := WEB_REDIRECT_URL + getRedirectPATH(r)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func GetGoogleUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := googleOauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	user, err := parseJSONFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{}
	if id, ok := user["sub"]; ok {
		userInfo.ID = id.(string)
	}
	if name, ok := user["name"]; ok {
		userInfo.Name = name.(string)
	}
	if email, ok := user["email"]; ok {
		userInfo.Email = email.(string)
	}
	if picture, ok := user["picture"]; ok {
		userInfo.Picture = picture.(string)
	}
	return userInfo, nil
}

func handleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	state := getState(r)
	url := facebookOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code cannot be empty", http.StatusBadRequest)
		return
	}

	token, err := facebookOauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get access token: %v", err), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token.AccessToken,
	})

	redirect_url := WEB_REDIRECT_URL + getRedirectPATH(r)
	http.Redirect(w, r, redirect_url, http.StatusTemporaryRedirect)
}

func GetFacebookUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := facebookOauthConfig.Client(ctx, token)
	resp, err := client.Get("https://graph.facebook.com/v2.12/me?fields=id,email,name,picture")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	user, err := parseJSONFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{}
	if id, ok := user["id"]; ok {
		userInfo.ID = (id.(string))
	}
	if name, ok := user["name"]; ok {
		userInfo.Name = (name.(string))
	}
	if email, ok := user["email"]; ok {
		userInfo.Email = (email.(string))
	}
	if picture, ok := user["picture"]; ok {
		if pictureMap, ok := picture.(map[string]interface{}); ok {
			if data, ok := pictureMap["data"].(map[string]interface{}); ok {
				if url, ok := data["url"].(string); ok {
					userInfo.Picture = (url)
				}
			}
		}
	}
	return userInfo, nil
}

func handleLineLogin(w http.ResponseWriter, r *http.Request) {
	state := getState(r)
	url := lineOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleLineCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code cannot be empty", http.StatusBadRequest)
		return
	}

	token, err := lineOauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get access token: %v", err), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token.AccessToken,
	})

	redirectURL := WEB_REDIRECT_URL + getRedirectPATH(r)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func GetLineUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := lineOauthConfig.Client(ctx, token)
	resp, err := client.Get("https://api.line.me/v2/profile")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	user, err := parseJSONFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{}
	if id, ok := user["userId"]; ok {
		userInfo.ID = (id.(string))
	}
	if name, ok := user["displayName"]; ok {
		userInfo.Name = (name.(string))
	}
	if picture, ok := user["pictureUrl"]; ok {
		userInfo.Picture = (picture.(string))
	}
	if email, ok := user["email"]; ok {
		userInfo.Email = (email.(string))
	}

	return userInfo, nil
}

func parseJSONFromReader(input io.Reader) (map[string]interface{}, error) {
	var result map[string]interface{}
	decoder := json.NewDecoder(input)
	err := decoder.Decode(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
