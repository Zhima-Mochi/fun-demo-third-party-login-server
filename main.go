package main

import (
	"context"
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
)

func init() {
	ip, err := getCurrentPublicIP()
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	url := fmt.Sprintf("http://%s:%s", ip, port)

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
}
func getCurrentPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

func main() {
	http.HandleFunc("/login/google", handleGoogleLogin)
	http.HandleFunc("/callback/google", handleGoogleCallback)
	http.HandleFunc("/login/facebook", handleFacebookLogin)
	http.HandleFunc("/callback/facebook", handleFacebookCallback)
	http.HandleFunc("/login/line", handleLineLogin)
	http.HandleFunc("/callback/line", handleLineCallback)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
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

	userInfo, err := GetGoogleUserInfo(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
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
	url := facebookOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
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

	userInfo, err := GetFacebookUserInfo(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
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
	url := lineOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
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

	userInfo, err := GetLineUserInfo(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
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
