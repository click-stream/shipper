package input

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/devopsext/utils"
	"golang.org/x/oauth2"
)

var (
	oidcStateCookieName       = "oidc_state"
	oidcAccessTokenCookieName = "access_token"
	oidcRedirectToCookieName  = "redirect_to"
)

var refreshTokens = make(map[string]string)

type HttpOidc struct {
	options            *HttpInputOptions
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
	config             *oauth2.Config
	endSessionEndpoint string
	secretKey          string
}

func genRandomString() string {
	rnd := make([]byte, 32)
	rand.Read(rnd)
	return base64.URLEncoding.EncodeToString(rnd)
}

func hashStatecode(state, key, seed string) string {
	hashBytes := sha256.Sum256([]byte(state + key + seed))
	return hex.EncodeToString(hashBytes[:])
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func (o *HttpOidc) writeCookie(w http.ResponseWriter, name string, value string, expires time.Time) {

	c := &http.Cookie{
		Name:    name,
		Value:   value,
		Path:    o.options.HttpURL,
		Expires: expires,
	}

	http.SetCookie(w, c)
}

func (o *HttpOidc) readCookie(r *http.Request, name string) string {

	cookie, err := r.Cookie(name)
	if err == nil {
		return cookie.Value
	}
	return ""
}

func (o *HttpOidc) deleteCookie(w http.ResponseWriter, name string) {

	c := &http.Cookie{
		Name:    name,
		Value:   "",
		Path:    o.options.HttpURL,
		Expires: time.Unix(0, 0),
	}

	http.SetCookie(w, c)
}

func (o *HttpOidc) getAccessToken(r *http.Request) string {

	accessToken := r.Header.Get("Authorization")
	if !utils.IsEmpty(accessToken) {

		parts := strings.Split(accessToken, " ")
		if len(parts) != 2 {
			return ""
		}

		accessToken = parts[1]
	}

	if utils.IsEmpty(accessToken) {
		accessToken = o.readCookie(r, oidcAccessTokenCookieName)
	}

	return accessToken
}

func (o *HttpOidc) getDefaultURL() string {
	return fmt.Sprintf("%s%s", o.options.HttpURL, o.options.HttpOidcDefaultURL)
}

func (o *HttpOidc) getLoginURL() string {
	return fmt.Sprintf("%s%s", o.options.HttpURL, o.options.HttpOidcLoginURL)
}

func (o *HttpOidc) oidcCheck(callback func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		SetupCors(w,r)
		if r.Method == "OPTIONS" {

			w.WriteHeader(200)
			return
		}

		accessToken := o.getAccessToken(r)
		if utils.IsEmpty(accessToken) {

			acceptHeader := r.Header.Get("Accept")

			if strings.Contains(acceptHeader, "application/json") || r.Method == "POST" {

				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			o.writeCookie(w, oidcRedirectToCookieName, r.URL.RequestURI(), time.Now().Add(5*time.Minute))
			http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
			return
		}

		_, err := o.verifier.Verify(r.Context(), accessToken)
		if err != nil {
			http.Error(w, "Failed to verify id token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		callback(w, r)
	})
}

func (o *HttpOidc) oidcLogin(w http.ResponseWriter, r *http.Request) {

	accessToken := o.getAccessToken(r)
	if utils.IsEmpty(accessToken) {

		state := genRandomString()
		hashedState := hashStatecode(state, o.secretKey, o.options.HttpOidcClientSecret)
		o.writeCookie(w, oidcStateCookieName, hashedState, time.Now().Add(60*time.Second))
		http.Redirect(w, r, o.config.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
		return
	}

	_, err := o.verifier.Verify(r.Context(), accessToken)
	if err != nil {
		http.Error(w, "Failed to verify id token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, o.getDefaultURL(), http.StatusFound)
}

func (o *HttpOidc) oidcLogout(w http.ResponseWriter, r *http.Request) {

	accessToken := o.getAccessToken(r)
	if !utils.IsEmpty(accessToken) {

		o.deleteCookie(w, oidcAccessTokenCookieName)

		refreshToken := refreshTokens[accessToken]

		if !utils.IsEmpty(o.endSessionEndpoint) && !utils.IsEmpty(refreshToken) {

			data := fmt.Sprintf("client_id=%s&client_secret=%s&refresh_token=%s",
				o.options.HttpOidcClientId, o.options.HttpOidcClientSecret, refreshToken)
			reader := bytes.NewReader([]byte(data))

			req, err := http.NewRequest("POST", o.endSessionEndpoint, reader)
			if err != nil {
				log.Error(err)
				http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
				return
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := doRequest(r.Context(), req)
			if err != nil {
				log.Error(err)
				http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
				return
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Error(err)
				http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
				return
			}

			if resp.StatusCode < http.StatusOK && resp.StatusCode >= http.StatusMultipleChoices {
				log.Error(fmt.Errorf("%s: %s", resp.Status, body))
				http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
				return
			}
		}
	}

	http.Redirect(w, r, o.getLoginURL(), http.StatusFound)
}

func (o *HttpOidc) oidcCallback(w http.ResponseWriter, r *http.Request) {

	cookieState := o.readCookie(r, oidcStateCookieName)
	queryState := hashStatecode(r.URL.Query().Get("state"), o.secretKey, o.options.HttpOidcClientSecret)

	if cookieState != queryState {
		http.Error(w, "State did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := o.config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := o.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify id token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, err := o.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		Token    *oauth2.Token
		Claims   *json.RawMessage
		UserInfo *oidc.UserInfo
	}{oauth2Token, new(json.RawMessage), userInfo}

	if err := idToken.Claims(&resp.Claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshTokens[rawIDToken] = oauth2Token.RefreshToken

	o.deleteCookie(w, oidcStateCookieName)
	o.writeCookie(w, oidcAccessTokenCookieName, rawIDToken, idToken.Expiry)

	redirectTo := o.readCookie(r, oidcRedirectToCookieName)
	if utils.IsEmpty(redirectTo) {
		redirectTo = o.getDefaultURL()
	}

	o.deleteCookie(w, oidcRedirectToCookieName)

	http.Redirect(w, r, redirectTo, http.StatusFound)
}

type wellknownJSON struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

func getLogoutEndpoint(ctx context.Context, issuer string) string {

	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		log.Error(err)
		return ""
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		log.Error(err)
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return ""
	}

	if resp.StatusCode != http.StatusOK {
		log.Error(fmt.Errorf("%s: %s", resp.Status, body))
		return ""
	}

	var w wellknownJSON
	err = json.Unmarshal(body, &w)
	if err != nil {
		log.Error(err)
		return ""
	}

	return w.EndSessionEndpoint
}

func NewHttpOidc(options *HttpInputOptions) *HttpOidc {

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, options.HttpOidcConfigURL)
	if err != nil {
		log.Error(err)
		return nil
	}

	endSessionEndpoint := ""

	if !utils.IsEmpty(options.HttpOidcLogoutURL) {
		endSessionEndpoint = getLogoutEndpoint(ctx, options.HttpOidcConfigURL)
	}

	oidcConfig := &oidc.Config{
		ClientID: options.HttpOidcClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	var redirectUrl string

	if !utils.IsEmpty(options.HttpExternalHost) {

		redirectUrl = fmt.Sprintf("%s%s", options.HttpExternalHost, options.HttpOidcCallbackURL)

	} else {

		scheme := "http"
		if options.HttpTls {
			scheme = "https"
		}

		host := ""
		port := 80

		listen := options.HttpListen
		if !utils.IsEmpty(listen) {

			parts := strings.Split(listen, ":")
			if len(parts) > 1 {

				host = parts[0]
				p, err := strconv.Atoi(parts[1])
				if err == nil {
					port = p
				}
			}
		}

		if utils.IsEmpty(host) {
			host = "localhost"
		}

		hostPort := ""
		if (port == 80 && !options.HttpTls) || (port == 443 && options.HttpTls) {
			hostPort = host
		} else {
			hostPort = fmt.Sprintf("%s:%d", host, port)
		}

		redirectUrl = fmt.Sprintf("%s://%s%s%s", scheme, hostPort, options.HttpURL, options.HttpOidcCallbackURL)
	}

	scopes := []string{oidc.ScopeOpenID}

	parts := strings.Split(options.HttpOidcScopes, ",")
	for _, part := range parts {

		scopes = append(scopes, strings.TrimSpace(part))
	}

	oauth2Config := &oauth2.Config{
		ClientID:     options.HttpOidcClientId,
		ClientSecret: options.HttpOidcClientSecret,
		RedirectURL:  redirectUrl,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	o := HttpOidc{
		options:            options,
		provider:           provider,
		verifier:           verifier,
		config:             oauth2Config,
		secretKey:          genRandomString(),
		endSessionEndpoint: endSessionEndpoint,
	}

	return &o
}
