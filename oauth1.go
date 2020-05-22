// Package oauth1 allows users to be created and authenticated
// via oauth1 services like facebook, google etc. Currently
// only the web server flow is supported.
//
// The general flow looks like this:
//   1. User goes to Start handler and has his session packed with goodies
//      then redirects to the OAuth service.
//   2. OAuth service returns to OAuthCallback which checks that everything is ok. It uses the
//      token received to get an access token and secret from the oauth1 library
//   3. Calls the OAuth1Provider.FindUserDetails which should return the user's
//      details in a generic form.
//   4. Passes the user details into the ServerStorer.NewFromOAuth1 in
//      order to create a user object we can work with.
//   5. Saves the user in the database, logs them in, redirects.
//
// In order to do this there are a number of parts:
//   1. The configuration of a provider
//      (handled by OAuth1Providers).
//   2. The flow of redirection of client, parameter passing etc
//      (handled by this package)
//   3. The HTTP call to the service once a token has been retrieved to
//      get user details (handled by OAuth1Provider.FindUserDetails)
//   4. The creation of a user from the user details returned from the
//      FindUserDetails (authboss.ServerStorer)
//
// Of these parts, the responsibility of the authboss library consumer
// is on 1, 3, and 4. Configuration of providers that should be used is totally
// up to the consumer. The FindUserDetails function is typically up to the
// user, but we have some basic ones included in this package too.
// The creation of users from the FindUserDetail's map[string]string return
// is handled as part of the implementation of the ServerStorer.
package oauth1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dghubble/oauth1"

	"github.com/volatiletech/authboss"
)

// FormValue constants
const (
	// SessionOAuth1Secret is the request secret created during the login flow.
	SessionOAuth1Secret = "oauth1_secret"
	// SessionOAuth1Params is the additional settings for oauth
	// like redirection/remember.
	SessionOAuth1Params = "oauth1_params"
	// EventOAuth1Fail For Authboss events
	EventOAuth1     authboss.Event = 23
	EventOAuth1Fail authboss.Event = 24

	FormValueOAuth1Redir = "redir"
)

var (
	// Providers are the registered OAuth1 providers
	Providers = make(map[string]Provider)
	// LoginOK is the path to redirec to on a successful login
	LoginOK = "/"
	// LoginNotOK is the path to redirec to on a failed login
	LoginNotOK = "/"

	errOAuthStateValidation = fmt.Errorf("could not validate oauth1 state param")
)

// Provider represents all we need to register an OAuth1 Provider
type Provider struct {
	Config           *oauth1.Config
	AdditionalParams url.Values
	FindUserDetails  func(context.Context, oauth1.Config, oauth1.Token) (map[string]string, error)
}

// Config is the configuration for oauth1
type Config = oauth1.Config

// Token represents an access token
type Token = oauth1.Token

// OAuth1 module
type OAuth1 struct {
	*authboss.Authboss
}

func init() {
	authboss.RegisterModule("oauth1", &OAuth1{})
}

// Init module
func (o *OAuth1) Init(ab *authboss.Authboss) error {
	o.Authboss = ab

	// Do annoying sorting on keys so we can have predictible
	// route registration (both for consistency inside the router but
	// also for tests -_-)
	var keys []string
	for k := range Providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, provider := range keys {
		cfg := Providers[provider]
		provider = strings.ToLower(provider)

		init := fmt.Sprintf("/oauth1/%s", provider)
		callback := fmt.Sprintf("/oauth1/callback/%s", provider)

		o.Authboss.Config.Core.Router.Get(init, o.Authboss.Core.ErrorHandler.Wrap(o.Start))
		o.Authboss.Config.Core.Router.Get(callback, o.Authboss.Core.ErrorHandler.Wrap(o.End))

		if mount := o.Authboss.Config.Paths.Mount; len(mount) > 0 {
			callback = path.Join(mount, callback)
		}

		cfg.Config.CallbackURL = o.Authboss.Config.Paths.RootURL + callback
	}

	return nil
}

// Start the oauth1 process
func (o *OAuth1) Start(w http.ResponseWriter, r *http.Request) error {
	logger := o.Authboss.RequestLogger(r)

	provider := strings.ToLower(filepath.Base(r.URL.Path))
	logger.Infof("started oauth1 flow for provider: %s", provider)
	cfg, ok := Providers[provider]
	if !ok {
		return fmt.Errorf("oauth1 provider %q not found", provider)
	}

	// This clearly ignores the fact that query parameters can have multiple
	// values but I guess we're ignoring that
	passAlongs := make(map[string]string)
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs[k] = val
		}
	}

	if len(passAlongs) > 0 {
		byt, err := json.Marshal(passAlongs)
		if err != nil {
			return err
		}
		authboss.PutSession(w, SessionOAuth1Params, string(byt))
	} else {
		authboss.DelSession(w, SessionOAuth1Params)
	}

	reqToken, reqSecret, err := cfg.Config.RequestToken()
	if err != nil {
		return fmt.Errorf("failed to get request token: %w", err)
	}
	authboss.PutSession(w, SessionOAuth1Secret, reqSecret) // save secret in session
	authCodeURL, err := cfg.Config.AuthorizationURL(reqToken)
	for key, vals := range cfg.AdditionalParams {
		for _, val := range vals {
			authCodeURL.Query().Add(key, val)
		}
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: authCodeURL.String(),
	}
	return o.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// End the oauth1 process, this is the handler for the oauth1 callback
// that the third party will redirect to.
func (o *OAuth1) End(w http.ResponseWriter, r *http.Request) error {
	logger := o.Authboss.RequestLogger(r)
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	logger.Infof("finishing oauth1 flow for provider: %s", provider)

	// This shouldn't happen because the router should 404 first, but just in case
	cfg, ok := Providers[provider]
	if !ok {
		return fmt.Errorf("oauth1 provider %q not found", provider)
	}

	rawParams, ok := authboss.GetSession(r, SessionOAuth1Params)
	var params map[string]string
	if ok {
		if err := json.Unmarshal([]byte(rawParams), &params); err != nil {
			return fmt.Errorf("failed to decode oauth1 params: %w", err)
		}
	}
	authboss.DelSession(w, SessionOAuth1Params)

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		reason := r.FormValue("error_reason")
		logger.Infof("oauth1 login failed: %s, reason: %s", hasErr, reason)

		handled, err := o.Authboss.Events.FireAfter(EventOAuth1Fail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: LoginNotOK,
			Failure:      fmt.Sprintf("%s login cancelled or failed", strings.Title(provider)),
		}
		return o.Authboss.Core.Redirector.Redirect(w, r, ro)
	}

	reqToken, verifier, err := oauth1.ParseAuthorizationCallback(r)
	if err != nil {
		return fmt.Errorf("could not parse oauth1 authorization callback: %w", err)
	}

	reqSecret, ok := authboss.GetSession(r, SessionOAuth1Secret)
	if !ok {
		return fmt.Errorf("could not get oauth1 req secret from session")
	}
	authboss.DelSession(w, SessionOAuth1Secret)

	// Get the code which we can use to make an access token and secret
	accessToken, accessSecret, err := cfg.Config.AccessToken(reqToken, reqSecret, verifier)

	details, err := cfg.FindUserDetails(r.Context(), *cfg.Config, oauth1.Token{
		Token:       accessToken,
		TokenSecret: accessSecret,
	})
	if err != nil {
		return err
	}

	storer := EnsureCanOAuth1(o.Authboss.Config.Storage.Server)
	user, err := storer.NewFromOAuth1(r.Context(), provider, details)
	if err != nil {
		return fmt.Errorf("failed to create oauth1 user from values: %w", err)
	}

	user.PutOAuth1AccessToken(accessToken)
	user.PutOAuth1AccessSecret(accessSecret)

	if err := storer.SaveOAuth1(r.Context(), user); err != nil {
		return err
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	handled, err := o.Authboss.Events.FireBefore(EventOAuth1, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	// Fully log user in
	authboss.PutSession(w, authboss.SessionKey, user.GetPID())
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	// Create a query string from all the pieces we've received
	// as passthru from the original request.
	redirect := LoginOK
	query := make(url.Values)
	for k, v := range params {
		switch k {
		case authboss.CookieRemember:
			if v == "true" {
				r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, RMTrue{}))
			}
		case FormValueOAuth1Redir:
			redirect = v
		default:
			query.Set(k, v)
		}
	}

	handled, err = o.Authboss.Events.FireAfter(EventOAuth1, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	if len(query) > 0 {
		redirect = fmt.Sprintf("%s?%s", redirect, query.Encode())
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: redirect,
		Success:      fmt.Sprintf("Logged in successfully with %s.", strings.Title(provider)),
	}
	return o.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// RMTrue is a dummy struct implementing authboss.RememberValuer
// in order to tell the remember me module to remember them.
type RMTrue struct{}

// GetShouldRemember always returns true
func (RMTrue) GetShouldRemember() bool { return true }

// EnsureCanOAuth1 makes sure the server storer supports
// oauth1 creation and lookup
func EnsureCanOAuth1(storer authboss.ServerStorer) ServerStorer {
	s, ok := storer.(ServerStorer)
	if !ok {
		panic("could not upgrade ServerStorer to oauth1.ServerStorer, check your struct")
	}

	return s
}

// ServerStorer has the ability to create users from data from the provider.
type ServerStorer interface {
	authboss.ServerStorer

	// NewFromOAuth1 should return an OAuth1User from a set
	// of details returned from OAuth1Provider.FindUserDetails
	// A more in-depth explanation is that once we've got an access token
	// for the service in question (say a service that rhymes with book)
	// the FindUserDetails function does an http request to a known endpoint
	// that provides details about the user, those details are captured in a
	// generic way as map[string]string and passed into this function to be
	// turned into a real user.
	//
	// It's possible that the user exists in the database already, and so
	// an attempt should be made to look that user up using the details.
	// Any details that have changed should be updated. Do not save the user
	// since that will be done later by ServerStorer.SaveOAuth1()
	NewFromOAuth1(ctx context.Context, provider string, details map[string]string) (User, error)

	// SaveOAuth1 has different semantics from the typical ServerStorer.Save,
	// in this case we want to insert a user if they do not exist.
	// The difference must be made clear because in the non-oauth1 case,
	// we know exactly when we want to Create vs Update. However since we're
	// simply trying to persist a user that may have been in our database,
	// but if not should already be (since you can think of the operation as
	// a caching of what's on the oauth1 provider's servers).
	SaveOAuth1(ctx context.Context, user User) error
}

// User allows reading and writing values relating to OAuth1
type User interface {
	authboss.User

	// IsOAuth1User checks to see if a user was registered in the site as an
	// oauth1 user.
	IsOAuth1User() bool

	GetOAuth1UID() (uid string)
	GetOAuth1Provider() (provider string)
	GetOAuth1AccessToken() (token string)
	GetOAuth1AccessSecret() (secret string)

	PutOAuth1AccessToken(token string)
	PutOAuth1AccessSecret(secret string)
}
