package oauth1

import (
	"context"
	"fmt"

	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
	twitterOAuth1 "github.com/dghubble/oauth1/twitter"
)

// TwitterProvider is a helper function to created a twitter oauth1 provider
func TwitterProvider(key, secret string) Provider {
	return Provider{
		Config: &oauth1.Config{
			ConsumerKey:    key,
			ConsumerSecret: secret,
			Endpoint:       twitterOAuth1.AuthenticateEndpoint,
		},
		FindUserDetails: TwitterFindUserDetails,
	}
}

// TwitterFindUserDetails will go to Twitter and access basic information about the user.
func TwitterFindUserDetails(ctx context.Context, config oauth1.Config, token oauth1.Token) (map[string]string, error) {
	t := true

	data := make(map[string]string)

	httpClient := config.Client(ctx, &token)
	client := twitter.NewClient(httpClient)

	user, _, err := client.Accounts.VerifyCredentials(&twitter.AccountVerifyParams{
		SkipStatus:   &t,
		IncludeEmail: &t,
	})
	if err != nil {
		return data, fmt.Errorf("error getting twitter user details: %w", err)
	}

	data["id"] = user.IDStr
	data["email"] = user.Email

	return data, err
}
