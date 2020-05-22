# OAuth1 Module for [Authboss](https://github.com/volatiletech/authboss)

## User Auth via OAuth1

| Info and Requirements |          |
| --------------------- | -------- |
Module        | oauth1
Pages         | _None_
Routes        | /oauth1/{provider}, /oauth1/callback/{provider}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [OAuth1ServerStorer](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#ServerStorer)
User          | [OAuth1User](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#User)
Values        | _None_
Mailer        | _None_

This is a tougher implementation than most modules because there's a lot going on. In addition to the
requirements stated above, you must also configure the `oauth1.Providers`. It's a public variable in the module.

```go
import oauth1 "github.com/stephenafamo/authboss-oauth1"

oauth1.Providers = map[string]oauth1.Provider{}
```

The providers require an oauth1 configuration that's typical for the Go oauth1 package, but in addition
to that they need a `FindUserDetails` method which has to take the token that's retrieved from the oauth1
provider, and call an endpoint that retrieves details about the user (at LEAST user's uid).
These parameters are returned in `map[string]string` form and passed into the `oauth1.ServerStorer`.

Please see the following documentation for more details:

* [Package docs for oauth1](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1)
* [oauth1.Provider](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#Provider)
* [oauth1.ServerStorer](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1/#OAuth1ServerStorer)
