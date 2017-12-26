package osin

// Client information
type Client interface {
	// Client id
	GetID() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectURI() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// ClientSecretMatcher is an optional interface clients can implement
// which allows them to be the one to determine if a secret matches.
// If a Client implements ClientSecretMatcher, the framework will never call GetSecret
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	ClientSecretMatches(secret string) bool
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    interface{}
}

func (d *DefaultClient) GetID() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetRedirectURI() string {
	return d.RedirectUri
}

func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

// Implement the ClientSecretMatcher interface
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.Id = client.GetID()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectURI()
	d.UserData = client.GetUserData()
}
