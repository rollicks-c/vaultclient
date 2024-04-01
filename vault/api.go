package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
)

type Client struct {
	authManager *authManager

	AppRoleAuth string // TODO
	JWTAuth     string // TODO
}

type Option func(c *Client)

func NewClient(addr string, options ...Option) (*Client, error) {

	// create api client
	vtClient, err := api.NewClient(&api.Config{
		Address: addr,
	})
	if err != nil {
		return nil, err
	}

	client := &Client{
		authManager: newAuthManager(vtClient),
	}
	for _, opt := range options {
		opt(client)
	}

	if client.authManager.tokenProvider == nil {
		return nil, fmt.Errorf("no token provider is set")
	}

	if err := client.verifyToken(); err != nil {
		return nil, err
	}

	return client, nil

}

func (c Client) verifyToken() error {
	return c.authManager.refreshToken()
}

func (c Client) SwitchVault(newAddr string) (*Client, error) {
	// create api client
	vtClient, err := api.NewClient(&api.Config{
		Address: newAddr,
	})
	if err != nil {
		return nil, err
	}

	client := &Client{
		authManager: newAuthManager(vtClient),
	}
	client.authManager.tokenProvider = c.authManager.tokenProvider

	return client, nil
}

func WithAppRole(roleID string, secretID string) Option {
	tp := tokenProviderAppRole{
		roleID:   roleID,
		secretID: secretID,
		authPath: "auth/approle/login",
	}
	return func(c *Client) {
		c.authManager.tokenProvider = tp
	}
}

func WithJWT(authPath, role, jwt string) Option {
	tp := &tokenProviderJWT{
		jwt:      jwt,
		role:     role,
		authPath: fmt.Sprintf("%s/login", authPath),
	}
	return func(c *Client) {
		c.authManager.tokenProvider = tp
	}
}

func WithToken(token string) Option {
	tp := &tokenProviderDirect{
		token:    token,
		prompter: nil,
	}
	return func(c *Client) {
		c.authManager.tokenProvider = tp
	}
}

func WithTokenPrompt(token string, prompter func() (string, error)) Option {
	tp := &tokenProviderDirect{
		token:    token,
		prompter: prompter,
	}
	return func(c *Client) {
		c.authManager.tokenProvider = tp
	}
}
