package vaultclient

import (
	"github.com/rollicks-c/vaultclient/vault"
)

func NewClient(addr string, options ...vault.Option) (*vault.Client, error) {
	return vault.NewClient(addr, options...)
}
