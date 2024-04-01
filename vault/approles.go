package vault

import (
	"fmt"
	"strings"
)

func (c Client) CreateAppRole(roleName, ttl, maxTTL string, policies ...string) (string, string, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return "", "", err
	}

	// prepare request
	path := fmt.Sprintf("%s/role/%s", c.AppRoleAuth, roleName)
	args := map[string]any{
		"token_ttl":     ttl,
		"token_max_ttl": maxTTL,
		"policies":      strings.Join(policies, ","),
	}

	// create role
	if _, err := vt.Logical().Write(path, args); err != nil {
		return "", "", err
	}

	// retrieve role and secret ID
	roleID, err := c.requestRoleID(roleName)
	if err != nil {
		return "", "", err
	}
	secretID, err := c.createSecretID(roleName)
	if err != nil {
		return "", "", err
	}

	// found
	return roleID, secretID, err

}

func (c Client) requestRoleID(roleName string) (string, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return "", err
	}

	// request role-id
	path := fmt.Sprintf("%s/role/%s/role-id", c.AppRoleAuth, roleName)
	res, err := vt.Logical().Read(path)
	if err != nil {
		return "", err
	}

	// unpack
	record, ok := res.Data["role_id"]
	if !ok {
		return "", fmt.Errorf("failed to retrieve role-id")
	}

	return record.(string), nil

}

func (c Client) createSecretID(roleName string) (string, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return "", err
	}

	// create secret-id
	path := fmt.Sprintf("%s/role/%s/secret-id", c.AppRoleAuth, roleName)
	args := map[string]any{}
	res, err := vt.Logical().Write(path, args)
	if err != nil {
		return "", err
	}

	// unpack
	record, ok := res.Data["secret_id"]
	if !ok {
		return "", fmt.Errorf("failed to retrieve secret-id")
	}

	return record.(string), nil

}
