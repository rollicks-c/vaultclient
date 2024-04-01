package vault

import (
	"encoding/json"
	"fmt"
)

type JWTRoleConfig struct {
	RoleType            string         `json:"role_type"`
	Policies            []string       `json:"policies"`
	TokenTTL            string         `json:"token_ttl"`
	TokenExplicitMaxTTL string         `json:"token_explicit_max_ttl"`
	UserClaim           string         `json:"user_claim"`
	BoundClaims         JWTBoundClaims `json:"bound_claims"`
}

type JWTBoundClaims struct {
	UserEmail    []string `json:"user_email"`
	UserId       []string `json:"user_id,omitempty"`
	RefProtected string   `json:"ref_protected"`
	RefType      string   `json:"ref_type"`
	Ref          []string `json:"ref"`
	NamespaceID  string   `json:"namespace_id,omitempty"`
}

func (c Client) WriteJWTRole(roleName string, roleConfig JWTRoleConfig) error {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return err
	}

	// prepare request
	path := fmt.Sprintf("%s/role/%s", c.JWTAuth, roleName)
	argsRaw, err := c.toGenericStruct(roleConfig)
	if err != nil {
		return err
	}

	// create role
	if _, err := vt.Logical().Write(path, argsRaw); err != nil {
		return err
	}

	return nil

}

func (c Client) ReadJWTRoleClaims(roleName string) (JWTBoundClaims, error) {

	// read config
	path := fmt.Sprintf("%s/role/%s", c.JWTAuth, roleName)
	res, ok, err := c.ReadValue(path, "bound_claims")
	if err != nil {
		return JWTBoundClaims{}, err
	}
	if !ok {
		return JWTBoundClaims{}, nil
	}

	// extract data
	raw, err := json.Marshal(res)
	if err != nil {
		return JWTBoundClaims{}, err
	}
	claims := JWTBoundClaims{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return JWTBoundClaims{}, err
	}

	return claims, nil
}

func (c Client) toGenericStruct(data interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	mapData := map[string]interface{}{}
	if err := json.Unmarshal(raw, &mapData); err != nil {
		return nil, err
	}
	return mapData, nil
}
