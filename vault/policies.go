package vault

import "fmt"

func (c Client) ListPolicies() ([]string, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return nil, err
	}

	pl := make([]string,0)

	policies, err := vt.Sys().ListPolicies()
	if err != nil {
		return nil, err
	}
	for _, policyName := range policies {
		policy, err := vt.Sys().GetPolicy(policyName)
		if err != nil {
			return nil, err
		}
		print := fmt.Sprintf("Policy: %s\nContents:\n%s\n", policyName, policy)
		pl = append(pl, print)
	}

	return pl, nil

}
