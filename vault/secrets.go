package vault

import (
	"fmt"
	"strings"
)

type Secret struct {
	data     map[string]interface{}
	metaData map[string]interface{}
}

func newSecret(source map[string]interface{}) (*Secret, error) {
	data, ok := source["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret")
	}
	metaData, ok := source["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret")
	}
	return &Secret{
		data:     data,
		metaData: metaData,
	}, nil
}

type SecretsProvider Client

func (c Client) AsProvider() SecretsProvider {
	return SecretsProvider(c)
}

func (p SecretsProvider) LoadSecret(uri string) (string, error) {
	secret, err := p.LoadSecret(uri)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", secret), nil

}

func (s Secret) GetItem(key string) (string, bool) {
	data, ok := s.data[key].(string)
	if !ok {
		return "", false
	}
	return data, true
}

func (s Secret) GetItemFuzzy(exp string) (string, string, bool) {

	// find candidates
	keyList := []string{}
	for k := range s.data {
		if strings.HasPrefix(k, exp) {
			keyList = append(keyList, k)
		}
	}
	if len(keyList) == 0 {
		return "", "", false
	}
	if len(keyList) > 1 {
		return "", "", false
	}

	// lookup
	value, ok := s.GetItem(keyList[0])
	if !ok {
		return "", "", false
	}
	return keyList[0], value, true

}

func (c Client) LoadSecret(path string) (*Secret, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return nil, err
	}

	// apply path options
	path = c.fixDataPathForV2(path)

	// retrieve secret
	res, err := vt.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	// not found
	if res == nil {
		return nil, nil
	}

	// unpack
	secret, err := newSecret(res.Data)
	if err != nil {
		return nil, err
	}

	// found
	return secret, nil

}

func (c Client) ListSecret(path string) ([]string, error) {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return nil, err
	}

	// apply path options
	path = c.fixMetaPathForV2(path)

	// retrieve secret
	res, err := vt.Logical().List(path)
	if err != nil {
		return nil, err
	}

	// not found
	if res == nil {
		return nil, fmt.Errorf("no value found at [%s]", path)
	}

	// unpack
	DataRaw, ok := res.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("invalid secret: %s", path)
	}
	data := DataRaw.([]interface{})
	keys := make([]string, 0, len(data))
	for _, k := range data {
		keys = append(keys, k.(string))
	}

	// found
	return keys, nil

}

func (c Client) WriteSecret(path string, data map[string]interface{}) error {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return err
	}

	// pack secret
	payload := map[string]interface{}{
		"data": data,
	}

	// apply path options
	path = c.fixDataPathForV2(path)

	// write secret
	if _, err := vt.Logical().Write(path, payload); err != nil {
		return err
	}

	return nil

}

func (c Client) DeleteSecret(path string) error {

	// login to vault
	vt, err := c.authManager.getClient()
	if err != nil {
		return err
	}

	// apply path options
	//path = c.fixDataPathForV2(path)
	path = c.fixMetaPathForV2(path)

	// remove secret
	if _, err := vt.Logical().Delete(path); err != nil {
		return err
	}

	return nil

}

func (c Client) ReadValue(path, field string) (interface{}, bool, error) {

	vt, err := c.authManager.getClient()
	if err != nil {
		return nil, false, err
	}

	// retrieve secret
	res, err := vt.Logical().Read(path)
	if err != nil {
		return nil, false, err
	}

	// not found
	if res == nil {
		return nil, false, nil
	}

	// extract
	value, ok := res.Data[field]
	if !ok {
		return nil, false, fmt.Errorf("field %s not found at %s", field, path)
	}

	// found
	return value, true, nil

}

func (c Client) fixDataPathForV2(secretPath string) string {
	secretPath = strings.TrimPrefix(secretPath, "/")
	parts := strings.Split(secretPath, "/")
	parts = append([]string{parts[0], "data"}, parts[1:]...)
	secretPath = strings.Join(parts, "/")
	return secretPath
}

func (c Client) fixMetaPathForV2(secretPath string) string {
	secretPath = strings.TrimPrefix(secretPath, "/")
	parts := strings.Split(secretPath, "/")
	parts = append([]string{parts[0], "metadata"}, parts[1:]...)
	secretPath = strings.Join(parts, "/")
	return secretPath
}
