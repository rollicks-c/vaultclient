package ui

import (
	"fmt"
	"github.com/manifoldco/promptui"
	"strings"
)

func promptConfString(prompt, defaultValue string) (string, error) {

	dataPrompt := promptui.Prompt{
		Label:   fmt.Sprintf("%s (%s)", prompt, defaultValue),
		Default: defaultValue,
		Mask:    '*',
		Validate: func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("value required")
			}
			return nil
		},
	}
	value, err := dataPrompt.Run()
	if err != nil {
		return "", err
	}
	return value, nil

}
