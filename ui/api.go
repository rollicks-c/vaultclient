package ui

import (
	"fmt"
	"os/exec"
	"runtime"
)

func CreateVaultTokenPrompter(vaultAddr string) func() (string, error) {

	return func() (string, error) {
		if err := OpenURL(vaultAddr); err != nil {
			return "", err
		}
		for {
			newToken, err := promptConfString("grab vault token and enter here", "")
			if err != nil {
				return "", err
			}
			if newToken == "" {
				continue
			}

			return newToken, nil
		}
	}

}

func OpenURL(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Run()
}
