package cli

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"golang.org/x/term"
)

type AdminCommands struct {
	auth       *auth.Service
	readSecret func(string) (string, error)
	readLine   func(string) (string, error)
	out        io.Writer
	inputTTY   bool
	outputTTY  bool
}

func NewAdminCommands(service *auth.Service, input *os.File, output io.Writer) *AdminCommands {
	readSecret := func(prompt string) (string, error) {
		fd := int(input.Fd())
		if !term.IsTerminal(fd) {
			return "", errors.New("secret input requires an interactive terminal")
		}
		if _, err := fmt.Fprint(output, prompt); err != nil {
			return "", err
		}
		value, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(output)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
		defer clear(value)
		return string(value), nil
	}
	reader := bufio.NewReader(input)
	readLine := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(output, prompt); err != nil {
			return "", err
		}
		value, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(value), nil
	}
	outputFile, outputIsFile := output.(*os.File)
	return newAdminCommandsWithTerminals(service, readSecret, readLine, output,
		term.IsTerminal(int(input.Fd())), outputIsFile && term.IsTerminal(int(outputFile.Fd())))
}

func newAdminCommands(service *auth.Service, readSecret func(string) (string, error), readLine func(string) (string, error), output io.Writer) *AdminCommands {
	return newAdminCommandsWithTerminals(service, readSecret, readLine, output, true, true)
}

func newAdminCommandsWithTerminals(service *auth.Service, readSecret func(string) (string, error), readLine func(string) (string, error), output io.Writer, inputTTY, outputTTY bool) *AdminCommands {
	return &AdminCommands{auth: service, readSecret: readSecret, readLine: readLine, out: output, inputTTY: inputTTY, outputTTY: outputTTY}
}

func (c *AdminCommands) Run(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tompanel admin reset-password|set-username|reset-totp")
	}
	if !c.inputTTY {
		return errors.New("input requires an interactive terminal")
	}
	if !c.outputTTY {
		return errors.New("output requires an interactive terminal")
	}
	switch args[0] {
	case "reset-password":
		password, err := c.readSecret("New password: ")
		if err != nil {
			return err
		}
		confirmation, err := c.readSecret("Confirm new password: ")
		if err != nil {
			return err
		}
		if !constantStringEqual(password, confirmation) {
			return errors.New("passwords do not match")
		}
		if err := c.auth.ResetPassword(ctx, 1, password); err != nil {
			return err
		}
		_, err = fmt.Fprintln(c.out, "Password reset; all sessions and recovery codes were invalidated.")
		return err
	case "set-username":
		username, err := c.readLine("New username: ")
		if err != nil {
			return err
		}
		if err := c.auth.SetUsername(ctx, 1, username); err != nil {
			return err
		}
		_, err = fmt.Fprintln(c.out, "Username updated; all sessions and recovery codes were invalidated.")
		return err
	case "reset-totp":
		confirmation, err := c.readLine("Type RESET TOTP to continue: ")
		if err != nil {
			return err
		}
		if confirmation != "RESET TOTP" {
			return errors.New("TOTP reset confirmation did not match")
		}
		enrollment, err := c.auth.ResetTOTP(ctx, 1)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.out, "TOTP secret: %s\nTOTP URI: %s\nRecovery codes (save these now):\n", enrollment.TOTPSecret, enrollment.TOTPURI); err != nil {
			return err
		}
		for _, code := range enrollment.RecoveryCodes {
			if _, err := fmt.Fprintln(c.out, code); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintln(c.out, "All previous sessions and recovery codes were invalidated.")
		return err
	default:
		return errors.New("usage: tompanel admin reset-password|set-username|reset-totp")
	}
}

func constantStringEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
