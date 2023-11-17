package client

import (
	"github.com/pkg/errors"
	"strings"
)

type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// Error spits out errors from the Vault API (gotta be a better way to do this?)
func (e *ErrorResponse) Error() error {
	if len(e.Errors) > 0 {
		return errors.New(strings.Join(e.Errors, "; "))
	}

	return nil
}

func VaultErrorString(resp *ErrorResponse) string {
	if len(resp.Errors) > 0 {
		return resp.Error().Error()
	}

	return ""
}
