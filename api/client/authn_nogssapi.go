// +build !linux !cgo static_build !gssapi

package client

import (
	"github.com/docker/engine-api/client/authn"
)

func NewGSSAuth() authn.AuthResponder {
	return nil
}
