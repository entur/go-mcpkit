package mcpkit

import (
	"errors"
	"net/http"
	"strings"
)

type accessKind uint8

const (
	accessUnset accessKind = iota
	accessProtected
	accessPublic
	accessLocal
)

func (k accessKind) String() string {
	switch k {
	case accessProtected:
		return "protected"
	case accessPublic:
		return "public-read-only"
	case accessLocal:
		return "local-process"
	}
	return "unset"
}

// Access is an endpoint's access posture. Its zero value is refused, so every
// endpoint states who may reach it and why.
type Access struct {
	kind   accessKind
	reason string
	auth   func(http.Handler) http.Handler
}

// Protected serves the endpoint over HTTP behind auth, the application's
// authentication wrapper. reason says who is admitted.
func Protected(auth func(http.Handler) http.Handler, reason string) Access {
	return Access{kind: accessProtected, reason: reason, auth: auth}
}

// PublicReadOnly serves open data to anyone, over HTTP or stdio. reason says
// why no authentication is needed.
func PublicReadOnly(reason string) Access { return Access{kind: accessPublic, reason: reason} }

// LocalProcess serves the endpoint only over stdio to the process that
// started it, never over HTTP. reason says why.
func LocalProcess(reason string) Access { return Access{kind: accessLocal, reason: reason} }

func (a Access) validate() error {
	switch {
	case a.kind == accessUnset:
		return errors.New("no access posture")
	case strings.TrimSpace(a.reason) == "":
		return errors.New("access posture has no reason")
	case a.kind == accessProtected && a.auth == nil:
		return errors.New("Protected access has no authentication wrapper")
	}
	return nil
}
