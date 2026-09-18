package policy

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
)

// Authenticator provides protocol-neutral authentication checks for the
// gateway. It deliberately exposes verification operations, never passwords.
type Authenticator struct {
	username string
	password string
	realm    string
}

func NewAuthenticator(spec config.AuthConfig) (*Authenticator, error) {
	if spec.Type == "none" {
		return nil, nil
	}
	password, ok := os.LookupEnv(spec.PasswordEnv)
	if !ok {
		return nil, errors.New("basic auth password environment variable is not set")
	}
	realm := spec.Realm
	if realm == "" {
		realm = "vpnfront"
	}
	return &Authenticator{username: spec.Username, password: password, realm: realm}, nil
}

func (a *Authenticator) Required() bool { return a != nil }

func (a *Authenticator) AuthenticateHTTP(request *http.Request) bool {
	if a == nil {
		return true
	}
	username, password, ok := ParseBasicProxyAuthorization(request.Header.Get("Proxy-Authorization"))
	return ok && a.matches(username, password)
}

func (a *Authenticator) AuthenticateSOCKS5(username, password string) bool {
	return a != nil && a.matches(username, password)
}

func (a *Authenticator) HTTPChallenge() string {
	if a == nil {
		return ""
	}
	return `Basic realm="` + a.realm + `"`
}

func (a *Authenticator) matches(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1
	return userOK && passwordOK
}

func ParseBasicProxyAuthorization(value string) (username, password string, ok bool) {
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", "", false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", false
	}
	return credentials[0], credentials[1], true
}
