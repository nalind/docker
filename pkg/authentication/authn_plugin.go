package authentication

import (
	"net/http"
)

// PluginImplements is the type of subsystem plugin that we look for.
const (
	PluginImplements          = "Authentication"
	AuthenticationRequestName = PluginImplements + ".Authenticate"
)

// User represents an authenticated remote user.  We know at least one of the
// user's name (if not "") and UID (if HaveUID is true), and possibly both.
type User struct {
	Name    string    `json:",omitempty"`
	HaveUID bool      `json:",omitempty"`
	UID     uint32    `json:",omitempty"`
	Groups  *[]string `json:",omitempty"`
	Scheme  string    `json:",omitempty"`
}

// AuthnPluginRequest is the structure that we pass to an authentication
// plugin.  It contains the incoming request's method, the Scheme, Path,
// Fragment, RawQuery, and RawPath fields of the request's net.http.URL, stored
// in a map, the hostname, all of the request's headers, the peer's certificate
// if the connection provided a verified client certificate, and the
// authentication options which were passed to the daemon at startup.
type AuthnPluginRequest struct {
	Method      string            `json:",omitempty"`
	URL         map[string]string `json:",omitempty"`
	Host        string            `json:",omitempty"`
	Header      http.Header       `json:",omitempty"`
	Certificate []byte            `json:",omitempty"`
	Options     map[string]string `json:",omitempty"`
}

// AuthnPluginResponse is the structure that we get back from an authentication
// plugin.  If authentication suceeded, it contains information about the
// authenticated user.  If authentication succeeded, only header values
// returned by the plugin which succeeded will be included in the response
// which is sent to the client.  If authentication fails, all headers returned
// by all called plugins will be included in the response.
type AuthnPluginResponse struct {
	AuthedUser User        `json:",omitempty"`
	Header     http.Header `json:",omitempty"`
}
