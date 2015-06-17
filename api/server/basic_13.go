package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/Sirupsen/logrus"
)

// basicAuth does what Request.BasicAuth() does in go 1.4 and later: it returns
// the parsed user name, password, and a boolean indicating whether or not
// parsing was successful.
func basicAuth(r *http.Request) (user, pass string, ok bool) {
	for _, header := range r.Header[http.CanonicalHeaderKey("Authorization")] {
		ah := strings.SplitN(strings.Replace(header, "\t", " ", -1), " ", 2)
		if ah[0] == "Basic" {
			basic, err := base64.StdEncoding.DecodeString(ah[1])
			if err != nil {
				logrus.Warnf("%v: could not decode client Basic data", err)
				return
			}
			colon := bytes.IndexAny(basic, ":")
			if colon < 0 {
				logrus.Warnf("client Basic data is malformed")
				return
			}
			return string(basic[0:colon]), string(basic[colon+1:]), true
		}
	}
	return
}
