package lib

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
)

// authnOpts is the set of authentication-related options which the client
// should be using.
type authnOpts struct {
}

// authResponder is an interface that wraps the scheme,
// authRespond, and authCompleted methods.
//
// At initialization time, an implementation of authResponder should register
// itself by calling registerAuthResponder.
type authResponder interface {
	// Scheme should return the name of the authorization scheme for which
	// the responder should be called.
	scheme() string
	// authRespond, given the authentication header value associated with
	// the scheme that it implements, can decide if the request should be
	// retried.  If it returns true, then the request is retransmitted to
	// the server, presumably because it has added an authentication header
	// which it believes the server will accept.
	authRespond(cli *Client, challenge string, req *http.Request) (bool, error)
	// AuthCompleted, given a (possibly empty) WWW-Authenticate header and
	// a successful response, should decide if the server's reply should be
	// accepted.
	authCompleted(cli *Client, challenge string, resp *http.Response) (bool, error)
}

// authResponderCreator either creates a new authResponder, or returns nil
type authResponderCreator func() authResponder

var authResponderCreators = []authResponderCreator{}

// registerAuthResponder registers a function which will be called at startup
// to create an authResponder.
func registerAuthResponder(arc authResponderCreator) {
	authResponderCreators = append(authResponderCreators, arc)
}

// Run through all of the registered responder creators and build a map of
// names-to-responders.
func createAuthResponders() map[string]authResponder {
	ars := make(map[string]authResponder)
	for _, arc := range authResponderCreators {
		responder := arc()
		if responder != nil {
			scheme := strings.ToLower(responder.scheme())
			ars[scheme] = responder
		}
	}
	return ars
}

// doer is just an interface wrapper that we use to be able to Do() using
// either an http.Client or an httputil.Clientconn.
type doer interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// Run the Doer's Do() method, setting and saving cookies.  An http.Client
// would handle this for us if we passed in a cookie jar when we initialized
// it, but we'd still have to do the work for httputil.ClientConn, so we don't
// set it for http.Clients to avoid duplicating cookies in requests.
func (cli *Client) doWithCookies(doer doer, req *http.Request) (*http.Response, error) {
	if localhost, err := os.Hostname(); err == nil && cli.proto == "unix" {
		req.URL.Host = localhost
	} else {
		req.URL.Host = cli.addr
	}
	req.URL.Scheme = cli.scheme
	if cli.jar != nil {
		for _, cookie := range cli.jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
	resp, err := doer.Do(req)
	if cli.jar != nil && resp != nil {
		if cookies := resp.Cookies(); cookies != nil {
			cli.jar.SetCookies(req.URL, cookies)
		}
	}
	return resp, err
}

// doWithAuthn calls Do(), and handles any "unauthorized" errors
// which it returns by retrying it with authentication.
func (cli *Client) doWithAuthn(doer doer, req *http.Request, body []byte) (*http.Response, error) {
	resp, err := cli.doWithCookies(doer, req)
	// If we previously tried to authenticate, or this isn't an authentication-required error, we're done.
	if req.Header.Get("Authorization") != "" || err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	// Handle Unauthorized errors by attempting to authenticate.
	scheme := ""
	for err == nil && resp.StatusCode == http.StatusUnauthorized {
		authnHeaders := req.Header[http.CanonicalHeaderKey("Authorization")]
		triedAuthnPreviously := authnHeaders != nil && len(authnHeaders) > 0
		retryWithUpdatedAuthn := false
		ah := resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")]
		for _, challenge := range ah {
			tokens := strings.Split(strings.Replace(challenge, "\t", " ", -1), " ")
			responder, ok := cli.authResponders[strings.ToLower(tokens[0])]
			if !ok {
				logrus.Debugf("no handler for \"%s\"", tokens[0])
				continue
			}
			retryWithUpdatedAuthn, err = responder.authRespond(cli, challenge, req)
			if retryWithUpdatedAuthn {
				logrus.Debugf("handler for \"%s\" produced data", tokens[0])
				scheme = strings.ToLower(tokens[0])
				break
			}
			if err != nil {
				logrus.Debugf("%v. handler for \"%s\" failed to produce data", err, tokens[0])
			} else {
				logrus.Debugf("handler for \"%s\" failed to produce data", tokens[0])
			}
		}
		if len(ah) == 0 {
			if triedAuthnPreviously {
				err = fmt.Errorf("Failed to authenticate to docker daemon")
			} else {
				err = errors.New("Failed to authenticate to docker daemon; server offered no authentication methods")
			}
			break
		} else if err != nil {
			err = fmt.Errorf("%v. Failed to authenticate to docker daemon", err)
			break
		} else if !retryWithUpdatedAuthn {
			err = errors.New("Unable to attempt to authenticate to docker daemon")
			break
		} else {
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			req.Body = ioutil.NopCloser(bytes.NewReader(body))
			resp, err = cli.doWithCookies(doer, req)
		}
	}
	if err == nil && resp.StatusCode != http.StatusUnauthorized {
		completed := false
		tokens := []string{}
		ah := resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")]
		for _, challenge := range ah {
			tokens = strings.Split(strings.Replace(challenge, "\t", " ", -1), " ")
			if strings.ToLower(tokens[0]) == scheme {
				break
			}
		}
		if len(tokens) == 0 || strings.ToLower(tokens[0]) == scheme {
			responder := cli.authResponders[scheme]
			completed, err = responder.authCompleted(cli, strings.Join(tokens, " "), resp)
			if completed {
				logrus.Debugf("handler for \"%s\" succeeded", scheme)
			} else {
				logrus.Debugf("handler for \"%s\" failed", scheme)
			}
		} else if len(ah) == 0 {
			logrus.Debugf("No authentication header in final server response")
		} else if err != nil {
			err = fmt.Errorf("%v. Unable to authenticate docker daemon", err)
		} else if !completed {
			err = fmt.Errorf("Unable to authenticate docker daemon")
		}
	}
	return resp, err
}
