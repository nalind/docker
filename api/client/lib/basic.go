package lib

import (
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
)

type basic struct {
	username, password string
}

func (b *basic) scheme() string {
	return "Basic"
}

func (b *basic) authRespond(cli *Client, challenge string, req *http.Request) (result bool, err error) {
	if b.username != "" && b.password != "" {
		logrus.Debugf("using previously-supplied Basic username and password")
		req.SetBasicAuth(b.username, b.password)
		return true, nil
	}

	if cli.authnOpts.getBasic == nil {
		logrus.Debugf("failed to obtain user name and password for Basic auth")
		return false, nil
	}

	realm, _ := getParameter(challenge, "realm")
	username, password, err := cli.authnOpts.getBasic(realm)
	if err != nil {
		return false, err
	}
	if username == "" {
		logrus.Debugf("failed to obtain user name for Basic auth")
		return false, nil
	}
	if password == "" {
		logrus.Debugf("failed to obtain password for Basic auth")
		return false, nil
	}

	b.username = username
	b.password = password
	req.SetBasicAuth(b.username, b.password)
	return true, nil
}

func (b *basic) authCompleted(cli *Client, challenge string, resp *http.Response) (result bool, err error) {
	if challenge == "" {
		return true, nil
	}
	return false, errors.New("Error: unexpected WWW-Authenticate header in server response")
}

func createBasic() authResponder {
	return &basic{}
}

func init() {
	registerAuthResponder(createBasic)
}
