package lib

import (
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
)

type bearer struct {
	token string
}

func (b *bearer) scheme() string {
	return "Bearer"
}

func (b *bearer) authRespond(cli *Client, challenge string, req *http.Request) (result bool, err error) {
	token := b.token
	if token != "" {
		logrus.Debugf("using previously-supplied Bearer token")
		req.Header.Add("Authorization", "Bearer "+token)
		return true, nil
	}
	if cli.authnOpts.getBearer == nil {
		logrus.Debugf("failed to obtain token for Bearer auth")
		return false, nil
	}
	token, err = cli.authnOpts.getBearer(challenge)
	if err != nil {
		return false, err
	}
	if token == "" {
		logrus.Debugf("Bearer token not supplied")
		return false, nil
	}
	b.token = token
	req.Header.Add("Authorization", "Bearer "+b.token)
	return true, nil
}

func (b *bearer) authCompleted(cli *Client, challenge string, resp *http.Response) (result bool, err error) {
	if challenge == "" {
		return true, nil
	}
	return false, errors.New("Error: unexpected WWW-Authenticate header in server response")
}

func createBearer() authResponder {
	return &bearer{}
}

func init() {
	registerAuthResponder(createBearer)
}
