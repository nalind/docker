package client

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/term"
)

type basic struct {
	username, password string
}

func (b *basic) Scheme() string {
	return "Basic"
}

func (b *basic) AuthRespond(cli *DockerCli, challenge string, req *http.Request) (result bool, err error) {
	var username, password string

	if b.username != "" && b.password != "" {
		logrus.Debugf("using previously-supplied Basic username and password")
		req.SetBasicAuth(b.username, b.password)
		return true, nil
	}

	if !cli.isTerminalIn || !cli.isTerminalOut {
		logrus.Debugf("not connected to a terminal, not prompting for Basic auth creds")
		return false, nil
	}

	readInput := func(in io.Reader, out io.Writer) string {
		reader := bufio.NewReader(in)
		line, _, err := reader.ReadLine()
		if err != nil {
			fmt.Fprintln(out, err.Error())
			os.Exit(1)
		}
		return string(line)
	}

	for username == "" {
		fmt.Fprintf(cli.out, "Username: ")
		username = readInput(cli.in, cli.out)
		username = strings.Trim(username, " ")
	}

	oldState, err := term.SaveState(cli.inFd)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(cli.out, "Password: ")
	term.DisableEcho(cli.inFd, oldState)

	password = readInput(cli.in, cli.out)
	fmt.Fprint(cli.out, "\n")

	term.RestoreTerminal(cli.inFd, oldState)
	if password == "" {
		return false, fmt.Errorf("Error: Password Required")
	}

	b.username = username
	b.password = password
	req.SetBasicAuth(b.username, b.password)
	return true, nil
}

func (b *basic) AuthCompleted(cli *DockerCli, challenge string, req *http.Request) (result bool, err error) {
	return true, nil
}

func createBasic() AuthResponder {
	return &basic{}
}

func init() {
	RegisterAuthResponder(createBasic)
}
