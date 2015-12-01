package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/term"
)

// ValidateAuthnOpt checks if a passed-in option value is a recognized
// authentication option.
func ValidateAuthnOpt(option string) (string, error) {
	if strings.HasPrefix(option, "basic.username=") ||
		strings.HasPrefix(option, "interactive=") ||
		strings.HasPrefix(option, "bearer.token=") {
		return option, nil
	}
	return "", fmt.Errorf("invalid authentication option %s", option)
}

func (cli *DockerCli) getBasic(realm string) (string, string, error) {
	username, ok := cli.authnOpts["basic.username"]
	if !ok {
		username = os.Getenv("DOCKER_AUTHN_USERID")
	}
	password := os.Getenv("DOCKER_AUTHN_PASSWORD")
	interactive, ok := cli.authnOpts["interactive"]
	if !ok {
		interactive = "true"
	}

	if username != "" && password != "" {
		return username, password, nil
	}

	if !cli.isTerminalIn || !cli.isTerminalOut {
		logrus.Debugf("not connected to a terminal, not prompting for Basic auth creds")
		return "", "", nil
	}
	if prompt, err := strconv.ParseBool(interactive); !prompt || err != nil {
		logrus.Debugf("interactive prompting disabled, not prompting for Basic auth creds")
		return "", "", nil
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

	if realm != "" {
		if username != "" {
			fmt.Fprintf(cli.out, "Username for %s [%s]: ", realm, username)
		} else {
			fmt.Fprintf(cli.out, "Username for %s: ", realm)
		}
	} else {
		if username != "" {
			fmt.Fprintf(cli.out, "Username[%s]: ", username)
		} else {
			fmt.Fprintf(cli.out, "Username: ")
		}
	}
	readUsername := strings.Trim(readInput(cli.in, cli.out), " ")
	if readUsername != "" {
		username = readUsername
	}
	if username == "" {
		return "", "", errors.New("user name required")
	}

	oldState, err := term.SaveState(cli.inFd)
	if err != nil {
		return "", "", err
	}
	fmt.Fprintf(cli.out, "Password: ")
	term.DisableEcho(cli.inFd, oldState)

	password = readInput(cli.in, cli.out)
	fmt.Fprint(cli.out, "\n")

	term.RestoreTerminal(cli.inFd, oldState)
	if password == "" {
		return "", "", errors.New("password required")
	}

	return username, password, nil
}

func (cli *DockerCli) getBearer(challenge string) (string, error) {
	token, ok := cli.authnOpts["bearer.token"]
	if !ok {
		token = os.Getenv("DOCKER_BEARER_TOKEN")
	}
	if token == "" {
		return "", errors.New("token required")
	}
	return token, nil
}
