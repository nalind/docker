package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cliconfig"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/client/authn"
	"github.com/docker/engine-api/client/transport"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"
)

// DockerCli represents the docker command line client.
// Instances of the client can be returned from NewDockerCli.
type DockerCli struct {
	// initializing closure
	init func() error

	// configFile has the client configuration file
	configFile *cliconfig.ConfigFile
	// in holds the input stream and closer (io.ReadCloser) for the client.
	in io.ReadCloser
	// out holds the output stream (io.Writer) for the client.
	out io.Writer
	// err holds the error stream (io.Writer) for the client.
	err io.Writer
	// keyFile holds the key file as a string.
	keyFile string
	// inFd holds the file descriptor of the client's STDIN (if valid).
	inFd uintptr
	// outFd holds file descriptor of the client's STDOUT (if valid).
	outFd uintptr
	// isTerminalIn indicates whether the client's STDIN is a TTY
	isTerminalIn bool
	// isTerminalOut indicates whether the client's STDOUT is a TTY
	isTerminalOut bool
	// client is the http client that performs all API operations
	client client.APIClient
	// state holds the terminal state
	state *term.State
	// authnOpts collects authentication options from the command line
	authnOpts map[string]string
}

// Initialize calls the init function that will setup the configuration for the client
// such as the TLS, tcp and other parameters used to run the client.
func (cli *DockerCli) Initialize() error {
	if cli.init == nil {
		return nil
	}
	return cli.init()
}

// CheckTtyInput checks if we are trying to attach to a container tty
// from a non-tty client input stream, and if so, returns an error.
func (cli *DockerCli) CheckTtyInput(attachStdin, ttyMode bool) error {
	// In order to attach to a container tty, input stream for the client must
	// be a tty itself: redirecting or piping the client standard input is
	// incompatible with `docker run -t`, `docker exec -t` or `docker attach`.
	if ttyMode && attachStdin && !cli.isTerminalIn {
		return errors.New("cannot enable tty mode on non tty input")
	}
	return nil
}

// PsFormat returns the format string specified in the configuration.
// String contains columns and format specification, for example {{ID}}\t{{Name}}.
func (cli *DockerCli) PsFormat() string {
	return cli.configFile.PsFormat
}

// ImagesFormat returns the format string specified in the configuration.
// String contains columns and format specification, for example {{ID}}\t{{Name}}.
func (cli *DockerCli) ImagesFormat() string {
	return cli.configFile.ImagesFormat
}

func (cli *DockerCli) setRawTerminal() error {
	if cli.isTerminalIn && os.Getenv("NORAW") == "" {
		state, err := term.SetRawTerminal(cli.inFd)
		if err != nil {
			return err
		}
		cli.state = state
	}
	return nil
}

func (cli *DockerCli) restoreTerminal(in io.Closer) error {
	if cli.state != nil {
		term.RestoreTerminal(cli.inFd, cli.state)
	}
	// WARNING: DO NOT REMOVE THE OS CHECK !!!
	// For some reason this Close call blocks on darwin..
	// As the client exists right after, simply discard the close
	// until we find a better solution.
	if in != nil && runtime.GOOS != "darwin" {
		return in.Close()
	}
	return nil
}

// NewDockerCli returns a DockerCli instance with IO output and error streams set by in, out and err.
// The key file, protocol (i.e. unix) and address are passed in as strings, along with the tls.Config. If the tls.Config
// is set the client scheme will be set to https.
// The client will be given a 32-second timeout (see https://github.com/docker/docker/pull/8035).
func NewDockerCli(in io.ReadCloser, out, err io.Writer, clientFlags *cli.ClientFlags) *DockerCli {
	cli := &DockerCli{
		in:      in,
		out:     out,
		err:     err,
		keyFile: clientFlags.Common.TrustKey,
	}
	cli.init = func() error {
		clientFlags.PostParse()
		configFile, e := cliconfig.Load(cliconfig.ConfigDir())
		if e != nil {
			fmt.Fprintf(cli.err, "WARNING: Error loading config file:%v\n", e)
		}
		cli.configFile = configFile

		host, err := getServerHost(clientFlags.Common.Hosts, clientFlags.Common.TLSOptions)
		if err != nil {
			return err
		}

		customHeaders := cli.configFile.HTTPHeaders
		if customHeaders == nil {
			customHeaders = map[string]string{}
		}
		customHeaders["User-Agent"] = "Docker-Client/" + dockerversion.Version + " (" + runtime.GOOS + ")"

		verStr := api.DefaultVersion.String()
		if tmpStr := os.Getenv("DOCKER_API_VERSION"); tmpStr != "" {
			verStr = tmpStr
		}

		httpClient, err := newHTTPClient(host, clientFlags.Common.TLSOptions)
		if err != nil {
			return err
		}

		client, err := client.NewClient(host, verStr, httpClient, customHeaders)
		if err != nil {
			return err
		}
		cli.client = client

		if cli.in != nil {
			cli.inFd, cli.isTerminalIn = term.GetFdInfo(cli.in)
		}
		if cli.out != nil {
			cli.outFd, cli.isTerminalOut = term.GetFdInfo(cli.out)
		}

		cli.authnOpts = clientFlags.Common.AuthnOpts
		if jar, err := cookiejar.New(nil); err == nil && jar != nil {
			client.AddMiddlewares(transport.NewCookieJarMiddleware(jar))
		}
		client.SetLogger(cli)
		authResponders := []authn.AuthResponder{}
		authResponders = append(authResponders, authn.NewBearerAuth(cli.GetBearerAuth))
		authResponders = append(authResponders, authn.NewBasicAuth(cli.GetBasicAuth))
		if len(authResponders) > 0 {
			client.AuthenticateWith(authResponders...)
		}

		return nil
	}

	return cli
}

// Debug logs a message at debug level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Debug(args ...interface{}) {
	//logrus.Debug(args...)
}

// Debug logs a message at debug level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Debugf(format string, args ...interface{}) {
	//logrus.Debugf(format, args...)
}

// Info logs a message at info level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Info(args ...interface{}) {
	logrus.Info(args...)
}

// Info logs a message at info level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Infof(format string, args ...interface{}) {
	logrus.Infof(format, args...)
}

// Error logs a message at error level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Error(args ...interface{}) {
	logrus.Error(args...)
}

// Error logs a message at error level.  This is one of the functions in the
// authn.Logger interface which the http client looks for in the object that we
// pass to its SetLogger() method.
func (cli *DockerCli) Errorf(format string, args ...interface{}) {
	logrus.Errorf(format, args...)
}

func getServerHost(hosts []string, tlsOptions *tlsconfig.Options) (host string, err error) {
	switch len(hosts) {
	case 0:
		host = os.Getenv("DOCKER_HOST")
	case 1:
		host = hosts[0]
	default:
		return "", errors.New("Please specify only one -H")
	}

	host, err = opts.ParseHost(tlsOptions != nil, host)
	return
}

func newHTTPClient(host string, tlsOptions *tlsconfig.Options) (*http.Client, error) {
	if tlsOptions == nil {
		// let the api client configure the default transport.
		return nil, nil
	}

	config, err := tlsconfig.Client(*tlsOptions)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	proto, addr, _, err := client.ParseHost(host)
	if err != nil {
		return nil, err
	}

	sockets.ConfigureTransport(tr, proto, addr)

	return &http.Client{
		Transport: tr,
	}, nil
}
