// +build freebsd linux

package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/sockets"
	"github.com/docker/libnetwork/portallocator"

	systemdActivation "github.com/coreos/go-systemd/activation"
)

// newServer sets up the required HTTPServers and does protocol specific checking.
// newServer does not set any muxers, you should set it later to Handler field
func (s *Server) newServer(proto, addr string) ([]*HTTPServer, error) {
	var (
		err error
		ls  []net.Listener
	)
	switch proto {
	case "fd":
		ls, err = listenFD(addr, s.cfg.TLSConfig)
		if err != nil {
			return nil, err
		}
	case "tcp":
		l, err := s.initTCPSocket(addr)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	case "unix":
		l, err := sockets.NewUnixSocket(addr, s.cfg.SocketGroup)
		if err != nil {
			return nil, fmt.Errorf("can't create unix socket %s: %v", addr, err)
		}
		ls = append(ls, l)
	default:
		return nil, fmt.Errorf("Invalid protocol format: %q", proto)
	}
	var res []*HTTPServer
	for _, l := range ls {
		res = append(res, &HTTPServer{
			&http.Server{
				Addr: addr,
			},
			l,
		})
	}
	return res, nil
}

func allocateDaemonPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	intPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	var hostIPs []net.IP
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		hostIPs = append(hostIPs, parsedIP)
	} else if hostIPs, err = net.LookupIP(host); err != nil {
		return fmt.Errorf("failed to lookup %s address in host specification", host)
	}

	pa := portallocator.Get()
	for _, hostIP := range hostIPs {
		if _, err := pa.RequestPort(hostIP, "tcp", intPort); err != nil {
			return fmt.Errorf("failed to allocate daemon listening port %d (err: %v)", intPort, err)
		}
	}
	return nil
}

func getUserFromHTTPResponseWriter(w http.ResponseWriter, options map[string]string) User {
	// First, check that we're even supposed to be looking up anything.
	local, ok := options["local-auth"]
	if !ok {
		return User{}
	}
	if use, err := strconv.ParseBool(local); err != nil || !use {
		return User{}
	}
	wi := reflect.ValueOf(w)
	// Dereference the http.ResponseWriter interface to look at the struct...
	hr := wi.Elem()
	switch hr.Kind() {
	case reflect.Struct:
	default:
		logrus.Warn("ResponseWriter is not a struct")
		return User{}
	}
	// which is an http.response that contains a field named "conn"...
	c := hr.FieldByName("conn")
	if !c.IsValid() {
		logrus.Warn("ResponseWriter has no conn field")
		return User{}
	}
	// ... which is an http.conn, which is an interface ...
	hc := c.Elem()
	switch hc.Kind() {
	case reflect.Struct:
	default:
		logrus.Warn("conn is not an interface to a struct: " + c.Elem().Kind().String())
		return User{}
	}
	// ... and which has an element named "rwc" ...
	rwc := hc.FieldByName("rwc")
	if !rwc.IsValid() {
		logrus.Warn("conn has no rwc field")
		return User{}
	}
	// ... which is a pointer to a net.Conn, which is an interface ...
	nc := rwc.Elem()
	// ... to a net.UnixConn structure ...
	nuc := nc.Elem()
	switch nuc.Kind() {
	case reflect.Struct:
	default:
		logrus.Warn("rwc is not an interface to a struct: " + rwc.Elem().Kind().String())
		return User{}
	}
	// ... which contains a net.conn named "fd" ...
	fd := nuc.FieldByName("fd")
	if !fd.IsValid() {
		logrus.Warn("rwc has no fd field")
		return User{}
	}
	// ... which is a pointer to a net.netFD structure ...
	nfd := fd.Elem()
	switch nfd.Kind() {
	case reflect.Struct:
	default:
		logrus.Warn("fd is not a struct")
		return User{}
	}
	// ... which contains an integer named sysfd.
	sysfd := nfd.FieldByName("sysfd")
	if !sysfd.IsValid() {
		logrus.Warn("fd has no sysfd field")
		return User{}
	}
	// read the address of the local end of the socket
	sa, err := syscall.Getsockname(int(sysfd.Int()))
	if err != nil {
		logrus.Warn("error reading server socket address")
		return User{}
	}
	// and only try to read the user if it's a Unix socket
	if _, isUnix := sa.(*syscall.SockaddrUnix); !isUnix {
		logrus.Warn("error reading server socket address")
		return User{}
	}
	uc, err := syscall.GetsockoptUcred(int(sysfd.Int()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || uc == nil {
		logrus.Warnf("%v: error reading client identity from kernel", err)
		return User{}
	}
	uidstr := fmt.Sprintf("%d", uc.Uid)
	pwd, err := user.LookupId(uidstr)
	if err != nil || pwd == nil {
		logrus.Warnf("unable to look up UID %s: %v", uidstr, err)
		return User{HaveUID: true, UID: uc.Uid}
	}
	logrus.Debugf("read UID %s (%s) from kernel", uidstr, pwd.Username)
	return User{Name: pwd.Username, HaveUID: true, UID: uc.Uid, Scheme: "External"}
}

// listenFD returns the specified socket activated files as a slice of
// net.Listeners or all of the activated files if "*" is given.
func listenFD(addr string, tlsConfig *tls.Config) ([]net.Listener, error) {
	var (
		err       error
		listeners []net.Listener
	)
	// socket activation
	if tlsConfig != nil {
		listeners, err = systemdActivation.TLSListeners(false, tlsConfig)
	} else {
		listeners, err = systemdActivation.Listeners(false)
	}
	if err != nil {
		return nil, err
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("No sockets found")
	}

	// default to all fds just like unix:// and tcp://
	if addr == "" || addr == "*" {
		return listeners, nil
	}

	fdNum, err := strconv.Atoi(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse systemd address, should be number: %v", err)
	}
	fdOffset := fdNum - 3
	if len(listeners) < int(fdOffset)+1 {
		return nil, fmt.Errorf("Too few socket activated files passed in")
	}
	if listeners[fdOffset] == nil {
		return nil, fmt.Errorf("failed to listen on systemd activated file at fd %d", fdOffset+3)
	}
	for i, ls := range listeners {
		if i == fdOffset || ls == nil {
			continue
		}
		if err := ls.Close(); err != nil {
			logrus.Errorf("Failed to close systemd activated file at fd %d: %v", fdOffset+3, err)
		}
	}
	return []net.Listener{listeners[fdOffset]}, nil
}

func validateLocalAuthOption(option string) (string, error) {
	if strings.HasPrefix(option, "local-auth=") {
		return option, nil
	}
	return "", fmt.Errorf("invalid authentication option: %s", option)
}

func init() {
	opts.RegisterAuthnOptionValidater(validateLocalAuthOption)
}
