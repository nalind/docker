// +build freebsd linux

package server

import (
	"fmt"
	"net"
	"net/http"
	"os/user"
	"reflect"
	"strconv"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon"
	"github.com/docker/docker/pkg/sockets"
	"github.com/docker/docker/pkg/systemd"
	"github.com/docker/docker/pkg/version"
	"github.com/docker/docker/runconfig"
	"github.com/docker/libnetwork/portallocator"
)

const (
	// See http://git.kernel.org/cgit/linux/kernel/git/tip/tip.git/tree/kernel/sched/sched.h?id=8cd9234c64c584432f6992fe944ca9e46ca8ea76#n269
	linuxMinCPUShares = 2
	linuxMaxCPUShares = 262144
)

// newServer sets up the required serverClosers and does protocol specific checking.
func (s *Server) newServer(proto, addr string) ([]serverCloser, error) {
	var (
		err error
		ls  []net.Listener
	)
	switch proto {
	case "fd":
		ls, err = systemd.ListenFD(addr)
		if err != nil {
			return nil, err
		}
		// We don't want to start serving on these sockets until the
		// daemon is initialized and installed. Otherwise required handlers
		// won't be ready.
		<-s.start
	case "tcp":
		l, err := s.initTCPSocket(addr)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	case "unix":
		l, err := sockets.NewUnixSocket(addr, s.cfg.SocketGroup, s.start)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	default:
		return nil, fmt.Errorf("Invalid protocol format: %q", proto)
	}
	var res []serverCloser
	for _, l := range ls {
		res = append(res, &HTTPServer{
			&http.Server{
				Addr:    addr,
				Handler: s.router,
			},
			l,
		})
	}
	return res, nil
}

// AcceptConnections allows clients to connect to the API server.
// Referenced Daemon is notified about this server, and waits for the
// daemon acknowledgement before the incoming connections are accepted.
func (s *Server) AcceptConnections(d *daemon.Daemon) {
	// Tell the init daemon we are accepting requests
	s.daemon = d
	s.registerSubRouter()
	go systemd.SdNotify("READY=1")
	// close the lock so the listeners start accepting connections
	select {
	case <-s.start:
	default:
		close(s.start)
	}
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

func adjustCPUShares(version version.Version, hostConfig *runconfig.HostConfig) {
	if version.LessThan("1.19") {
		if hostConfig != nil && hostConfig.CPUShares > 0 {
			// Handle unsupported CpuShares
			if hostConfig.CPUShares < linuxMinCPUShares {
				logrus.Warnf("Changing requested CpuShares of %d to minimum allowed of %d", hostConfig.CPUShares, linuxMinCPUShares)
				hostConfig.CPUShares = linuxMinCPUShares
			} else if hostConfig.CPUShares > linuxMaxCPUShares {
				logrus.Warnf("Changing requested CpuShares of %d to maximum allowed of %d", hostConfig.CPUShares, linuxMaxCPUShares)
				hostConfig.CPUShares = linuxMaxCPUShares
			}
		}
	}
}

func getUserFromHttpResponseWriter(w http.ResponseWriter) User {
	wi := reflect.ValueOf(w)
	// Dereference the http.ResponseWriter interface to look at the struct...
	switch hr := wi.Elem(); hr.Kind() {
	case reflect.Struct:
		// which is an http.response that contains a field named "conn"...
		if c := hr.FieldByName("conn"); c.IsValid() {
			// ... which is an http.conn, which is an interface ...
			switch hc := c.Elem(); hc.Kind() {
			case reflect.Struct:
				// ... and an element named "rwc" ...
				if rwc := hc.FieldByName("rwc"); rwc.IsValid() {
					// ... which is a pointer to a net.Conn, which is an interface ...
					nc := rwc.Elem()
					// ... to a net.UnixConn, which contains a net.conn ...
					switch nuc := nc.Elem(); nuc.Kind() {
					case reflect.Struct:
						// ... which contains a net.conn named "fd" ...
						fd := nuc.FieldByName("fd")
						if fd.IsValid() {
							// ... which is a pointer to a net.netFD ...
							switch nfd := fd.Elem(); nfd.Kind() {
							case reflect.Struct:
								// ... which contains an integer named sysfd.
								sysfd := nfd.FieldByName("sysfd")
								if sysfd.IsValid() {
									// read the address of the local end of the socket
									sa, err := syscall.Getsockname(int(sysfd.Int()))
									if err == nil {
										// and only try to read the user if it's a Unix socket
										if _, isUnix := sa.(*syscall.SockaddrUnix); isUnix {
											uc, err := syscall.GetsockoptUcred(int(sysfd.Int()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
											if err == nil && uc != nil {
												uidstr := fmt.Sprintf("%d", uc.Uid)
												pwd, err := user.LookupId(uidstr)
												if err == nil && pwd != nil {
													logrus.Debugf("read UID %s (%s) from kernel", uidstr, pwd.Username)
													return User{Name: pwd.Username, HaveUid: true, Uid: uc.Uid}
												}
												logrus.Warnf("unable to look up UID %s: %v", uidstr, err)
												return User{HaveUid: true, Uid: uc.Uid}
											}
											if err != nil {
												logrus.Warnf("%v: error reading client identity from kernel", err)
											}
										}
									} else {
										logrus.Warn("error reading server socket address")
									}
								} else {
									logrus.Warn("fd has no sysfd field")
								}
							default:
								logrus.Warn("fd is not a struct")
							}
						} else {
							logrus.Warn("rwc has no fd field")
						}
					default:
						logrus.Warn("rwc is not an interface to a struct: " + rwc.Elem().Kind().String())
					}
				} else {
					logrus.Warn("conn has no rwc field")
				}
			default:
				logrus.Warn("conn is not a struct")
			}
		} else {
			logrus.Warn("ResponseWriter has no conn field")
		}
	default:
		logrus.Warn("ResponseWriter is not a struct")
	}
	return User{}
}

// getContainersByNameDownlevel performs processing for pre 1.20 APIs. This
// is only relevant on non-Windows daemons.
func getContainersByNameDownlevel(w http.ResponseWriter, s *Server, namevar string) error {
	containerJSONRaw, err := s.daemon.ContainerInspectPre120(namevar)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, containerJSONRaw)
}
