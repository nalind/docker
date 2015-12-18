package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/server"
	"github.com/docker/docker/pkg/authorization"
	"github.com/go-check/check"
)

type BasicEnv struct {
	saslauthdPath   string
	htpasswdPath    string
	oldSaslConfPath string
}

func NewBasicEnv() *BasicEnv {
	base := "/tmp/basic"
	return &BasicEnv{
		saslauthdPath: base + "/saslauthd/",
		htpasswdPath:  "fixtures/basic/htpasswd",
	}
}

func (b *BasicEnv) Start(c *check.C) {
	if err := os.MkdirAll(b.saslauthdPath, 0711); err != nil {
		c.Fatalf("Failed to mkdir for saslauthd, err %v", err)
	}
	// Start up saslauthd in the background.
	if output, _, err := runCommandWithOutput(exec.Command("fixtures/basic/docker-saslauthd.sh", "-V", "-a", "kerberos5", "-m", b.saslauthdPath)); err != nil {
		c.Fatalf("Failed to start saslauthd, err %v with output %s", err, string(output))
	}
	b.oldSaslConfPath = os.Getenv("SASL_CONF_PATH")
	os.Setenv("SASL_CONF_PATH", "fixtures/basic")
}

func (b *BasicEnv) Stop(c *check.C) {
	// Send saslauthd a SIGINT to exit and clean up its worker processes.
	if pidBytes, err := ioutil.ReadFile(b.saslauthdPath + "saslauthd.pid"); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes))); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				process.Signal(os.Interrupt)
			}
		}
	}
	os.RemoveAll(b.saslauthdPath)
	os.Unsetenv("SASL_CONF_PATH")
	if b.oldSaslConfPath != "" {
		os.Setenv("SASL_CONF_PATH", b.oldSaslConfPath)
	}
}

type Krb5Env struct {
	envPath       string
	kdcEnvPath    string
	kdcPidPath    string
	oldConfig     string
	oldKdcProfile string
}

func NewKrb5Env() *Krb5Env {
	krb5 := Krb5Env{
		envPath:    "/tmp/krb5/",
		kdcEnvPath: "krb5kdc/",
		kdcPidPath: "krb5kdc.pid",
	}

	krb5.kdcEnvPath = krb5.envPath + krb5.kdcEnvPath
	krb5.kdcPidPath = krb5.kdcEnvPath + krb5.kdcPidPath

	return &krb5
}

func (krb5 *Krb5Env) Start(c *check.C) {
	krb5.oldConfig = os.Getenv("KRB5_CONFIG")
	krb5.oldKdcProfile = os.Getenv("KRB5_KDC_PROFILE")
	os.Setenv("KRB5_CONFIG", "fixtures/krb5/krb5.conf")
	os.Setenv("KRB5_KDC_PROFILE", "fixtures/krb5/krb5kdc/kdc.conf")

	if err := os.MkdirAll(krb5.kdcEnvPath, 0666); err != nil {
		c.Fatalf("Failed to mkdir for kerberos environment, err %v", err)
	}

	// Create a kerberos database and a stash file.
	if output, _, err := runCommandWithOutput(exec.Command("kdb5_util", "create", "-s", "-W", "-P", "admin")); err != nil {
		c.Fatalf("Failed to create kerberos db, err %v with output %s", err, string(output))
	}

	// Run the KDC. Note that this command is non-blocking.
	if output, _, err := runCommandWithOutput(exec.Command("krb5kdc", "-P", krb5.kdcPidPath)); err != nil {
		c.Fatalf("Failed to start kdc, err %v with output %s", err, string(output))
	}
}

func (krb5 *Krb5Env) Stop(c *check.C) {
	// Kill the KDC.
	if pidBytes, err := ioutil.ReadFile(krb5.kdcPidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes))); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				process.Kill()
			}
		}
	}

	if output, _, err := runCommandWithOutput(exec.Command("kdb5_util", "destroy", "-f")); err != nil {
		c.Logf("Failed to destroy kerberos db, err %v with output %s", err, output)
	}

	os.RemoveAll(krb5.kdcEnvPath)
	os.RemoveAll(krb5.envPath)

	os.Unsetenv("KRB5_CONFIG")
	if krb5.oldConfig != "" {
		os.Setenv("KRB5_CONFIG", krb5.oldConfig)
	}

	os.Unsetenv("KRB5_KDC_PROFILE")
	if krb5.oldConfig != "" {
		os.Setenv("KRB5_KDC_PROFILE", krb5.oldKdcProfile)
	}
}

func (krb5 *Krb5Env) AddClientPrinc(c *check.C, principal string, password string) {
	query := fmt.Sprintf("addprinc -pw %s %s", password, principal)
	if output, _, err := runCommandWithOutput(exec.Command("kadmin.local", "-q", query)); err != nil {
		c.Fatalf("Failed to add kerberos principal, err %v with output %s", err, output)
	}
}

func (krb5 *Krb5Env) AddServerPrinc(c *check.C, principal string) {
	query := fmt.Sprintf("addprinc -randkey %s", principal)
	if output, _, err := runCommandWithOutput(exec.Command("kadmin.local", "-q", query)); err != nil {
		c.Fatalf("Failed to add kerberos principal, err %v with output %s", err, output)
	}
}

func (krb5 *Krb5Env) DelPrinc(c *check.C, principal string) {
	query := fmt.Sprintf("delprinc -force %s", principal)
	if output, _, err := runCommandWithOutput(exec.Command("kadmin.local", "-q", query)); err != nil {
		c.Fatalf("Failed to delete kerberos principal, err %v with output %s", err, output)
	}
}

func (krb5 *Krb5Env) AddPrincToKeytab(c *check.C, principal string) {
	query := fmt.Sprintf("ktadd %s", principal)
	if output, _, err := runCommandWithOutput(exec.Command("kadmin.local", "-q", query)); err != nil {
		c.Fatalf("Failed to add kerberos principal to keytab, err %v with output %s", err, output)
	}
}

func (krb5 *Krb5Env) RemovePrincFromKeytab(c *check.C, principal string) {
	query := fmt.Sprintf("ktrem %s", principal)
	if output, _, err := runCommandWithOutput(exec.Command("kadmin.local", "-q", query)); err != nil {
		c.Logf("Failed to remove kerberos principal from keytab, err %v with output %s", err, output)
	}
}

// kinit does not support password as a cli paramter, so a keytab entry for the given pricinpal is assumed.
func (krb5 *Krb5Env) Kinit(c *check.C, principal string) {
	if output, _, err := runCommandWithOutput(exec.Command("kinit", principal, "-k")); err != nil {
		c.Fatalf("Failed to add obtain kerberos ticket, err %v with output %s", err, output)
	}
}

func (krb5 *Krb5Env) Kdestroy(c *check.C) {
	if output, _, err := runCommandWithOutput(exec.Command("kdestroy")); err != nil {
		c.Logf("Failed to destroy kerberos cache, err %v with output %s", err, output)
	}
}

const (
	clientPrincipal     = "docker"
	clientPrincipalPass = "docker"
	daemonPrincipal     = "HTTP/localhost"
)

var (
	hostPrincipal string
)

func setUpNegotiatePrincipals(c *check.C, krb5 *Krb5Env) {
	krb5.AddClientPrinc(c, clientPrincipal, clientPrincipalPass)
	krb5.AddPrincToKeytab(c, clientPrincipal)
	krb5.AddServerPrinc(c, daemonPrincipal)
	krb5.AddPrincToKeytab(c, daemonPrincipal)
}

func tearDownNegotiatePrincipals(c *check.C, krb5 *Krb5Env) {
	krb5.RemovePrincFromKeytab(c, daemonPrincipal)
	krb5.DelPrinc(c, daemonPrincipal)
	krb5.RemovePrincFromKeytab(c, clientPrincipal)
	krb5.DelPrinc(c, clientPrincipal)
}

func setUpBasicPrincipals(c *check.C, krb5 *Krb5Env) {
	krb5.AddClientPrinc(c, clientPrincipal, clientPrincipalPass)
	hostname, err := os.Hostname()
	if err != nil {
		hostPrincipal = "host/localhost"
	} else {
		hostPrincipal = "host/" + hostname
	}
	krb5.AddServerPrinc(c, hostPrincipal)
	krb5.AddPrincToKeytab(c, hostPrincipal)
}

func tearDownBasicPrincipals(c *check.C, krb5 *Krb5Env) {
	krb5.RemovePrincFromKeytab(c, hostPrincipal)
	krb5.DelPrinc(c, hostPrincipal)
	krb5.DelPrinc(c, clientPrincipal)
}

func (s *DockerAuthnSuite) TestKerberosAuthnRest(c *check.C) {
	s.krb5.Start(c)
	setUpNegotiatePrincipals(c, s.krb5)
	defer tearDownNegotiatePrincipals(c, s.krb5)
	s.krb5.Kinit(c, clientPrincipal)
	defer s.krb5.Kdestroy(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}

	//force tcp protocol
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "-D", "info")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestKerberosAuthnRun(c *check.C) {
	s.krb5.Start(c)
	setUpNegotiatePrincipals(c, s.krb5)
	defer tearDownNegotiatePrincipals(c, s.krb5)
	s.krb5.Kinit(c, clientPrincipal)
	defer s.krb5.Kdestroy(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}

	//force tcp protocol
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	stdin := "echo interactive docker output"
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "run", "busybox", "/bin/sh", "-c", stdin)
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
	c.Assert(strings.Contains(out, "interactive docker output"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestKerberosAuthnNoConfig(c *check.C) {
	if err := s.ds.d.Start("-H", s.daemonAddr, "-a"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}

	//force tcp protocol
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "server offered no authentication methods"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestKerberosAuthnNoTicket(c *check.C) {
	s.krb5.Start(c)
	setUpNegotiatePrincipals(c, s.krb5)
	defer tearDownNegotiatePrincipals(c, s.krb5)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}

	//force tcp protocol
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Unable to attempt to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func SetRightPasswordEnv(c *exec.Cmd) {
	for _, env := range os.Environ() {
		c.Env = append(c.Env, env)
	}
	c.Env = append(c.Env, "DOCKER_AUTHN_PASSWORD="+clientPrincipalPass)
}

func SetWrongPasswordEnv(c *exec.Cmd) {
	for _, env := range os.Environ() {
		c.Env = append(c.Env, env)
	}
	c.Env = append(c.Env, "DOCKER_AUTHN_PASSWORD=not-"+clientPrincipalPass)
}

func (s *DockerAuthnSuite) TestBasicAuthnGoodKrb5(c *check.C) {
	s.krb5.Start(c)
	setUpBasicPrincipals(c, s.krb5)
	defer tearDownBasicPrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "libsasl2=true", "--authn-opt", "realm=DOCKER.LOCAL"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetRightPasswordEnv, "-D", "info", "--authn-opt", "basic.username="+clientPrincipal)
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestBasicAuthnBadKrb51(c *check.C) {
	s.krb5.Start(c)
	setUpBasicPrincipals(c, s.krb5)
	defer tearDownBasicPrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "libsasl2=true", "--authn-opt", "realm=DOCKER.LOCAL"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetWrongPasswordEnv, "-D", "info", "--authn-opt", "basic.username="+clientPrincipal)
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestBasicAuthnBadKrb52(c *check.C) {
	s.krb5.Start(c)
	setUpBasicPrincipals(c, s.krb5)
	defer tearDownBasicPrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "libsasl2=true", "--authn-opt", "realm=DOCKER.LOCAL"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetRightPasswordEnv, "-D", "info", "--authn-opt", "basic.username=not-"+clientPrincipal)
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestBasicAuthnGoodHTPASSWD(c *check.C) {
	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "htpasswd="+s.basic.htpasswdPath); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetRightPasswordEnv, "-D", "info", "--authn-opt", "basic.username="+clientPrincipal)
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestBasicAuthnBadHTPASSWD1(c *check.C) {
	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "htpasswd="+s.basic.htpasswdPath); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetWrongPasswordEnv, "-D", "info", "--authn-opt", "basic.username="+clientPrincipal)
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestBasicAuthnBadHTPASSWD2(c *check.C) {
	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "htpasswd="+s.basic.htpasswdPath); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CustomCmd(SetRightPasswordEnv, "-D", "info", "--authn-opt", "basic.username=not-"+clientPrincipal)
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestExternalUnixAuthnGood1(c *check.C) {
	s.krb5.Start(c)
	setUpBasicPrincipals(c, s.krb5)
	defer tearDownBasicPrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "local-auth=true"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.Cmd("-D", "info")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestExternalUnixAuthnGood2(c *check.C) {
	s.krb5.Start(c)
	setUpNegotiatePrincipals(c, s.krb5)
	defer tearDownNegotiatePrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "local-auth=true"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.Cmd("-D", "info")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestExternalUnixAuthnBad1(c *check.C) {
	s.krb5.Start(c)
	setUpBasicPrincipals(c, s.krb5)
	defer tearDownBasicPrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "local-auth=true"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	//force tcp protocol, so Unix auth can't work
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "-D", "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Unable to attempt to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestExternalUnixAuthnBad2(c *check.C) {
	s.krb5.Start(c)
	setUpNegotiatePrincipals(c, s.krb5)
	defer tearDownNegotiatePrincipals(c, s.krb5)
	s.basic.Start(c)

	if err := s.ds.d.Start("-H", s.daemonAddr, "-a", "--authn-opt", "local-auth=true"); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	//force tcp protocol, so Unix auth can't work
	host := fmt.Sprintf("tcp://%s", s.daemonAddr)
	daemonArgs := []string{"--host", host}
	out, err := s.ds.d.CmdWithArgs(daemonArgs, "-D", "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Unable to attempt to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) MapClientCertificateToUser(w http.ResponseWriter, r *http.Request) {
	req := server.CertmapPluginRequest{Options: make(map[string]string)}
	resp := server.CertmapPluginResponse{Header: make(http.Header)}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing MapClientCertificateToUser request from docker daemon: %v", err)
		return
	}
	certs, err := x509.ParseCertificates(req.Certificate)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing MapClientCertificateToUser certificates from docker daemon: %v", err)
		return
	}
	if len(certs) == 0 || certs[0] == nil {
		s.ds.d.c.Fatalf("No certificates in MapClientCertificateToUser request from docker daemon")
		return
	}
	subject := certs[0].Subject
	// Actual mappers should be much smarter than this.
	resp.AuthedUser.Name = subject.CommonName
	json.NewEncoder(w).Encode(resp)
}

func (s *DockerAuthnSuite) TestExternalCertAuthnGood1(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--tlsverify",
		"--tlscacert", "fixtures/https/ca.pem",
		"--tlscert", "fixtures/https/server-cert.pem",
		"--tlskey", "fixtures/https/server-key.pem",
		"--authn-opt", "certmap=test-authn-certmap",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
		"--tlsverify",
		"--tlscacert", "fixtures/https/ca.pem",
		"--tlscert", "fixtures/https/client-cert.pem",
		"--tlskey", "fixtures/https/client-key.pem",
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestExternalCertAuthnBad1(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--tlsverify",
		"--tlscacert", "fixtures/https/ca.pem",
		"--tlscert", "fixtures/https/server-cert.pem",
		"--tlskey", "fixtures/https/server-key.pem",
		"--authn-opt", "certmap=test-authn-certmap",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
		"--tlsverify",
		"--tlscacert", "fixtures/https/ca.pem",
		"--tlscert", "fixtures/https/client-rogue-cert.pem",
		"--tlskey", "fixtures/https/client-rogue-key.pem",
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "bad certificate"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) GetChallenge(w http.ResponseWriter, r *http.Request) {
	req := server.AuthnPluginRequest{URL: make(map[string]string), Options: make(map[string]string)}
	resp := server.AuthnPluginResponse{Header: make(http.Header)}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing Authentication.GetChallenge request from docker daemon: %v", err)
		return
	}
	resp.Header.Add("WWW-Authenticate", "Bearer")
	json.NewEncoder(w).Encode(resp)
}

func (s *DockerAuthnSuite) CheckResponse(w http.ResponseWriter, r *http.Request) {
	req := server.AuthnPluginRequest{URL: make(map[string]string), Options: make(map[string]string)}
	resp := server.AuthnPluginResponse{Header: make(http.Header)}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing Authentication.CheckResponse request from docker daemon: %v", err)
		return
	}
	headers := req.Header[http.CanonicalHeaderKey("Authorization")]
	for _, h := range headers {
		fields := strings.SplitN(strings.Replace(h, "\t", " ", -1), " ", 2)
		if fields[0] == "Bearer" {
			if fields[1] == "YES-I-AM-A-BEAR" {
				resp.AuthedUser.Scheme = "Bearer"
				resp.AuthedUser.Name = "Bear"
			}
			if fields[1] == "SO-MANY-BEARS" {
				resp.AuthedUser.Scheme = "Bearer"
				resp.AuthedUser.Name = "SomeOtherBear"
			}
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *DockerAuthnSuite) AuthzRequest(w http.ResponseWriter, r *http.Request) {
	req := authorization.Request{}
	resp := authorization.Response{}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing AuthZ.Req request from docker daemon: %v", err)
		return
	}
	resp.Allow = req.User == "Bear"
	if !resp.Allow {
		if req.User != "" {
			resp.Msg = "Authorization denied: not the bear we were looking for."
		} else {
			resp.Msg = "Authorization denied: client not authenticated."
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *DockerAuthnSuite) AuthzResponse(w http.ResponseWriter, r *http.Request) {
	req := authorization.Request{}
	resp := authorization.Response{}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.ds.d.c.Fatalf("Error parsing AuthZ.Rep request from docker daemon: %v", err)
		return
	}
	resp.Allow = req.User == "Bear"
	if !resp.Allow {
		if req.User != "" {
			resp.Msg = "Authorization denied: not the bear we were looking for."
		} else {
			resp.Msg = "Authorization denied: client not authenticated."
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *DockerAuthnSuite) TestPluginAuthnGood1(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--authn-opt", "plugins=test-authn-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info", "--authn-opt", "bearer.token=YES-I-AM-A-BEAR")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestPluginAuthnBad1(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--authn-opt", "plugins=test-authn-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info", "--authn-opt", "bearer.token=NO-I-AM-NOT-A-BEAR")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestPluginAuthnGood2(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--authn-opt", "plugins=test-authn-plugin",
		"--authz-plugin", "test-authz-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info", "--authn-opt", "bearer.token=YES-I-AM-A-BEAR")
	if err != nil {
		c.Fatalf("Error Occurred: %v and output: %s", err, out)
	}
}

func (s *DockerAuthnSuite) TestPluginAuthnBad2a(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr,
		"--authz-plugin", "test-authz-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Authorization denied: client not authenticated."), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestPluginAuthnBad2b(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--authn-opt", "plugins=test-authn-plugin",
		"--authz-plugin", "test-authz-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info", "--authn-opt", "bearer.token=NO-I-AM-NOT-A-BEAR")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Failed to authenticate to docker daemon"), check.Equals, true, check.Commentf("actual output is: %s", out))
}

func (s *DockerAuthnSuite) TestPluginAuthnBad2c(c *check.C) {
	serverOpts := []string{
		"--host", s.daemonAddr, "-a",
		"--authn-opt", "plugins=test-authn-plugin",
		"--authz-plugin", "test-authz-plugin",
	}
	clientOpts := []string{
		"-D", "--host", "tcp://" + s.daemonAddr,
	}
	if err := s.ds.d.Start(serverOpts...); err != nil {
		c.Fatalf("Could not start daemon: %v", err)
	}
	out, err := s.ds.d.CmdWithArgs(clientOpts, "info", "--authn-opt", "bearer.token=SO-MANY-BEARS")
	c.Assert(err, check.ErrorMatches, "exit status 1")
	c.Assert(strings.Contains(out, "Authorization denied: not the bear we were looking for."), check.Equals, true, check.Commentf("actual output is: %s", out))
}
