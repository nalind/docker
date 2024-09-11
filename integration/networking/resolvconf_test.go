package networking

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/integration/internal/container"
	"github.com/docker/docker/integration/internal/network"
	"github.com/docker/docker/testutil/daemon"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/skip"
)

// Regression test for https://github.com/moby/moby/issues/46968
func TestResolvConfLocalhostIPv6(t *testing.T) {
	// No "/etc/resolv.conf" on Windows.
	skip.If(t, testEnv.DaemonInfo.OSType == "windows")

	ctx := setupTest(t)

	tmpFileName := network.WriteTempResolvConf(t, "127.0.0.53")

	d := daemon.New(t, daemon.WithEnvVars("DOCKER_TEST_RESOLV_CONF_PATH="+tmpFileName))
	d.StartWithBusybox(ctx, t)
	defer d.Stop(t)

	c := d.NewClientT(t)
	defer c.Close()

	netName := "nnn"
	network.CreateNoError(ctx, t, c, netName,
		network.WithDriver("bridge"),
		network.WithIPv6(),
		network.WithIPAM("fd49:b5ef:36d9::/64", "fd49:b5ef:36d9::1"),
	)
	defer network.RemoveNoError(ctx, t, c, netName)

	result := container.RunAttach(ctx, t, c,
		container.WithImage("busybox:latest"),
		container.WithNetworkMode(netName),
		container.WithCmd("cat", "/etc/resolv.conf"),
	)
	defer c.ContainerRemove(ctx, result.ContainerID, containertypes.RemoveOptions{
		Force: true,
	})

	output := strings.ReplaceAll(result.Stdout.String(), tmpFileName, "RESOLV.CONF")
	assert.Check(t, is.Equal(output, `# Generated by Docker Engine.
# This file can be edited; Docker Engine will not make further changes once it
# has been modified.

nameserver 127.0.0.11
options ndots:0

# Based on host file: 'RESOLV.CONF' (internal resolver)
# ExtServers: [host(127.0.0.53)]
# Overrides: []
# Option ndots from: internal
`))
}

// Check that when a container is connected to an internal network, DNS
// requests sent to daemon's internal DNS resolver are not forwarded to
// an upstream resolver listening on a localhost address.
// (Assumes the host does not already have a DNS server on 127.0.0.1.)
func TestInternalNetworkDNS(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "No resolv.conf on Windows")
	skip.If(t, testEnv.IsRootless, "Can't use resolver on host in rootless mode")
	ctx := setupTest(t)

	// Start a DNS server on the loopback interface.
	network.StartDaftDNS(t, "127.0.0.1")

	// Set up a temp resolv.conf pointing at that DNS server, and a daemon using it.
	tmpFileName := network.WriteTempResolvConf(t, "127.0.0.1")
	d := daemon.New(t, daemon.WithEnvVars("DOCKER_TEST_RESOLV_CONF_PATH="+tmpFileName))
	d.StartWithBusybox(ctx, t)
	defer d.Stop(t)

	c := d.NewClientT(t)
	defer c.Close()

	intNetName := "intnet"
	network.CreateNoError(ctx, t, c, intNetName,
		network.WithDriver("bridge"),
		network.WithInternal(),
	)
	defer network.RemoveNoError(ctx, t, c, intNetName)

	extNetName := "extnet"
	network.CreateNoError(ctx, t, c, extNetName,
		network.WithDriver("bridge"),
	)
	defer network.RemoveNoError(ctx, t, c, extNetName)

	// Create a container, initially with external connectivity.
	// Expect the external DNS server to respond to a request from the container.
	ctrId := container.Run(ctx, t, c, container.WithNetworkMode(extNetName))
	defer c.ContainerRemove(ctx, ctrId, containertypes.RemoveOptions{Force: true})
	res, err := container.Exec(ctx, c, ctrId, []string{"nslookup", "test.example"})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(res.ExitCode, 0))
	assert.Check(t, is.Contains(res.Stdout(), network.DNSRespAddr))

	// Connect the container to the internal network as well.
	// External DNS should still be used.
	err = c.NetworkConnect(ctx, intNetName, ctrId, nil)
	assert.NilError(t, err)
	res, err = container.Exec(ctx, c, ctrId, []string{"nslookup", "test.example"})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(res.ExitCode, 0))
	assert.Check(t, is.Contains(res.Stdout(), network.DNSRespAddr))

	// Disconnect from the external network.
	// Expect no access to the external DNS.
	err = c.NetworkDisconnect(ctx, extNetName, ctrId, true)
	assert.NilError(t, err)
	res, err = container.Exec(ctx, c, ctrId, []string{"nslookup", "test.example"})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(res.ExitCode, 1))
	assert.Check(t, is.Contains(res.Stdout(), "SERVFAIL"))

	// Reconnect the external network.
	// Check that the external DNS server is used again.
	err = c.NetworkConnect(ctx, extNetName, ctrId, nil)
	assert.NilError(t, err)
	res, err = container.Exec(ctx, c, ctrId, []string{"nslookup", "test.example"})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(res.ExitCode, 0))
	assert.Check(t, is.Contains(res.Stdout(), network.DNSRespAddr))
}

// Check that '--dns' can be used to name a server inside a '--internal' network.
// Regression test for https://github.com/moby/moby/issues/47822
func TestInternalNetworkLocalDNS(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "No internal networks on Windows")
	skip.If(t, testEnv.IsRootless, "Can't write an accessible dnsd.conf in rootless mode")
	ctx := setupTest(t)

	d := daemon.New(t)
	d.StartWithBusybox(ctx, t)
	defer d.Stop(t)

	c := d.NewClientT(t)
	defer c.Close()

	intNetName := "intnet"
	network.CreateNoError(ctx, t, c, intNetName,
		network.WithDriver("bridge"),
		network.WithInternal(),
	)
	defer network.RemoveNoError(ctx, t, c, intNetName)

	// Write a config file for busybox's dnsd.
	td := t.TempDir()
	fname := path.Join(td, "dnsd.conf")
	err := os.WriteFile(fname, []byte("foo.example 192.0.2.42\n"), 0o644)
	assert.NilError(t, err)

	// Start a DNS server on the internal network.
	serverId := container.Run(ctx, t, c,
		container.WithNetworkMode(intNetName),
		container.WithMount(mount.Mount{
			Type:   mount.TypeBind,
			Source: fname,
			Target: "/etc/dnsd.conf",
		}),
		container.WithCmd("dnsd"),
	)
	defer c.ContainerRemove(ctx, serverId, containertypes.RemoveOptions{Force: true})

	// Get the DNS server's address.
	inspect := container.Inspect(ctx, t, c, serverId)
	serverIP := inspect.NetworkSettings.Networks[intNetName].IPAddress

	// Query the internal network's DNS server (via the daemon's internal DNS server).
	res := container.RunAttach(ctx, t, c,
		container.WithNetworkMode(intNetName),
		container.WithDNS([]string{serverIP}),
		container.WithCmd("nslookup", "-type=A", "foo.example"),
	)
	defer c.ContainerRemove(ctx, res.ContainerID, containertypes.RemoveOptions{Force: true})
	assert.Check(t, is.Contains(res.Stdout.String(), "192.0.2.42"))
}

// TestNslookupWindows checks that nslookup gets results from external DNS.
// Regression test for https://github.com/moby/moby/issues/46792
func TestNslookupWindows(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType != "windows")

	ctx := setupTest(t)
	c := testEnv.APIClient()

	attachCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res := container.RunAttach(attachCtx, t, c,
		container.WithCmd("nslookup", "docker.com"),
	)
	defer c.ContainerRemove(ctx, res.ContainerID, containertypes.RemoveOptions{Force: true})

	assert.Check(t, is.Equal(res.ExitCode, 0))
	// Current default is to forward requests to external servers, which
	// can only be changed in daemon.json using feature flag "windows-dns-proxy".
	assert.Check(t, is.Contains(res.Stdout.String(), "Addresses:"))
}