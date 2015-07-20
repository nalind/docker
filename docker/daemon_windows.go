// +build daemon

package main

import (
	"os"

	apiserver "github.com/docker/docker/api/server"
	"github.com/docker/docker/daemon"
)

func setPlatformServerConfig(serverConfig *apiserver.Config, daemonCfg *daemon.Config) *apiserver.Config {
	serverConfig.AuthOptions = daemonCfg.AuthOptions
	return serverConfig
}

// currentUserIsOwner checks whether the current user is the owner of the given
// file.
func currentUserIsOwner(f string) bool {
	return false
}

// setDefaultUmask doesn't do anything on windows
func setDefaultUmask() error {
	return nil
}

func getDaemonConfDir() string {
	return os.Getenv("PROGRAMDATA") + `\docker\config`
}
