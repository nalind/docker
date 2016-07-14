package main

import (
	"fmt"
	"os"

	"github.com/docker/docker/pkg/mflag"
)

func wipe(flags *mflag.FlagSet, action string, m Mall, args []string) int {
	err := m.Wipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", err)
		return 1
	}
	return 0
}

func init() {
	commands = append(commands, command{
		names:   []string{"wipe"},
		usage:   "Wipe all layers",
		minArgs: 0,
		action:  wipe,
	})
}
