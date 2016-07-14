package main

import (
	"fmt"
	"os"

	"github.com/docker/docker/pkg/mflag"
)

func status(flags *mflag.FlagSet, action string, m Mall, args []string) int {
	status, err := m.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "status: %v\n", err)
		return 1
	}
	for _, pair := range status {
		fmt.Fprintf(os.Stderr, "%s: %s\n", pair[0], pair[1])
	}
	return 0
}

func init() {
	commands = append(commands, command{
		names:   []string{"status"},
		usage:   "Check on graph driver status",
		minArgs: 0,
		action:  status,
	})
}
