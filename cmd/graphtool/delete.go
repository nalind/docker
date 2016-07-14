package main

import (
	"fmt"
	"os"

	"github.com/docker/docker/pkg/mflag"
)

func deletepet(flags *mflag.FlagSet, action string, m Mall, args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "No pet filesystem specified.\n")
		return 1
	}
	if err := m.DeletePet(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

func init() {
	commands = append(commands, command{
		names:       []string{"delete", "release"},
		optionsHelp: "layerName",
		usage:       "Delete (release) a pet read-write layer",
		minArgs:     1,
		action:      deletepet,
	})
}
