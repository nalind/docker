package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cow"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/pkg/reexec"
)

type command struct {
	names       []string
	optionsHelp string
	minArgs     int
	maxArgs     int
	usage       string
	addFlags    func(*mflag.FlagSet, *command)
	action      func(*mflag.FlagSet, string, cow.Mall, []string) int
}

var commands = []command{}

func main() {
	if reexec.Init() {
		return
	}

	graphRoot := "/var/lib/cowman"
	graphDriver := os.Getenv("DOCKER_GRAPHDRIVER")
	graphOptions := strings.Split(os.Getenv("DOCKER_STORAGE_OPTS"), ",")
	if len(graphOptions) == 1 && graphOptions[0] == "" {
		graphOptions = nil
	}
	debug := false

	makeFlags := func(command string, eh mflag.ErrorHandling) *mflag.FlagSet {
		flags := mflag.NewFlagSet(command, eh)
		flags.StringVar(&graphRoot, []string{"-graph", "g"}, graphRoot, "Root of the storage tree")
		flags.StringVar(&graphDriver, []string{"-storage-driver", "s"}, graphDriver, "Storage driver to use ($DOCKER_GRAPHDRIVER)")
		flags.Var(opts.NewListOptsRef(&graphOptions, nil), []string{"-storage-opt"}, "Set storage driver options ($DOCKER_STORAGE_OPTS)")
		flags.BoolVar(&debug, []string{"-debug", "D"}, debug, "Print debugging information")
		return flags
	}

	flags := makeFlags("cowman", mflag.ContinueOnError)
	flags.Usage = func() {
		fmt.Printf("Usage: cowman command [options [...]]\n\n")
		fmt.Printf("Commands:\n\n")
		for _, command := range commands {
			fmt.Printf("  %-14s%s\n", command.names[0], command.usage)
		}
		fmt.Printf("\nOptions:\n")
		flags.PrintDefaults()
	}

	if len(os.Args) < 2 {
		flags.Usage()
		os.Exit(1)
	}
	if err := flags.ParseFlags(os.Args[1:], true); err != nil {
		fmt.Printf("%v while parsing arguments (1)\n", err)
		flags.Usage()
		os.Exit(1)
	}

	args := flags.Args()
	if len(args) < 1 {
		flags.Usage()
		os.Exit(1)
		return
	}
	cmd := args[0]

	for _, command := range commands {
		for _, name := range command.names {
			if cmd == name {
				flags := makeFlags(cmd, mflag.ExitOnError)
				if command.addFlags != nil {
					command.addFlags(flags, &command)
				}
				flags.Usage = func() {
					fmt.Printf("Usage: cowman %s %s\n\n", cmd, command.optionsHelp)
					fmt.Printf("%s\n", command.usage)
					fmt.Printf("\nOptions:\n")
					flags.PrintDefaults()
				}
				if err := flags.ParseFlags(args[1:], false); err != nil {
					fmt.Printf("%v while parsing arguments (3)", err)
					flags.Usage()
					os.Exit(1)
				}
				args = flags.Args()
				if command.minArgs != 0 && len(args) < command.minArgs {
					fmt.Printf("%s: more arguments required.\n", cmd, args)
					flags.Usage()
					os.Exit(1)
				}
				if command.maxArgs != 0 && len(args) > command.maxArgs {
					fmt.Printf("%s: too many arguments (%s).\n", cmd, args)
					flags.Usage()
					os.Exit(1)
				}
				if debug {
					logrus.SetLevel(logrus.DebugLevel)
					logrus.Debugf("graphRoot: %s", graphRoot)
					logrus.Debugf("graphDriver: %s", graphDriver)
					logrus.Debugf("graphOptions: %s", graphOptions)
				} else {
					logrus.SetLevel(logrus.ErrorLevel)
				}
				if err := os.MkdirAll(graphRoot, 0700); err != nil && !os.IsExist(err) {
					fmt.Printf("%s: %v\n", graphRoot, err)
					os.Exit(1)
				}
				for _, subdir := range []string{"mounts", "tmp", graphDriver} {
					if err := os.MkdirAll(filepath.Join(graphRoot, subdir), 0700); err != nil && !os.IsExist(err) {
						fmt.Printf("%s: %v\n", filepath.Join(graphRoot, subdir), err)
						os.Exit(1)
					}
				}
				if fd, err := syscall.Open(filepath.Join(graphRoot, "cowman.lock"), os.O_RDWR, syscall.S_IRUSR|syscall.S_IWUSR); err != nil {
					fmt.Printf("error obtaining lock: %v\n", err)
					os.Exit(1)
				} else {
					lk := syscall.Flock_t{
						Type:   syscall.F_WRLCK,
						Whence: int16(os.SEEK_SET),
						Start:  0,
						Len:    0,
						Pid:    int32(os.Getpid()),
					}
					if err = syscall.FcntlFlock(uintptr(fd), syscall.F_SETLKW, &lk); err != nil {
						fmt.Printf("error obtaining lock: %v\n", err)
						os.Exit(1)
					}
				}
				mall := cow.MakeMall(graphRoot, graphDriver, graphOptions)
				os.Exit(command.action(flags, cmd, mall, args))
				break
			}
		}
	}
	fmt.Printf("%s: unrecognized command.\n", cmd)
	os.Exit(1)
}
