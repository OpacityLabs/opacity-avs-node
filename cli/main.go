package main

import (
	"os"

	"github.com/OpacityLabs/opacity-avs-node/cli/actions"
	"github.com/urfave/cli"
)

var (
	/* Required Flags */
	ConfigFileFlag = cli.StringFlag{
		Name:     "config",
		Required: true,
		Usage:    "Load configuration from `FILE`",
	}
	/* Optional Flags */
)

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{ConfigFileFlag}
	app.Commands = []cli.Command{
		{
			Name:    "register-operator-with-avs",
			Aliases: []string{"r"},
			Usage:   "registers operator with avs registry",
			Action:  actions.RegisterOperatorWithAvs,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
