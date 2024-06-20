package main

import (
	"log"
	"os"

	"github.com/Layr-Labs/incredible-squaring-avs/core/config"
	"github.com/OpacityLabs/opacity-avs-node/cli/actions"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{config.ConfigFileFlag}
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
		log.Fatal(err)
	}
}
