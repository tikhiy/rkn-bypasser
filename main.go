package main

import (
	"fmt"
	"os"

	"github.com/dimuls/rkn-bypasser/proxy"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Usage = "RNK bypasser proxy server"
	app.Version = "1.2"
	app.Author = "Vadim Chernov"
	app.Email = "dimuls@yandex.ru"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "bind-addr",
			Usage:  "bind address",
			EnvVar: "BIND_ADDR",
		},
		cli.StringFlag{
			Name:   "tor-addr",
			Usage:  "tor proxy server address",
			EnvVar: "TOR_ADDR",
			Value:  "127.0.0.1:9050",
		},
		cli.BoolFlag{
			Name:   "with-additional-ips",
			Usage:  "use additional blocked IPs file",
			EnvVar: "WITH_ADDITIONAL_IPS",
		},
	}

	app.Action = run

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	if !c.IsSet("bind-addr") {
		logrus.Fatal("Set BIND_ADDR environment variable or -bind-addr flag")
	}

	bindAddr := c.String("bind-addr")
	torAddr := c.String("tor-addr")
	withAdditionalIPs := c.Bool("with-additional-ips")

	logrus.WithFields(logrus.Fields{
		"bindAddr":          bindAddr,
		"torAddr":           torAddr,
		"withAdditionalIPs": withAdditionalIPs,
	}).Info("Running proxy")

	proxy.Run(bindAddr, torAddr, withAdditionalIPs)

	return nil
}
