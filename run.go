package main

import (
	"log"

	"github.com/getlantern/errors"
	"github.com/someanon/rkn-bypasser/proxy"
	"gopkg.in/urfave/cli.v1"
)

func run(c *cli.Context) error {
	initLog()

	if !c.IsSet("addr") {
		log.Fatal("[ERR] Set ADDR environment variable or -addr flag")
		return errors.New("addr is not set")
	}

	addr := c.String("addr")
	torAddr := c.String("tor")

	if torAddr == "" && c.Bool("with-tor") {
		torAddr = "tor-proxy:9150"
	}

	torStr := "without tor"
	if torAddr != "" {
		torStr = "with tor " + torAddr
	}
	log.Printf("Running at %s %s\n", addr, torStr)

	proxy.Run(addr, torAddr)
	return nil
}
