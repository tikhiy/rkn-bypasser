package proxy

import (
	"context"
	"net"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

type dialer struct {
	torAddr string
}

func (d dialer) torDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5(network, d.torAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d dialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ip := strings.Split(addr, ":")[0]
	if blockedIPs.Has(ip) {
		return d.torDial(ctx, network, addr)
	}
	return net.Dial(network, addr)
}

func Run(bindAddr string, torAddr string, withAdditionalIPs bool) {

	initBlockedIPs(withAdditionalIPs)

	d := dialer{torAddr: torAddr}

	server, err := socks5.New(&socks5.Config{Dial: d.dial})
	if err != nil {
		logrus.WithError(err).Fatal(
			"Failed to create SOCKS5 proxy server")
	}

	if err := server.ListenAndServe("tcp", bindAddr); err != nil {
		logrus.WithError(err).Fatal(
			"Failed to start SOCKS5 proxy server")
	}
}
