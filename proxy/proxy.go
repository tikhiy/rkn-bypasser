package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cretz/bine/process"

	"github.com/cretz/bine/tor"
	"github.com/things-go/go-socks5"
	"go.uber.org/zap"
)

const (
	proxyNetwork = "tcp"

	defaultListenAddr             = "127.0.0.1:8000"
	defaultBlockedIPsURI          = "https://reestr.rublacklist.net/api/v2/ips/json"
	defaultBlockedIPsUpdatePeriod = 3 * time.Hour
	defaultTorPath                = "tor"
)

var defaultTorArgs = []string{"--quiet"}

//go:generate curl https://dist.torproject.org/torbrowser/11.0.1/tor-win64-0.4.6.8.zip -o tor.zip
//go:embed tor.zip
var torZIP []byte

type Server struct {
	listenAddr             string
	blockedIPsURI          string
	blockedIPsUpdatePeriod time.Duration
	torPath                string
	torrcFile              string
	torArgs                []string
	listenEvents           chan<- ServerListenEvent

	blockedIPsMx sync.RWMutex
	blockedIPs   map[string]struct{}

	logger *zap.Logger
}

func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{
		listenAddr:             defaultListenAddr,
		blockedIPsURI:          defaultBlockedIPsURI,
		blockedIPsUpdatePeriod: defaultBlockedIPsUpdatePeriod,
		torPath:                defaultTorPath,
		torArgs:                defaultTorArgs,

		blockedIPs: map[string]struct{}{},
	}

	for _, o := range opts {
		o(s)
	}

	if s.logger == nil {
		logger, err := zap.NewDevelopment()
		if err != nil {
			return nil, fmt.Errorf("create logger: %w", err)
		}
		s.logger = logger
	}

	return s, nil
}

type ServerOption func(s *Server)

func WithListenAddr(addr string) ServerOption {
	return func(s *Server) {
		s.listenAddr = addr
	}
}

func WithBlockedIPsURI(uri string) ServerOption {
	return func(s *Server) {
		s.blockedIPsURI = uri
	}
}

func WithBlockedIPsUpdatePeriod(period time.Duration) ServerOption {
	return func(s *Server) {
		s.blockedIPsUpdatePeriod = period
	}
}

func WithTorPath(path string) ServerOption {
	return func(s *Server) {
		s.torPath = path
	}
}

func WithTorrcFile(path string) ServerOption {
	return func(s *Server) {
		s.torrcFile = path
	}
}

func WithTorArgs(args []string) ServerOption {
	return func(s *Server) {
		s.torArgs = args
	}
}

func WithLogger(logger *zap.Logger) ServerOption {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithListenEvents(events chan<- ServerListenEvent) ServerOption {
	return func(s *Server) {
		s.listenEvents = events
	}
}

func (s *Server) loadBlockedIPs(ctx context.Context) error {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.blockedIPsURI, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return fmt.Errorf("get blocked ips: %w", err)
	}

	defer resp.Body.Close()

	var ips []string

	err = json.NewDecoder(resp.Body).Decode(&ips)
	if err != nil {
		return fmt.Errorf("json decode blocked ips: %w", err)
	}

	newBlockedIPs := map[string]struct{}{}

	for _, ip := range ips {
		newBlockedIPs[ip] = struct{}{}
	}

	s.blockedIPsMx.Lock()
	s.blockedIPs = newBlockedIPs
	s.blockedIPsMx.Unlock()

	return nil
}

func uncompressZIP(ctx context.Context, archive io.ReaderAt, size int, destination string) error {

	r, err := zip.NewReader(archive, int64(size))
	if err != nil {
		return fmt.Errorf("create zip reader: %w", err)
	}

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		filePath := filepath.Join(destination, f.Name)

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(filePath, 0755)
			if err != nil {
				return fmt.Errorf("create directory `%s`: %w", filePath, err)
			}
			continue
		}

		err = os.MkdirAll(filepath.Dir(filePath), 0755)
		if err != nil {
			return fmt.Errorf("create directory `%s`: %w", filePath, err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("open file `%s`: %w", filePath, err)
		}

		srcFile, err := f.Open()
		if err != nil {
			dstFile.Close()
			return fmt.Errorf("open file in archive `%s`: %w", f.Name, err)
		}

		_, err = io.Copy(dstFile, srcFile)

		dstFile.Close()
		srcFile.Close()

		if err != nil {
			return fmt.Errorf("copy file: %w", err)
		}
	}

	return nil
}

func (s *Server) initTorPath(ctx context.Context) error {

	stat, err := os.Stat(s.torPath)
	if err == nil {
		if stat.IsDir() {
			return nil
		} else {
			return fmt.Errorf("expected tor path is directory but file found")
		}
	}

	err = uncompressZIP(ctx, bytes.NewReader(torZIP), len(torZIP), s.torPath)
	if err != nil {
		return fmt.Errorf("uncompress tor: %w", err)
	}

	return nil
}

type ServerListenEvent int8

const (
	LoadingBlockedIPs ServerListenEvent = iota
	InitializingTor
	StartingTor
	StartingProxy
	Started
	Stopped
)

func (e ServerListenEvent) String() string {
	switch e {
	case LoadingBlockedIPs:
		return "loading-blocked-ips"
	case InitializingTor:
		return "initializing-tor"
	case StartingTor:
		return "starting-tor"
	case StartingProxy:
		return "starting-proxy"
	case Started:
		return "started"
	case Stopped:
		return "stopped"
	}
	return ""
}

func (s *Server) send(e ServerListenEvent) {
	if s.listenEvents != nil {
		s.listenEvents <- e
	}
}

func (s *Server) Listen(ctx context.Context) error {

	var wg sync.WaitGroup

	s.logger.Info("loading blocked ips")
	s.send(LoadingBlockedIPs)

	err := s.loadBlockedIPs(ctx)
	if err != nil {
		return fmt.Errorf("load blocked ips: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer s.logger.Info("blocked ips loader stopped")

		t := time.NewTicker(3 * time.Hour)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			err := s.loadBlockedIPs(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					s.logger.Error("failed to load blocked ips", zap.Error(err))
				}
				return
			}
		}
	}()

	s.logger.Info("blocked ips loaded")

	s.logger.Info("initializing tor")
	s.send(InitializingTor)

	err = s.initTorPath(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("unzip tor: %w", err)
	}

	torTempDir := filepath.Join(s.torPath, "Temp")

	err = os.MkdirAll(torTempDir, 0755)
	if err != nil {
		return fmt.Errorf("create tor temp dir: %w", err)
	}

	s.logger.Info("tor initialized")

	s.logger.With(
		zap.String("tor_path", s.torPath),
		zap.String("torrc_file", s.torrcFile),
		zap.Strings("tor_args", s.torArgs),
	).Info("starting tor")
	s.send(StartingTor)

	t, err := tor.Start(ctx, &tor.StartConf{
		ProcessCreator: process.CmdCreatorFunc(func(ctx context.Context, args ...string) (*exec.Cmd, error) {
			cmd := exec.CommandContext(ctx, filepath.Join(s.torPath, "Tor/tor.exe"), args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd, nil
		}),
		GeoIPFileReader: func(ipv6 bool) (io.ReadCloser, error) {
			if ipv6 {
				return os.Open(filepath.Join(s.torPath, "Data/Tor/geoip6"))
			}
			return os.Open(filepath.Join(s.torPath, "Data/Tor/geoip"))
		},
		TempDataDirBase: torTempDir,
		TorrcFile:       s.torrcFile,
		ExtraArgs:       s.torArgs,
	})
	if err != nil {
		return fmt.Errorf("start tor: %w", err)
	}

	defer t.Close()

	td, err := t.Dialer(ctx, nil)
	if err != nil {
		return fmt.Errorf("init tor dialer: %w", err)
	}

	s.logger.Info("tor started")

	s.logger.With(zap.String("listen_addr", s.listenAddr)).
		Info("starting proxy server")
	s.send(StartingProxy)

	d := &net.Dialer{}

	ss := socks5.NewServer(socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		ip, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("split addr host and port: %w", err)
		}
		s.blockedIPsMx.RLock()
		_, blocked := s.blockedIPs[ip]
		s.blockedIPsMx.RUnlock()
		if blocked {
			return td.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}))

	l, err := net.Listen(proxyNetwork, s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen bind address: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.logger.Info("proxy server stopped")
		for {
			err = ss.Serve(l)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Error("failed to serve socks5 proxy", zap.Error(err))
				time.Sleep(time.Second)
			}
		}
	}()

	s.logger.Info("proxy server started")
	s.send(Started)

	<-ctx.Done()
	l.Close()
	wg.Wait()

	s.send(Stopped)

	return nil
}
