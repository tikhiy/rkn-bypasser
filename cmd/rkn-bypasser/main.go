package main

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"go.uber.org/zap"

	"github.com/dimuls/rkn-bypasser/proxy"
)

func main() {

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to init logger")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		sig := make(chan os.Signal)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		<-sig

		logger.Info("stop signal received, stopping")

		cancel()

		logger.Info("everything is stopped, exiting")
	}()

	s, err := proxy.NewServer(proxy.WithLogger(logger))
	if err != nil {
		logger.Fatal("failed to create proxy server", zap.Error(err))
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		err = s.Listen(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Fatal("proxy server failed to listen", zap.Error(err))
		}
	}()

	wg.Wait()
}
