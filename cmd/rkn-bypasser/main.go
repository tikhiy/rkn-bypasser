package main

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/dimuls/rkn-bypasser/proxy"
)

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		panic("failed to init logger")
	}
}

func run(*cobra.Command, []string) {

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer logger.Info("everything is stopped, exiting")
		defer wg.Done()

		sig := make(chan os.Signal)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		<-sig
		logger.Info("stop signal received, stopping")
		cancel()
	}()

	s, err := proxy.NewServer(proxy.WithLogger(logger),
		proxy.WithListenAddr(viper.GetString("listen-address")),
		proxy.WithTorPath(viper.GetString("tor-path")),
		proxy.WithTorrcFile(viper.GetString("torrc")),
		proxy.WithTorArgs(viper.GetStringSlice("tor-args")))
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

var cmd = &cobra.Command{
	Use:   "rkn-bypasser",
	Short: "RKN blocks bypass service",
	Run:   run,
}

var (
	cfgFile string
)

func init() {
	cobra.OnInitialize(initConfig)

	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .\\rkn-bypasser.yaml)")

	cmd.Flags().String("listen-address", "127.0.0.1:8000", "proxy server listen address")
	cmd.Flags().String("tor-path", "tor", "tor path")
	cmd.Flags().String("torrc", "", "torrc file path")
	cmd.Flags().StringSlice("tor-args", []string{"--quiet"}, "tor args to use")

	viper.BindPFlags(cmd.Flags())
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("rkn-bypasser")
	}

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err == nil {
		logger.With(zap.String("config", viper.ConfigFileUsed())).
			Info("using config")
	}

}

func main() {
	cmd.Execute()
}
