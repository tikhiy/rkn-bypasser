package main

import (
	"context"
	_ "embed"
	"sync"
	"time"

	"github.com/getlantern/systray"

	"github.com/dimuls/rkn-bypasser/proxy"
)

//go:generate go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
//go:generate goversioninfo -icon=icon.ico

//go:embed icon.ico
var icon []byte

var wg sync.WaitGroup
var ctx context.Context
var disable context.CancelFunc
var proxyServer *proxy.Server
var listenEvents chan proxy.ServerListenEvent
var listenErrors = make(chan error)

func main() {
	listenEvents = make(chan proxy.ServerListenEvent, 10)

	proxyServer, _ = proxy.NewServer(
		proxy.WithListenEvents(listenEvents))

	systray.Run(onReady, func() {})
}

func enable() {
	ctx, disable = context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := proxyServer.Listen(ctx)
		if err != nil {
			listenErrors <- err
		}
	}()
}

func onReady() {

	systray.SetIcon(icon)
	systray.SetTitle("Обход блокировок РКН")

	mEnable := systray.AddMenuItem("Включить", "Включить прокси сервер")
	mEnabling := systray.AddMenuItem("Включение...", "Прокси сервер в процессе включения")
	mDisable := systray.AddMenuItem("Выключить", "Выключить прокси сервер")
	mDisabling := systray.AddMenuItem("Выключение...", "Прокси сервер в процессе выключения")

	systray.AddSeparator()

	mExit := systray.AddMenuItem("Выйти", "Выйти из программы")

	enable()

	mEnable.Hide()
	mEnabling.Disable()
	mDisable.Hide()
	mDisabling.Hide()
	mExit.Disable()

	for {
		select {
		case <-listenErrors:
			disable()
		case e := <-listenEvents:
			switch e {
			case proxy.Started:
				mEnable.Hide()
				mEnabling.Hide()
				mDisable.Show()
				mExit.Enable()
			case proxy.Stopped:
				mEnable.Show()
				mDisable.Hide()
				mDisabling.Hide()
				mExit.Enable()
			}
		case <-mEnable.ClickedCh:
			mEnable.Hide()
			mEnabling.Disable()
			mExit.Disable()
			enable()
		case <-mDisable.ClickedCh:
			disable()
			mDisable.Hide()
			mDisabling.Disable()
			mExit.Disable()
			wg.Wait()
		case <-mExit.ClickedCh:
			disable()
			mDisable.Hide()
			mDisabling.Disable()
			mExit.Disable()
			wg.Wait()
			systray.Quit()
			time.Sleep(1 * time.Second)
			return
		}
	}
}
