.PHONY: default clean
default: release/rkn-bypasser-tray.exe release/rkn-bypasser.exe

clean:
	rm -rf cmd/rkn-bypasser-tray/resource.syso proxy/tor.zip release

proxy/tor.zip:
	go generate ./proxy/proxy.go

cmd/rkn-bypasser-tray/resource.syso:
	go generate cmd/rkn-bypasser-tray/main.go

release/rkn-bypasser-tray.exe: proxy/tor.zip
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H windowsgui" -o release/rkn-bypasser-tray.exe ./cmd/rkn-bypasser-tray

release/rkn-bypasser.exe: proxy/tor.zip cmd/rkn-bypasser-tray/resource.syso
	GOOS=windows GOARCH=amd64 go build -trimpath -o release/rkn-bypasser.exe ./cmd/rkn-bypasser