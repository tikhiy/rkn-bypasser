.PHONY: default clean
default: build/rkn-bypasser-tray.exe build/rkn-bypasser.exe

clean:
	rm -rf cmd/rkn-bypasser-tray/resource.syso proxy/tor.zip release

proxy/tor.zip:
	go generate ./proxy/proxy.go

cmd/rkn-bypasser-tray/resource.syso:
	go generate cmd/rkn-bypasser-tray/main.go

build/rkn-bypasser-tray.exe: proxy/tor.zip
	GOOS=windows GOARCH=amd64 go build -ldflags "-H windowsgui" -o release/rkn-bypasser-tray.exe ./cmd/rkn-bypasser-tray

build/rkn-bypasser.exe: proxy/tor.zip cmd/rkn-bypasser-tray/resource.syso
	GOOS=windows GOARCH=amd64 go build -o release/rkn-bypasser.exe ./cmd/rkn-bypasser