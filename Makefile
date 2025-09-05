VERSION:=$(shell git describe)

build:
	go build -o talosdump-linux-amd64

install: build
	install talosdump-linux-amd64 ~/.local/lib/wireshark/extcap/talosdump

release: build
	gh release create -d --generate-notes "$(VERSION)" talosdump-linux-amd64
