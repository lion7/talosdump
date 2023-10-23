VERSION:=$(shell git describe)

build:
	go build -o talosdump-linux-amd64

release: build
	gh release create --generate-notes "$(VERSION)" talosdump-linux-amd64
