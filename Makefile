.PHONY: all build-core build-macos build-all test selftest run-web run-app clean

BINARY := dist/gridshield
APP_BUNDLE := dist/GridShieldVPN.app

all: build-core build-macos

build-core:
	@mkdir -p dist
	go build -ldflags="-s -w" -o $(BINARY) ./cmd/gridshield

build-macos: build-core
	./macos/GridShieldApp/build_app.sh

# Cross-compile CLI + Embedded Web Dashboard for macOS, Linux, and Windows
build-all:
	@mkdir -p dist/release
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/release/gridshield-darwin-arm64 ./cmd/gridshield
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/release/gridshield-darwin-amd64 ./cmd/gridshield
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/release/gridshield-linux-amd64 ./cmd/gridshield
	GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/release/gridshield-linux-arm64 ./cmd/gridshield
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/release/gridshield-windows-amd64.exe ./cmd/gridshield
	@ls -lh dist/release/

test:
	go test -v -race ./...

selftest: build-core
	./$(BINARY) selftest --ascii prefer_ascii --aead chacha20-poly1305 --httpmask auto
	./$(BINARY) selftest --ascii prefer_entropy --aead aes-128-gcm --httpmask ws

run-web: build-core
	./$(BINARY) daemon --open

run-app: build-macos
	open $(APP_BUNDLE)

clean:
	rm -rf dist macos/GridShieldApp/.build
