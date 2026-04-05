PROJECT         := github.com/jasonmadigan/podman-mac-net-connect
VERSION         := 0.1.0
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION}

run:: build-go run-go

build:: build-go

run-go::
	go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go::
	go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}
