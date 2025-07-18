PROJECT         := github.com/jasonmadigan/podman-mac-net-connect
SETUP_IMAGE     := ghcr.io/jasonmadigan/podman-mac-net-connect
VERSION         := 0.1.1
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION}

run:: build-podman run-go
build:: build-podman build-go

run-go::
	go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go::
	go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}

# Local development build (single arch)
build-podman::
	podman build -f ./client/Dockerfile -t ${SETUP_IMAGE}:${VERSION} ./client

# Local development - build and push (for testing)
build-push:: build-podman
	podman push ${SETUP_IMAGE}:${VERSION}
