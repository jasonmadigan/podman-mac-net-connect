PROJECT         := github.com/jasonmadigan/podman-mac-net-connect
SETUP_IMAGE     := quay.io/jasonmadigan/podman-mac-net-connect
VERSION         := 0.0.1
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION} -X ${PROJECT}/version.SetupImage=${SETUP_IMAGE}

run:: build-podman run-go
build:: build-podman build-go

run-go::
	go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go::
	go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}

build-podman::
	podman build -t ${SETUP_IMAGE}:${VERSION} ./client

build-push-quay::
	podman buildx build --platform linux/amd64,linux/arm64 --push -t ${SETUP_IMAGE}:${VERSION} ./client