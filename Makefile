PROJECT         := github.com/chipmk/docker-mac-net-connect
SETUP_IMAGE     := quay.io/philbrookes/podman-connect
VERSION         := best
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION} -X ${PROJECT}/version.SetupImage=${SETUP_IMAGE}

run:: build-docker run-go
build:: build-docker build-go

run-go::
	go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go::
	go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}

build-docker::
	podman build -t ${SETUP_IMAGE}:${VERSION} ./client

build-push-docker::
	podman buildx build --platform linux/amd64,linux/arm64 --push -t ${SETUP_IMAGE}:${VERSION} ./client