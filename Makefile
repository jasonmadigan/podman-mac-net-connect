PROJECT         := github.com/jasonmadigan/podman-mac-net-connect
SETUP_IMAGE     := quay.io/jmadigan/podman-mac-net-connect
VERSION         := 0.0.7
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION}

run:: build-podman run-go
build:: build-podman build-go

run-go::
	go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go::
	go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}

# Building for amd64 and arm64
build-podman::
	# Build for amd64
	podman build --arch=amd64 -f ./client/Dockerfile.amd64 -t ${SETUP_IMAGE}:${VERSION}-amd64 ./client
	podman push ${SETUP_IMAGE}:${VERSION}-amd64
	# Build for arm64
	podman build --arch=arm64 -f ./client/Dockerfile.arm64 -t ${SETUP_IMAGE}:${VERSION}-arm64 ./client
	podman push ${SETUP_IMAGE}:${VERSION}-arm64
	# Create and push manifest
	podman manifest create ${SETUP_IMAGE}:${VERSION}
	podman manifest add ${SETUP_IMAGE}:${VERSION} docker://${SETUP_IMAGE}:${VERSION}-amd64
	podman manifest add ${SETUP_IMAGE}:${VERSION} docker://${SETUP_IMAGE}:${VERSION}-arm64
	podman manifest push --all ${SETUP_IMAGE}:${VERSION} docker://${SETUP_IMAGE}:${VERSION}


# Simplified target for pushing to Quay, relies on build-podman for actual build and push steps
build-push-quay:: build-podman
