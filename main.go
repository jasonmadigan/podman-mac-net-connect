//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jasonmadigan/podman-mac-net-connect/networkmanager"
	"github.com/jasonmadigan/podman-mac-net-connect/version"

	"github.com/containers/podman/v4/pkg/bindings"
	"github.com/containers/podman/v4/pkg/bindings/containers"
	"github.com/containers/podman/v4/pkg/bindings/images"
	"github.com/containers/podman/v4/pkg/bindings/network"
	"github.com/containers/podman/v4/pkg/bindings/system"
	"github.com/containers/podman/v4/pkg/domain/entities"
	"github.com/containers/podman/v4/pkg/specgen"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

// getPodmanConnection gets the Podman connection details using the official podman system connection command
func getPodmanConnection() (string, string, error) {
	// Get the list of system connections in JSON format
	cmd := exec.Command("podman", "system", "connection", "list", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to list podman connections: %w", err)
	}

	// Parse the JSON response
	var connections []PodmanSystemConnection
	if err := json.Unmarshal(output, &connections); err != nil {
		return "", "", fmt.Errorf("failed to parse podman connections: %w", err)
	}

	if len(connections) == 0 {
		return "", "", fmt.Errorf("no podman connections found")
	}

	// Prefer root connection for privileged operations, fallback to default
	var selectedConnection *PodmanSystemConnection
	for _, conn := range connections {
		// Look for a root connection (contains 'root' in URI)
		if strings.Contains(conn.URI, "root@") {
			selectedConnection = &conn
			break
		}
	}

	// If no root connection found, use the default connection
	if selectedConnection == nil {
		for _, conn := range connections {
			if conn.Default {
				selectedConnection = &conn
				break
			}
		}
	}

	// If still no connection found, use the first one
	if selectedConnection == nil {
		selectedConnection = &connections[0]
	}

	fmt.Printf("Selected Podman connection: %s (%s)\n", selectedConnection.Name, selectedConnection.URI)
	return selectedConnection.URI, selectedConnection.Identity, nil
}

// PodmanConnectionDetails holds the connection URI and identity file path for Podman API access.
type PodmanConnectionDetails struct {
	URI      string
	Identity string
}

// PodmanSystemConnection represents a connection from 'podman system connection list'
type PodmanSystemConnection struct {
	Name      string `json:"Name"`
	URI       string `json:"URI"`
	Identity  string `json:"Identity"`
	IsMachine bool   `json:"IsMachine"`
	Default   bool   `json:"Default"`
}

// loadWireGuardModule attempts to load the WireGuard module using a privileged container
func loadWireGuardModule(podmanCli context.Context) error {
	// Use a minimal alpine image to run modprobe
	imageName := "alpine:latest"

	// Check if the image exists locally, pull if not
	_, err := images.GetImage(podmanCli, imageName, &images.GetOptions{})
	if err != nil {
		fmt.Printf("Image (%v) doesn't exist locally. Pulling...\n", imageName)
		_, err := images.Pull(podmanCli, imageName, &images.PullOptions{})
		if err != nil {
			return fmt.Errorf("failed to pull alpine image: %w", err)
		}
	}

	// Clean up any existing container with the same name
	containerName := "wireguard-module-loader"
	cleanupContainer(podmanCli, containerName) // Ignore errors - container might not exist

	// Create a privileged container to load the WireGuard module
	resp, err := containers.CreateWithSpec(podmanCli, &specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:         containerName,
			RawImageName: imageName,
			Remove:       true,
			Command:      []string{"modprobe", "wireguard"},
		},
		ContainerSecurityConfig: specgen.ContainerSecurityConfig{
			CapAdd: []string{"NET_ADMIN", "SYS_MODULE"},
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image: imageName,
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			NetNS: specgen.Namespace{
				NSMode: specgen.Host,
			},
		},
	}, &containers.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create wireguard module loader container: %w", err)
	}

	// Start the container
	err = containers.Start(podmanCli, resp.ID, &containers.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start wireguard module loader container: %w", err)
	}

	// Wait for the container to complete
	_, err = containers.Wait(podmanCli, resp.ID, &containers.WaitOptions{})
	if err != nil {
		return fmt.Errorf("failed to wait for wireguard module loader container: %w", err)
	}

	fmt.Println("WireGuard module loaded successfully via container.")
	return nil
}

func main() {
	uri, identity, err := getPodmanConnection()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Found Podman connection")
	fmt.Println("URI:", uri)
	fmt.Println("Identity file:", identity)

	connectionDetails := PodmanConnectionDetails{
		URI:      uri,
		Identity: identity,
	}

	fmt.Printf("Connection URI: %s, Identity File: %s\n", connectionDetails.URI, connectionDetails.Identity)

	// Create Podman connection early so we can use it for module loading
	fmt.Printf("Creating Podman connection with URI: %s and Identity: %s\n", connectionDetails.URI, connectionDetails.Identity)
	podmanCtx, err := bindings.NewConnectionWithIdentity(context.Background(), connectionDetails.URI, connectionDetails.Identity, false)
	if err != nil {
		fmt.Printf("Error creating Podman connection with identity: %v\n", err)
		os.Exit(ExitSetupFailed)
	}
	fmt.Println("Successfully created Podman connection with identity.")

	// Load WireGuard module using privileged container
	if err := loadWireGuardModule(podmanCtx); err != nil {
		fmt.Printf("Error loading WireGuard module: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelVerbose
	}()

	fmt.Printf("podman-mac-net-connect version '%s'\n", version.Version)

	tun, err := tun.CreateTUN("utun", device.DefaultMTU)
	if err != nil {
		fmt.Printf("Failed to create TUN device: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	interfaceName, err := tun.Name()
	if err != nil {
		fmt.Printf("Failed to get TUN device name: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	fileUAPI, err := ipc.UAPIOpen(interfaceName)

	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on UAPI socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// Wireguard configuration
	hostPeerIp := "10.33.34.1"
	vmPeerIp := "10.33.34.2"

	c, err := wgctrl.New()
	if err != nil {
		logger.Errorf("Failed to create new wgctrl client: %v", err)
		os.Exit(ExitSetupFailed)
	}

	defer c.Close()

	hostPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Errorf("Failed to generate host private key: %v", err)
		os.Exit(ExitSetupFailed)
	}

	vmPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Errorf("Failed to generate VM private key: %v", err)
		os.Exit(ExitSetupFailed)
	}

	_, wildcardIpNet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		logger.Errorf("Failed to parse wildcard CIDR: %v", err)
		os.Exit(ExitSetupFailed)
	}

	_, vmIpNet, err := net.ParseCIDR(vmPeerIp + "/32")
	if err != nil {
		logger.Errorf("Failed to parse VM peer CIDR: %v", err)
		os.Exit(ExitSetupFailed)
	}

	peer := wgtypes.PeerConfig{
		PublicKey: vmPrivateKey.PublicKey(),
		AllowedIPs: []net.IPNet{
			*wildcardIpNet,
			*vmIpNet,
		},
	}

	port := 3334
	err = c.ConfigureDevice(interfaceName, wgtypes.Config{
		ListenPort: &port,
		PrivateKey: &hostPrivateKey,
		Peers:      []wgtypes.PeerConfig{peer},
	})
	if err != nil {
		logger.Errorf("Failed to configure Wireguard device: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	networkManager := networkmanager.New()

	_, stderr, err := networkManager.SetInterfaceAddress(hostPeerIp, vmPeerIp, interfaceName)
	if err != nil {
		logger.Errorf("Failed to set interface address with ifconfig: %v. %v", err, stderr)
		os.Exit(ExitSetupFailed)
	}

	logger.Verbosef("Interface %s created\n", interfaceName)
	logger.Verbosef("Wireguard server listening\n")

	// Create cancellable context for background operations
	backgroundCtx, cancelBackground := context.WithCancel(podmanCtx)
	defer cancelBackground()

	// Set up VM once at startup
	go func() {
		for {
			select {
			case <-backgroundCtx.Done():
				logger.Verbosef("VM setup cancelled")
				return
			default:
			}

			err = setupPodmanVm(backgroundCtx, port, hostPeerIp, vmPeerIp, hostPrivateKey, vmPrivateKey)
			if err != nil {
				logger.Errorf("Failed to setup VM: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			logger.Verbosef("VM setup completed successfully")
			break // VM setup successful, exit the loop
		}

		// Start event-driven network monitoring
		monitorNetworkEvents(backgroundCtx, &networkManager, interfaceName, logger)
	}()

	// Wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
		logger.Verbosef("Received termination signal, shutting down gracefully...")
	case <-errs:
		logger.Verbosef("Error occurred, shutting down...")
	case <-device.Wait():
		logger.Verbosef("Device stopped, shutting down...")
	}

	// Cancel background operations
	cancelBackground()

	// Comprehensive cleanup
	performCleanup(podmanCtx, &networkManager, interfaceName, logger, uapi, device)

	logger.Verbosef("Shutdown complete")
}

func setupPodmanVm(
	podmanCli context.Context,
	serverPort int,
	hostPeerIp string,
	vmPeerIp string,
	hostPrivateKey wgtypes.Key,
	vmPrivateKey wgtypes.Key,
) error {

	imageName := fmt.Sprintf("%s:%s", version.SetupImage, version.Version)

	_, err := images.GetImage(podmanCli, imageName, &images.GetOptions{})
	if err != nil {
		fmt.Printf("Image (%v) doesn't exist locally. Pulling...\n", imageName)

		_, err := images.Pull(podmanCli, imageName, &images.PullOptions{})
		if err != nil {
			return fmt.Errorf("failed to pull setup image: %w", err)
		}
	}

	// Clean up any existing container with the same name
	containerName := "wireguard-setup"
	cleanupContainer(podmanCli, containerName) // Ignore errors - container might not exist

	resp, err := containers.CreateWithSpec(podmanCli, &specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:         containerName,
			RawImageName: imageName,
			Remove:       true,
			Env: map[string]string{
				"SERVER_PORT":     strconv.Itoa(serverPort),
				"HOST_PEER_IP":    hostPeerIp,
				"VM_PEER_IP":      vmPeerIp,
				"HOST_PUBLIC_KEY": hostPrivateKey.PublicKey().String(),
				"VM_PRIVATE_KEY":  vmPrivateKey.String(),
			},
			Command: []string{"./app"},
		},
		ContainerSecurityConfig: specgen.ContainerSecurityConfig{
			CapAdd: []string{"NET_ADMIN"},
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image: imageName,
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			NetNS: specgen.Namespace{
				NSMode: specgen.Host,
			},
		},
	}, &containers.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Run container to completion
	err = containers.Start(podmanCli, resp.ID, &containers.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	fmt.Println("Setup container complete")

	return nil
}

// monitorNetworkEvents monitors Podman events for network changes and updates routes accordingly
func monitorNetworkEvents(ctx context.Context, networkManager *networkmanager.NetworkManager, interfaceName string, logger *device.Logger) {
	// Create a context that can be cancelled
	monitorCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// First, process all existing networks
	networks, err := network.List(monitorCtx, &network.ListOptions{})
	if err != nil {
		logger.Errorf("Failed to list initial networks: %v", err)
		return
	}

	for _, net := range networks {
		logger.Verbosef("Processing existing network: %s", net.Name)
		networkManager.ProcessPodmanNetworkCreate(net, interfaceName)
	}

	// Set up event monitoring for network changes
	eventChan := make(chan entities.Event)
	cancelChan := make(chan bool)

	// Configure event filtering for network events
	stream := true
	eventOptions := &system.EventsOptions{
		Filters: map[string][]string{
			"type": {"network"},
		},
		Stream: &stream,
	}

	// Start event monitoring in a goroutine
	go func() {
		// Don't try to close the channel - let the events system handle it
		if err := system.Events(monitorCtx, eventChan, cancelChan, eventOptions); err != nil {
			logger.Errorf("Failed to monitor events: %v", err)
		}
	}()

	// Process network events
	for {
		select {
		case <-monitorCtx.Done():
			logger.Verbosef("Network monitoring cancelled")
			return
		case event, ok := <-eventChan:
			if !ok {
				logger.Verbosef("Event channel closed")
				return
			}
			logger.Verbosef("Received network event: %s - %s", event.Action, event.Actor.Attributes["name"])

			switch event.Action {
			case "create":
				// Get the specific network that was created
				networkName := event.Actor.Attributes["name"]
				if networkName != "" {
					networks, err := network.List(monitorCtx, &network.ListOptions{})
					if err != nil {
						logger.Errorf("Failed to list networks after create event: %v", err)
						continue
					}

					// Find the newly created network
					for _, net := range networks {
						if net.Name == networkName {
							logger.Verbosef("Processing new network: %s", net.Name)
							networkManager.ProcessPodmanNetworkCreate(net, interfaceName)
							break
						}
					}
				}
			case "remove":
				// Handle network removal (route cleanup)
				networkName := event.Actor.Attributes["name"]
				if networkName != "" {
					logger.Verbosef("Network removed: %s", networkName)
					networkManager.ProcessPodmanNetworkRemove(networkName)
				}
			}
		}
	}
}

// cleanupContainer removes a container by name, ignoring errors if it doesn't exist
func cleanupContainer(ctx context.Context, name string) error {
	force := true
	ignore := true
	_, err := containers.Remove(ctx, name, &containers.RemoveOptions{
		Force:  &force,
		Ignore: &ignore,
	})
	return err
}

// performCleanup handles graceful shutdown and cleanup of all resources
func performCleanup(podmanCtx context.Context, networkManager *networkmanager.NetworkManager, interfaceName string, logger *device.Logger, uapi net.Listener, device *device.Device) {
	logger.Verbosef("Starting cleanup process...")

	// Create a timeout context for cleanup operations
	cleanupCtx, cancel := context.WithTimeout(podmanCtx, 10*time.Second)
	defer cancel()

	// 1. Clean up network routes
	logger.Verbosef("Cleaning up network routes...")
	for _, network := range networkManager.PodmanNetworks {
		for _, subnet := range network.Subnets {
			if network.Driver == "bridge" {
				logger.Verbosef("Removing route for %s (%s)", subnet.Subnet, network.Name)
				_, stderr, err := networkManager.DeleteRoute(subnet.Subnet.String())
				if err != nil {
					logger.Errorf("Failed to remove route %s: %v. %v", subnet.Subnet, err, stderr)
				}
			}
		}
	}

	// 2. Clean up any running containers we created
	logger.Verbosef("Cleaning up containers...")
	containerNames := []string{"wireguard-module-loader", "wireguard-setup"}
	for _, containerName := range containerNames {
		if err := cleanupContainer(cleanupCtx, containerName); err != nil {
			logger.Errorf("Failed to remove container %s: %v", containerName, err)
		}
	}

	// 3. Close WireGuard resources
	logger.Verbosef("Closing WireGuard resources...")
	if uapi != nil {
		uapi.Close()
	}
	if device != nil {
		device.Close()
	}

	// 4. The WireGuard interface (utun) should be automatically cleaned up
	// when the device is closed, but we log for visibility
	logger.Verbosef("WireGuard interface %s should be automatically cleaned up", interfaceName)

	logger.Verbosef("Cleanup completed successfully")
}
