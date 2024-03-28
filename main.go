//go:build darwin

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
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
	"github.com/containers/podman/v4/pkg/specgen"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

type ContainersConfig struct {
	Engine struct {
		ServiceDestinations map[string]ServiceDestination `toml:"service_destinations"`
	} `toml:"engine"`
}

type ServiceDestination struct {
	URI      string `toml:"uri"`
	Identity string `toml:"identity"`
}

// findPodmanProcesses searches for Podman-related processes and attempts to parse
// the SSH URI and identity file from the process's command line arguments.
func findPodmanProcesses() (string, string, error) {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to list processes: %w", err)
	}

	var identityPath string
	var sshURI string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "gvproxy") {
			// Look for the -forward-identity argument for the identity file
			identityMatches := regexp.MustCompile(`-forward-identity ([^\s]+)`).FindStringSubmatch(line)
			if len(identityMatches) > 1 {
				identityPath = identityMatches[1]
			}

			// Attempt to construct the SSH URI based on the gvproxy process arguments
			portMatches := regexp.MustCompile(`-ssh-port (\d+)`).FindStringSubmatch(line)
			if len(portMatches) > 1 {
				port := portMatches[1]
				sshURI = fmt.Sprintf("ssh://root@127.0.0.1:%s/run/podman/podman.sock", port)
			}
		}
	}

	if identityPath == "" || sshURI == "" {
		return "", "", fmt.Errorf("no Podman processes found or missing data to construct SSH URI")
	}

	return sshURI, identityPath, nil
}

// SSHConnectionDetails holds the SSH URI and identity file path.
type SSHConnectionDetails struct {
	URI      string
	Identity string
}

// loadWireGuardModule attempts to load the WireGuard module using modprobe.
func loadWireGuardModule(details *SSHConnectionDetails) error {
	// Parse the URI to extract username and host.
	uri, err := url.Parse(details.URI)
	if err != nil {
		return fmt.Errorf("failed to parse SSH URI: %w", err)
	}

	// Extract the username and hostname from the URI.
	userInfo := uri.User
	username := userInfo.Username()
	hostname := uri.Hostname()

	// Derive the port from the URI, defaulting to 22 if not specified.
	port := uri.Port()
	if port == "" {
		port = "22" // Default SSH port.
	}

	// Construct the SSH command for loading the WireGuard module.
	sshCommand := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -p %s %s@%s 'sudo modprobe wireguard'",
		details.Identity, port, username, hostname)

	// Execute the SSH command.
	cmd := exec.Command("sh", "-c", sshCommand)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to load WireGuard module via SSH: %s: %w", output, err)
	}

	fmt.Println("WireGuard module loaded successfully.")
	return nil
}

func main() {
	uri, identity, err := findPodmanProcesses()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Found Podman process")
	fmt.Println("URI:", uri)
	fmt.Println("Identity file:", identity)

	sshDetails := SSHConnectionDetails{
		URI:      uri,
		Identity: identity,
	}

	fmt.Printf("SSH URI: %s, Identity File: %s\n", sshDetails.URI, sshDetails.Identity)

	// Proceed with WireGuard module loading and further setup
	// Note: The owner parameter has been removed from the function call
	if err := loadWireGuardModule(&sshDetails); err != nil {
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
		fmt.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	interfaceName, err := tun.Name()
	if err != nil {
		fmt.Errorf("Failed to get TUN device name: %v", err)
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

	hostPeerIp := "10.33.33.1"
	vmPeerIp := "10.33.33.2"

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

	port := 3333
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

	fmt.Printf("Attempting to create Podman connection with URI: %s and Identity: %s\n", sshDetails.URI, sshDetails.Identity)
	podmanCtx, err := bindings.NewConnectionWithIdentity(context.Background(), sshDetails.URI, sshDetails.Identity, false)
	if err != nil {
		fmt.Printf("Error creating Podman connection with identity: %v\n", err)
		return
	} else {
		fmt.Println("Successfully created Podman connection with identity.")
	}

	go func() {
		for {
			err = setupPodmanVm(podmanCtx, port, hostPeerIp, vmPeerIp, hostPrivateKey, vmPrivateKey)
			if err != nil {
				logger.Errorf("Failed to setup VM: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			fmt.Printf("Set up VM\n")
			networks, err := network.List(podmanCtx, &network.ListOptions{})
			if err != nil {
				logger.Errorf("Failed to list podman networks: %w", err)
				time.Sleep(5 * time.Second)
				continue
			}
			for _, network := range networks {
				fmt.Printf("network create for %+v", network)
				networkManager.ProcessPodmanNetworkCreate(network, interfaceName)
			}

			time.Sleep(5 * time.Second)
		}
	}()

	// Wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// Clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down\n")
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

	resp, err := containers.CreateWithSpec(podmanCli, &specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:         "wireguard-setup",
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
