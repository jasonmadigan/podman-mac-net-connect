//go:build darwin

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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

	"go.podman.io/common/pkg/config"

	"github.com/containers/podman/v6/pkg/bindings"
	"github.com/containers/podman/v6/pkg/bindings/network"
	"github.com/containers/podman/v6/pkg/bindings/system"
	"github.com/containers/podman/v6/pkg/domain/entities/types"
	"github.com/containers/podman/v6/pkg/machine"
	"github.com/containers/podman/v6/pkg/machine/define"
	"github.com/containers/podman/v6/pkg/machine/shim"
	"github.com/containers/podman/v6/pkg/machine/vmconfigs"
)

const maxSetupRetries = 5

const ExitSetupFailed = 1

// getMachineSSHConfig gets SSH config for the default podman machine and
// returns the SSH config and the stored API connection details.
func getMachineSSHConfig() (*vmconfigs.SSHConfig, string, string, error) {
	mc, _, err := shim.VMExists(define.DefaultMachineName)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to find podman machine %q: %w", define.DefaultMachineName, err)
	}

	// look up the rootful API connection registered by podman machine init
	cfg, err := config.New(nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to load podman config: %w", err)
	}

	conn, err := cfg.GetConnection(define.DefaultMachineName+"-root", false)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get root connection for %q: %w", define.DefaultMachineName, err)
	}

	return &mc.SSH, conn.URI, conn.Identity, nil
}

// vmSSH wraps the machine SSH calls to avoid repeating config everywhere.
type vmSSH struct {
	config *vmconfigs.SSHConfig
}

func (v *vmSSH) run(args ...string) error {
	return machine.LocalhostSSH("root", v.config.IdentityPath, define.DefaultMachineName, v.config.Port, args)
}

func (v *vmSSH) runWithStdin(stdin io.Reader, args ...string) error {
	return machine.LocalhostSSHWithStdin("root", v.config.IdentityPath, define.DefaultMachineName, v.config.Port, args, stdin)
}

func loadWireGuardModule(ssh *vmSSH) error {
	if err := ssh.run("modprobe", "wireguard"); err != nil {
		return fmt.Errorf("loading wireguard module: %w", err)
	}
	return nil
}

const wgInterface = "maddawg0"

func setupPodmanVm(
	ssh *vmSSH,
	serverPort int,
	hostPeerIp string,
	vmPeerIp string,
	hostPrivateKey wgtypes.Key,
	vmPrivateKey wgtypes.Key,
) error {
	// clean up any existing interface
	ssh.run("ip", "link", "del", wgInterface)

	if err := ssh.run("ip", "link", "add", wgInterface, "type", "wireguard"); err != nil {
		return fmt.Errorf("creating wireguard interface: %w", err)
	}

	if err := ssh.run("ip", "addr", "add", vmPeerIp+"/32", "peer", hostPeerIp+"/32", "dev", wgInterface); err != nil {
		return fmt.Errorf("assigning interface address: %w", err)
	}

	// pipe private key via stdin so it doesn't appear in process list.
	// endpoint uses host.containers.internal which podman sets up in the VM.
	endpoint := fmt.Sprintf("host.containers.internal:%d", serverPort)
	err := ssh.runWithStdin(
		strings.NewReader(vmPrivateKey.String()),
		"wg", "set", wgInterface,
		"private-key", "/dev/stdin",
		"peer", hostPrivateKey.PublicKey().String(),
		"endpoint", endpoint,
		"allowed-ips", "0.0.0.0/0,"+hostPeerIp+"/32",
		"persistent-keepalive", "5",
	)
	if err != nil {
		return fmt.Errorf("configuring wireguard peer: %w", err)
	}

	if err := ssh.run("ip", "link", "set", wgInterface, "up"); err != nil {
		return fmt.Errorf("bringing up interface: %w", err)
	}

	// add NAT rule if not already present
	if err := ssh.run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", hostPeerIp, "-j", "MASQUERADE"); err != nil {
		if err := ssh.run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", hostPeerIp, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("adding NAT rule: %w", err)
		}
	}

	return nil
}

func main() {
	sshConfig, uri, identity, err := getMachineSSHConfig()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(ExitSetupFailed)
	}

	ssh := &vmSSH{config: sshConfig}

	fmt.Printf("Found podman machine (SSH port: %d)\n", sshConfig.Port)

	if err := loadWireGuardModule(ssh); err != nil {
		fmt.Printf("Error loading WireGuard module: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	podmanCtx, err := bindings.NewConnectionWithIdentity(context.Background(), uri, identity, false)
	if err != nil {
		fmt.Printf("Error creating Podman API connection: %v\n", err)
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

	hostPeerIp := getEnvOrDefault("PMNET_HOST_IP", "10.33.34.1")
	vmPeerIp := getEnvOrDefault("PMNET_VM_IP", "10.33.34.2")

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

	port := getEnvOrDefaultInt("PMNET_WG_PORT", 3334)
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

	if err := networkmanager.SetInterfaceAddress(interfaceName, hostPeerIp, vmPeerIp); err != nil {
		logger.Errorf("Failed to set interface address: %v", err)
		os.Exit(ExitSetupFailed)
	}

	logger.Verbosef("Interface %s created\n", interfaceName)
	logger.Verbosef("Wireguard server listening\n")

	// Create cancellable context for background operations
	backgroundCtx, cancelBackground := context.WithCancel(podmanCtx)
	defer cancelBackground()

	go func() {
		delay := 2 * time.Second
		for attempt := 1; attempt <= maxSetupRetries; attempt++ {
			select {
			case <-backgroundCtx.Done():
				logger.Verbosef("VM setup cancelled")
				return
			default:
			}

			err = setupPodmanVm(ssh, port, hostPeerIp, vmPeerIp, hostPrivateKey, vmPrivateKey)
			if err == nil {
				logger.Verbosef("VM setup completed successfully")
				monitorNetworkEvents(backgroundCtx, &networkManager, interfaceName, logger)
				return
			}

			logger.Errorf("Failed to setup VM (attempt %d/%d): %v", attempt, maxSetupRetries, err)
			if attempt < maxSetupRetries {
				time.Sleep(delay)
				delay *= 2
			}
		}
		logger.Errorf("VM setup failed after %d attempts, giving up", maxSetupRetries)
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
	performCleanup(&networkManager, logger, uapi, device)

	logger.Verbosef("Shutdown complete")
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
	eventChan := make(chan types.Event)
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
				networkName := event.Actor.Attributes["name"]
				if networkName != "" {
					report, err := network.Inspect(monitorCtx, networkName, &network.InspectOptions{})
					if err != nil {
						logger.Errorf("Failed to inspect network %s: %v", networkName, err)
						continue
					}
					logger.Verbosef("Processing new network: %s", networkName)
					networkManager.ProcessPodmanNetworkCreate(report.Network, interfaceName)
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

func performCleanup(networkManager *networkmanager.NetworkManager, logger *device.Logger, uapi net.Listener, wgDevice *device.Device) {
	logger.Verbosef("Starting cleanup...")

	networkManager.CleanupRoutes()

	if uapi != nil {
		uapi.Close()
	}
	if wgDevice != nil {
		wgDevice.Close()
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvOrDefaultInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}
