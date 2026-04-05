package networkmanager

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	containerTypes "go.podman.io/common/libnetwork/types"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type NetworkManager struct {
	mu             sync.RWMutex
	podmanNetworks map[string]containerTypes.Network
}

func New() NetworkManager {
	return NetworkManager{
		podmanNetworks: map[string]containerTypes.Network{},
	}
}

// ifreq is the BSD ifreq struct: 16-byte name + 16-byte sockaddr_in.
type ifreq struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
}

func newIfreq(ifaceName string, ip net.IP) ifreq {
	var ifr ifreq
	copy(ifr.name[:], ifaceName)
	ifr.addr.Len = unix.SizeofSockaddrInet4
	ifr.addr.Family = unix.AF_INET
	copy(ifr.addr.Addr[:], ip.To4())
	return ifr
}

func SetInterfaceAddress(ifaceName string, localIP, peerIP string) error {
	local := net.ParseIP(localIP).To4()
	peer := net.ParseIP(peerIP).To4()
	if local == nil || peer == nil {
		return fmt.Errorf("invalid IP address")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("creating socket: %w", err)
	}
	defer unix.Close(fd)

	ifr := newIfreq(ifaceName, local)
	if err := ioctlIfreq(fd, unix.SIOCSIFADDR, &ifr); err != nil {
		return fmt.Errorf("setting interface address: %w", err)
	}

	ifr = newIfreq(ifaceName, peer)
	if err := ioctlIfreq(fd, unix.SIOCSIFDSTADDR, &ifr); err != nil {
		return fmt.Errorf("setting peer address: %w", err)
	}

	return nil
}

func ioctlIfreq(fd int, req uint64, ifr *ifreq) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func addRoute(cidr string, ifaceName string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}

	dst := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	if dst == nil || mask == nil {
		return fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}

	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: [4]byte(dst)}
	addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: iface.Index}
	addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte(mask)}

	return writeRouteMessage(unix.RTM_ADD, addrs)
}

func deleteRoute(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	dst := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	if dst == nil || mask == nil {
		return fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}

	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: [4]byte(dst)}
	addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte(mask)}

	return writeRouteMessage(unix.RTM_DELETE, addrs)
}

func writeRouteMessage(msgType int, addrs []route.Addr) error {
	msg := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    msgType,
		Flags:   unix.RTF_UP | unix.RTF_STATIC,
		Seq:     1,
		Addrs:   addrs,
	}

	b, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling route message: %w", err)
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("opening routing socket: %w", err)
	}
	defer unix.Close(fd)

	_, err = unix.Write(fd, b)
	return err
}

func (manager *NetworkManager) ProcessPodmanNetworkCreate(network containerTypes.Network, iface string) {
	manager.mu.Lock()
	if _, exists := manager.podmanNetworks[network.ID]; exists {
		manager.mu.Unlock()
		return
	}
	manager.podmanNetworks[network.ID] = network
	manager.mu.Unlock()

	for _, subnet := range network.Subnets {
		if network.Driver == "bridge" {
			if err := addRoute(subnet.Subnet.String(), iface); err != nil {
				fmt.Printf("failed to add route for %s: %v\n", subnet.Subnet, err)
			}
		}
	}
}

func (manager *NetworkManager) ProcessPodmanNetworkRemove(networkName string) {
	manager.mu.Lock()
	var found *containerTypes.Network
	for id, network := range manager.podmanNetworks {
		if network.Name == networkName {
			found = &network
			delete(manager.podmanNetworks, id)
			break
		}
	}
	manager.mu.Unlock()

	if found == nil {
		return
	}

	for _, subnet := range found.Subnets {
		if found.Driver == "bridge" {
			if err := deleteRoute(subnet.Subnet.String()); err != nil {
				fmt.Printf("failed to remove route for %s: %v\n", subnet.Subnet, err)
			}
		}
	}
}

// ForEachNetwork iterates over tracked networks under a read lock.
func (manager *NetworkManager) ForEachNetwork(fn func(containerTypes.Network)) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, n := range manager.podmanNetworks {
		fn(n)
	}
}

// CleanupRoutes removes routes for all tracked bridge networks.
func (manager *NetworkManager) CleanupRoutes() {
	manager.ForEachNetwork(func(n containerTypes.Network) {
		for _, subnet := range n.Subnets {
			if n.Driver == "bridge" {
				if err := deleteRoute(subnet.Subnet.String()); err != nil {
					fmt.Printf("failed to remove route for %s: %v\n", subnet.Subnet, err)
				}
			}
		}
	})
}
