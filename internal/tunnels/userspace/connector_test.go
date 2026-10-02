package userspace

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestUserspaceConnectorTCPUDPAndNoHostInterface(t *testing.T) {
	before := interfaceSnapshot(t)
	serverPrivate, serverPublic := testKeyPair(t)
	clientPrivate, clientPublic := testKeyPair(t)
	serverDevice, serverNet, serverPort := startPeer(t, netip.MustParseAddr("10.200.0.1"), serverPrivate, clientPublic, "10.200.0.2/32", "")
	defer serverDevice.Close()

	configPath := writeWireGuardConfig(t, clientPrivate, netip.MustParsePrefix("10.200.0.2/32"), serverPublic, serverPort)
	connector, err := New(context.Background(), testProfile(configPath))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = connector.Close() }()

	listener, err := serverNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.200.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("server ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	echoDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			echoDone <- acceptErr
			return
		}
		defer func() { _ = connection.Close() }()
		_, copyErr := io.Copy(connection, connection)
		echoDone <- copyErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := connector.OpenTCP(ctx, destinationFor(listener.Addr()))
	if err != nil {
		t.Fatalf("OpenTCP() error = %v", err)
	}
	if _, err := connection.Write([]byte("userspace-tcp")); err != nil {
		t.Fatalf("TCP write error = %v", err)
	}
	response := make([]byte, len("userspace-tcp"))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("TCP read error = %v", err)
	}
	if string(response) != "userspace-tcp" {
		t.Fatalf("TCP response = %q", response)
	}
	_ = connection.Close()
	select {
	case err := <-echoDone:
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("TCP echo error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for TCP echo")
	}

	serverUDP, err := serverNet.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.200.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("server ListenUDP() error = %v", err)
	}
	defer func() { _ = serverUDP.Close() }()
	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 128)
		n, address, readErr := serverUDP.ReadFrom(buffer)
		if readErr != nil {
			udpDone <- readErr
			return
		}
		_, writeErr := serverUDP.WriteTo(buffer[:n], address)
		udpDone <- writeErr
	}()
	packet, err := connector.OpenUDP(ctx)
	if err != nil {
		t.Fatalf("OpenUDP() error = %v", err)
	}
	defer func() { _ = packet.Close() }()
	udpDestination := &net.UDPAddr{IP: net.ParseIP("10.200.0.1"), Port: serverUDP.LocalAddr().(*net.UDPAddr).Port}
	if _, err := packet.WriteTo([]byte("userspace-udp"), udpDestination); err != nil {
		t.Fatalf("UDP write error = %v", err)
	}
	buffer := make([]byte, 128)
	if err := packet.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("UDP read deadline error = %v", err)
	}
	n, _, err := packet.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("UDP read error = %v", err)
	}
	if string(buffer[:n]) != "userspace-udp" {
		t.Fatalf("UDP response = %q", buffer[:n])
	}
	if err := <-udpDone; err != nil {
		t.Fatalf("UDP echo error = %v", err)
	}

	after := interfaceSnapshot(t)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("host interfaces changed: before=%v after=%v", before, after)
	}
}

func testProfile(path string) config.ProfileConfig {
	return config.ProfileConfig{ID: "userspace", Backend: "wireguard", Mode: "userspace-netstack", ConfigPath: path}
}

func destinationFor(address net.Addr) domain.Destination {
	tcpAddress := address.(*net.TCPAddr)
	return domain.Destination{Host: tcpAddress.IP.String(), Port: uint16(tcpAddress.Port)}
}

func startPeer(t *testing.T, address netip.Addr, privateHex, peerPublic, allowedIP, endpoint string) (*device.Device, *netstack.Net, uint16) {
	t.Helper()
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s\n", privateHex, keyHexFromBase64(peerPublic), allowedIP)
	if endpoint != "" {
		fmt.Fprintf(&builder, "endpoint=%s\n", endpoint)
	}
	builder.WriteByte('\n')
	if err := dev.IpcSet(builder.String()); err != nil {
		dev.Close()
		t.Fatalf("IpcSet() error = %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("Up() error = %v", err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		dev.Close()
		t.Fatalf("IpcGet() error = %v", err)
	}
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, parseErr := strconv.ParseUint(strings.TrimPrefix(line, "listen_port="), 10, 16)
			if parseErr != nil {
				dev.Close()
				t.Fatalf("parse listen port: %v", parseErr)
			}
			return dev, tnet, uint16(port)
		}
	}
	dev.Close()
	t.Fatal("IpcGet() did not report listen port")
	return nil, nil, 0
}

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519() error = %v", err)
	}
	return fmt.Sprintf("%x", private), base64.StdEncoding.EncodeToString(public)
}

func writeWireGuardConfig(t *testing.T, privateHex string, address netip.Prefix, peerPublic string, serverPort uint16) string {
	t.Helper()
	private, err := hex.DecodeString(privateHex)
	if err != nil || len(private) != 32 {
		t.Fatalf("decode private key: %v", err)
	}
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 0.0.0.0/0
`, base64.StdEncoding.EncodeToString(private), address, peerPublic, serverPort)
	file, err := os.CreateTemp(t.TempDir(), "wireguard-*.conf")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return file.Name()
}

func interfaceSnapshot(t *testing.T) map[string]string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error = %v", err)
	}
	result := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		result[iface.Name] = iface.HardwareAddr.String()
	}
	return result
}

func keyHexFromBase64(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		panic("invalid test WireGuard public key")
	}
	return fmt.Sprintf("%x", decoded)
}
