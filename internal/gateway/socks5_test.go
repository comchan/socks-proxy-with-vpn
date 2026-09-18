package gateway

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

func socks5Greeting(t *testing.T, client net.Conn) {
	t.Helper()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	response := readN(t, client, 2)
	if response[0] != socks5Version || response[1] != socks5NoAuth {
		t.Fatalf("SOCKS5 method response = %x", response)
	}
}

func socks5ConnectRequest(host string, port uint16) []byte {
	request := []byte{0x05, socks5Connect, 0x00, socks5Domain, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	return request
}

func TestServeSOCKS5ConnectRelays(t *testing.T) {
	var got domain.Destination
	upstreamClient, upstreamServer := net.Pipe()
	gateway := New(&fakeConnector{
		openTCP: func(_ context.Context, destination domain.Destination) (net.Conn, error) {
			got = destination
			return upstreamClient, nil
		},
	})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS5(context.Background(), conn)
	})
	t.Cleanup(func() { _ = upstreamServer.Close() })

	socks5Greeting(t, client)
	if _, err := client.Write(socks5ConnectRequest("service.internal", 8443)); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socks5Success {
		t.Fatalf("SOCKS5 CONNECT reply = %x", reply)
	}
	if got.Host != "service.internal" || got.Port != 8443 {
		t.Fatalf("destination = %+v", got)
	}

	go func() { _, _ = client.Write([]byte("client-data")) }()
	if data := readN(t, upstreamServer, len("client-data")); string(data) != "client-data" {
		t.Fatalf("upstream data = %q", data)
	}
	go func() { _, _ = upstreamServer.Write([]byte("upstream-data")) }()
	if data := readN(t, client, len("upstream-data")); string(data) != "upstream-data" {
		t.Fatalf("client data = %q", data)
	}
	_ = client.Close()
	_ = upstreamServer.Close()
	<-done
}

func TestServeSOCKS5MapsConnectionRefused(t *testing.T) {
	gateway := New(&fakeConnector{
		openTCP: func(context.Context, domain.Destination) (net.Conn, error) {
			return nil, egress.NewError(egress.FailureConnectionRefused, errors.New("test refusal"))
		},
	})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS5(context.Background(), conn)
	})
	socks5Greeting(t, client)
	if _, err := client.Write([]byte{0x05, socks5Connect, 0, socks5IPv4, 192, 0, 2, 10, 0, 80}); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socks5ConnectionRefused {
		t.Fatalf("SOCKS5 failure reply = %x", reply)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("connection refusal should return an error")
	}
}

func TestServeSOCKS5RejectsBind(t *testing.T) {
	gateway := New(&fakeConnector{})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS5(context.Background(), conn)
	})
	socks5Greeting(t, client)
	if _, err := client.Write([]byte{0x05, 0x02, 0, socks5IPv4, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socks5CommandUnsupported {
		t.Fatalf("SOCKS5 BIND reply = %x", reply)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("BIND should return an error")
	}
}

func TestServeSOCKS5RejectsUnsupportedAuthentication(t *testing.T) {
	gateway := New(&fakeConnector{})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS5(context.Background(), conn)
	})
	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	if response := readN(t, client, 2); response[1] != socks5NoAcceptableMethods {
		t.Fatalf("method response = %x", response)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("unsupported authentication should return an error")
	}
}
func TestSOCKS5ReplyMapsEgressFailures(t *testing.T) {
	tests := []struct {
		name string
		kind egress.FailureKind
		want byte
	}{
		{name: "network", kind: egress.FailureNetworkUnreachable, want: socks5NetworkUnreachable},
		{name: "host", kind: egress.FailureHostUnreachable, want: socks5HostUnreachable},
		{name: "refused", kind: egress.FailureConnectionRefused, want: socks5ConnectionRefused},
		{name: "TTL", kind: egress.FailureTTLExpired, want: socks5TTLExpired},
		{name: "command", kind: egress.FailureCommandNotSupported, want: socks5CommandUnsupported},
		{name: "address", kind: egress.FailureAddressTypeNotSupported, want: socks5AddressUnsupported},
		{name: "general", kind: egress.FailureGeneral, want: socks5GeneralFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := socks5ReplyForError(egress.NewError(test.kind, errors.New("test"))); got != test.want {
				t.Fatalf("reply = 0x%02x, want 0x%02x", got, test.want)
			}
		})
	}
}
func TestSOCKS5UDPAssociateRelaysDatagrams(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	egressSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	gateway := New(&fakeConnector{
		openUDP: func(context.Context) (net.PacketConn, error) {
			return egressSocket, nil
		},
		resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- gateway.ServeSOCKS5(context.Background(), conn)
	}()

	control, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = control.Close() }()
	socks5Greeting(t, control)
	if _, err := control.Write([]byte{0x05, socks5UDPAssociate, 0, socks5IPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	udpReply := readN(t, control, 10)
	if udpReply[1] != socks5Success || udpReply[3] != socks5IPv4 {
		t.Fatalf("UDP ASSOCIATE reply = %x", udpReply)
	}
	relayAddress := &net.UDPAddr{IP: net.IPv4(udpReply[4], udpReply[5], udpReply[6], udpReply[7]), Port: int(udpReply[8])<<8 | int(udpReply[9])}
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientUDP.Close() }()

	requestPacket, err := encodeSOCKS5UDPDatagram(domain.Destination{Host: remote.LocalAddr().(*net.UDPAddr).IP.String(), Port: uint16(remote.LocalAddr().(*net.UDPAddr).Port)}, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientUDP.WriteToUDP(requestPacket, relayAddress); err != nil {
		t.Fatal(err)
	}

	remoteBuffer := make([]byte, 128)
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count, source, err := remote.ReadFromUDP(remoteBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(remoteBuffer[:count]) != "ping" {
		t.Fatalf("remote payload = %q", remoteBuffer[:count])
	}
	if _, err := remote.WriteToUDP([]byte("pong"), source); err != nil {
		t.Fatal(err)
	}

	if err := clientUDP.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	responseBuffer := make([]byte, 128)
	count, _, err = clientUDP.ReadFromUDP(responseBuffer)
	if err != nil {
		t.Fatal(err)
	}
	responseDestination, payload, err := parseSOCKS5UDPDatagram(responseBuffer[:count])
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "pong" || responseDestination.Port != uint16(remote.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("UDP response destination=%+v payload=%q", responseDestination, payload)
	}
	_ = control.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("UDP association did not stop after control connection closed")
	}
}

func TestSOCKS5UDPDatagramRejectsFragments(t *testing.T) {
	_, _, err := parseSOCKS5UDPDatagram([]byte{0, 0, 1, socks5IPv4, 127, 0, 0, 1, 0, 53, 1})
	if err == nil {
		t.Fatal("fragmented UDP datagram should be rejected")
	}
}

func TestSOCKS5UDPDomainResolutionUsesConnector(t *testing.T) {
	gateway := New(&fakeConnector{
		resolve: func(_ context.Context, hostname string) ([]net.IP, error) {
			if hostname != "service.internal" {
				t.Fatalf("resolved hostname = %q", hostname)
			}
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		},
	})
	address, err := gateway.resolveUDPAddress(context.Background(), domain.Destination{Host: "service.internal", Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	if !address.IP.Equal(net.ParseIP("192.0.2.10")) || address.Port != 53 {
		t.Fatalf("resolved address = %v", address)
	}
}

func TestReadSOCKS5AddressRejectsUnknownType(t *testing.T) {
	_, err := readSOCKS5Destination(bufio.NewReader(stringsReader("")), 0x02, false)
	if egress.KindOf(err) != egress.FailureAddressTypeNotSupported {
		t.Fatalf("error kind = %v, want address-type failure", egress.KindOf(err))
	}
}

type stringsReader string

func (s stringsReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, errors.New("empty reader")
	}
	n := copy(p, s)
	return n, nil
}
