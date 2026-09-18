package domain

import "testing"

func TestParseAddressSupportsIPv4AndIPv6(t *testing.T) {
	ipv4, err := ParseAddress("192.0.2.10:443")
	if err != nil {
		t.Fatal(err)
	}
	if ipv4.Host != "192.0.2.10" || ipv4.Port != 443 {
		t.Fatalf("IPv4 destination = %+v", ipv4)
	}

	ipv6, err := ParseAddress("[2001:db8::10]:8443")
	if err != nil {
		t.Fatal(err)
	}
	if ipv6.Host != "2001:db8::10" || ipv6.Port != 8443 {
		t.Fatalf("IPv6 destination = %+v", ipv6)
	}
}

func TestParseHostPortAppliesDefaultPort(t *testing.T) {
	destination, err := ParseHostPort("origin.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	if destination.Host != "origin.example" || destination.Port != 80 {
		t.Fatalf("destination = %+v", destination)
	}
}

func TestParseHostPortAppliesDefaultPortToBracketedIPv6(t *testing.T) {
	destination, err := ParseHostPort("[2001:db8::10]", 443)
	if err != nil {
		t.Fatal(err)
	}
	if destination.Host != "2001:db8::10" || destination.Port != 443 {
		t.Fatalf("destination = %+v", destination)
	}
}

func TestParseAddressRejectsZeroPort(t *testing.T) {
	if _, err := ParseAddress("origin.example:0"); err == nil {
		t.Fatal("zero port should be rejected")
	}
}
