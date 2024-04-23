package dnsstamps

import (
	"encoding/hex"
	"strings"
	"testing"
)

var pk1 []byte

func init() {
	var err error
	// generated with:
	// openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/ssl/certs/Go_Daddy_Class_2_CA.pem
	pkStr := "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4"
	pk1, err = hex.DecodeString(strings.Replace(pkStr, ":", "", -1))
	if err != nil {
		panic(err)
	}
	if len(pk1) != 32 {
		panic("invalid public key fingerprint")
	}
}

func TestDnscryptStamp(t *testing.T) {
	// same as exampleStamp in dnscrypt-stamper
	const expected = `sdns://AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeDNSCrypt
	stamp.ServerAddrStr = "127.0.0.1"

	stamp.ProviderName = "2.dnscrypt-cert.localhost"
	stamp.ServerPk = pk1
	stampStr := stamp.String()

	if stampStr != expected {
		t.Errorf("expected stamp %q but got instead %q", expected, stampStr)
	}

	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverHTTP_NoHashes(t *testing.T) {
	const expected = `sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.ServerAddrStr = "127.0.0.1"

	stamp.Proto = StampProtoTypeDoH
	stamp.ProviderName = "example.com"
	stamp.Hashes = [][]uint8{pk1}
	stamp.Path = "/dns-query"
	stampStr := stamp.String()

	if stampStr != expected {
		t.Errorf("expected stamp %q but got instead %q", expected, stampStr)
	}

	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverHTTP2_2(t *testing.T) {
	const q9 = `sdns://AgYAAAAAAAAACDkuOS45LjEwABJkbnM5LnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ`

	parsedStamp, err := NewServerStampFromString(q9)
	if err != nil {
		t.Fatal(err)
	}
	ps := parsedStamp.String()
	if ps != q9 {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, q9)
	}
}

func TestODoHTarget(t *testing.T) {
	const stamp = `sdns://BQcAAAAAAAAAEG9kb2guZXhhbXBsZS5jb20HL3RhcmdldA`

	parsedStamp, err := NewServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
	ps := parsedStamp.String()
	if ps != stamp {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stamp)
	}
}

func TestODoHRelay(t *testing.T) {
	const stamp = `sdns://hQcAAAAAAAAAB1s6OjFdOjGCq80CASMPZG9oLmV4YW1wbGUuY29tBi9yZWxheQ`

	parsedStamp, err := NewServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
	ps := parsedStamp.String()
	if ps != stamp {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stamp)
	}
}

func TestRelayServerPair(t *testing.T) {
	const stamp = `sdns://hQcAAAAAAAAAB1s6OjFdOjGCq80CASMPZG9oLmV4YW1wbGUuY29tBi9yZWxheQ/BQcAAAAAAAAAEG9kb2guZXhhbXBsZS5jb20HL3RhcmdldA`
	_, _, err := NewRelayAndServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPlainOldDNS(t *testing.T) {
	// [DNSSEC|No Filter|No Log] + 8.8.8.8 (no port)
	const stamp = `sdns://AAcAAAAAAAAABzguOC44Ljg`
	parsedStamp, err := NewServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "8.8.8.8:53" {
		t.Errorf("expected server address 8.8.8.8 but got %q", parsedStamp.ServerAddrStr)
	}
	ps := parsedStamp.String()
	if ps != stamp {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stamp)
	}
}

func TestPlainOldDNSWithPort(t *testing.T) {
	// [DNSSEC|No Filter|No Log] + 8.8.8.8:8053
	const stamp = `sdns://AAcAAAAAAAAADDguOC44Ljg6ODA1Mw`
	parsedStamp, err := NewServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "8.8.8.8:8053" {
		t.Errorf("expected server address 8.8.8.8 but got %q", parsedStamp.ServerAddrStr)
	}
	ps := parsedStamp.String()
	if ps != stamp {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stamp)
	}
}
