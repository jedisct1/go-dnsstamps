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

func TestDNSOverTLS_Basic(t *testing.T) {
	// [DNSSEC|No Filter|No Log] + 127.0.0.1 + hash + dns.example.com
	const expected = `sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5A9kbnMuZXhhbXBsZS5jb20`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "127.0.0.1"
	stamp.ProviderName = "dns.example.com"
	stamp.Hashes = [][]uint8{pk1}
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

func TestDNSOverTLS_DefaultPort(t *testing.T) {
	// Test that default port 853 is added correctly
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default port 853 added
	if parsedStamp.ServerAddrStr != "1.1.1.1:853" {
		t.Errorf("expected server address 1.1.1.1:853 but got %q", parsedStamp.ServerAddrStr)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_CustomPort(t *testing.T) {
	// Test with custom port 8853
	const expected = `sdns://AwcAAAAAAAAADDEuMS4xLjE6ODg1MyDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BJjbG91ZGZsYXJlLWRucy5jb20`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.1.1.1:8853"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stampStr := stamp.String()

	if stampStr != expected {
		t.Errorf("expected stamp %q but got instead %q", expected, stampStr)
	}

	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "1.1.1.1:8853" {
		t.Errorf("expected server address 1.1.1.1:8853 but got %q", parsedStamp.ServerAddrStr)
	}
	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_NoHashes(t *testing.T) {
	// Test DoT stamp without certificate hashes
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "9.9.9.9"
	stamp.ProviderName = "dns.quad9.net"
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoFilter

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify parsed stamp matches original
	if parsedStamp.Proto != StampProtoTypeTLS {
		t.Errorf("expected proto TLS but got %v", parsedStamp.Proto)
	}
	if parsedStamp.ServerAddrStr != "9.9.9.9:853" {
		t.Errorf("expected server address 9.9.9.9:853 but got %q", parsedStamp.ServerAddrStr)
	}
	if parsedStamp.ProviderName != "dns.quad9.net" {
		t.Errorf("expected provider name dns.quad9.net but got %q", parsedStamp.ProviderName)
	}
	if len(parsedStamp.Hashes) != 0 {
		t.Errorf("expected no hashes but got %d", len(parsedStamp.Hashes))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_MultipleHashes(t *testing.T) {
	// Test with multiple certificate hashes
	hash1 := pk1
	hash2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}

	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "8.8.8.8"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{hash1, hash2}
	stamp.Props = ServerInformalPropertyDNSSEC

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify multiple hashes were parsed correctly
	if len(parsedStamp.Hashes) != 2 {
		t.Errorf("expected 2 hashes but got %d", len(parsedStamp.Hashes))
	}
	if len(parsedStamp.Hashes[0]) != 32 {
		t.Errorf("expected first hash to be 32 bytes but got %d", len(parsedStamp.Hashes[0]))
	}
	if len(parsedStamp.Hashes[1]) != 32 {
		t.Errorf("expected second hash to be 32 bytes but got %d", len(parsedStamp.Hashes[1]))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_IPv6(t *testing.T) {
	// Test with IPv6 address
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "[2001:4860:4860::8888]"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{pk1}
	stamp.Props = ServerInformalPropertyDNSSEC

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default port 853 added
	if parsedStamp.ServerAddrStr != "[2001:4860:4860::8888]:853" {
		t.Errorf("expected server address [2001:4860:4860::8888]:853 but got %q", parsedStamp.ServerAddrStr)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_AllProps(t *testing.T) {
	// Test with all properties set
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog | ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.0.0.1"
	stamp.ProviderName = "one.one.one.one"
	stamp.Hashes = [][]uint8{pk1}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all properties were preserved
	if parsedStamp.Props != stamp.Props {
		t.Errorf("expected props %v but got %v", stamp.Props, parsedStamp.Props)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_Basic(t *testing.T) {
	// [DNSSEC|No Filter|No Log] + 127.0.0.1 + hash + dns.example.com
	const expected = `sdns://BAcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5A9kbnMuZXhhbXBsZS5jb20`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "127.0.0.1"
	stamp.ProviderName = "dns.example.com"
	stamp.Hashes = [][]uint8{pk1}
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

func TestDNSOverQUIC_DefaultPort(t *testing.T) {
	// Test that default port 853 is added correctly
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default port 853 added
	if parsedStamp.ServerAddrStr != "1.1.1.1:853" {
		t.Errorf("expected server address 1.1.1.1:853 but got %q", parsedStamp.ServerAddrStr)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_CustomPort(t *testing.T) {
	// Test with custom port 8853
	const expected = `sdns://BAcAAAAAAAAADDEuMS4xLjE6ODg1MyDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BJjbG91ZGZsYXJlLWRucy5jb20`

	var stamp ServerStamp
	stamp.Props |= ServerInformalPropertyDNSSEC
	stamp.Props |= ServerInformalPropertyNoLog
	stamp.Props |= ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.1.1.1:8853"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stampStr := stamp.String()

	if stampStr != expected {
		t.Errorf("expected stamp %q but got instead %q", expected, stampStr)
	}

	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "1.1.1.1:8853" {
		t.Errorf("expected server address 1.1.1.1:8853 but got %q", parsedStamp.ServerAddrStr)
	}
	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_NoHashes(t *testing.T) {
	// Test DoQ stamp without certificate hashes
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "9.9.9.9"
	stamp.ProviderName = "dns.quad9.net"
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoFilter

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify parsed stamp matches original
	if parsedStamp.Proto != StampProtoTypeDoQ {
		t.Errorf("expected proto DoQ but got %v", parsedStamp.Proto)
	}
	if parsedStamp.ServerAddrStr != "9.9.9.9:853" {
		t.Errorf("expected server address 9.9.9.9:853 but got %q", parsedStamp.ServerAddrStr)
	}
	if parsedStamp.ProviderName != "dns.quad9.net" {
		t.Errorf("expected provider name dns.quad9.net but got %q", parsedStamp.ProviderName)
	}
	if len(parsedStamp.Hashes) != 0 {
		t.Errorf("expected no hashes but got %d", len(parsedStamp.Hashes))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_MultipleHashes(t *testing.T) {
	// Test with multiple certificate hashes
	hash1 := pk1
	hash2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}

	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "8.8.8.8"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{hash1, hash2}
	stamp.Props = ServerInformalPropertyDNSSEC

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify multiple hashes were parsed correctly
	if len(parsedStamp.Hashes) != 2 {
		t.Errorf("expected 2 hashes but got %d", len(parsedStamp.Hashes))
	}
	if len(parsedStamp.Hashes[0]) != 32 {
		t.Errorf("expected first hash to be 32 bytes but got %d", len(parsedStamp.Hashes[0]))
	}
	if len(parsedStamp.Hashes[1]) != 32 {
		t.Errorf("expected second hash to be 32 bytes but got %d", len(parsedStamp.Hashes[1]))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_IPv6(t *testing.T) {
	// Test with IPv6 address
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "[2001:4860:4860::8888]"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{pk1}
	stamp.Props = ServerInformalPropertyDNSSEC

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default port 853 added
	if parsedStamp.ServerAddrStr != "[2001:4860:4860::8888]:853" {
		t.Errorf("expected server address [2001:4860:4860::8888]:853 but got %q", parsedStamp.ServerAddrStr)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_AllProps(t *testing.T) {
	// Test with all properties set
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog | ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.0.0.1"
	stamp.ProviderName = "one.one.one.one"
	stamp.Hashes = [][]uint8{pk1}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all properties were preserved
	if parsedStamp.Props != stamp.Props {
		t.Errorf("expected props %v but got %v", stamp.Props, parsedStamp.Props)
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

// Bootstrap IP address tests for DoT

func TestDNSOverTLS_SingleBootstrapIP(t *testing.T) {
	// Test DoT stamp with single bootstrap IP address
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"1.1.1.1"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify bootstrap IPs were parsed correctly
	if len(parsedStamp.BootstrapIPs) != 1 {
		t.Errorf("expected 1 bootstrap IP but got %d", len(parsedStamp.BootstrapIPs))
	}
	if parsedStamp.BootstrapIPs[0] != "1.1.1.1" {
		t.Errorf("expected bootstrap IP 1.1.1.1 but got %q", parsedStamp.BootstrapIPs[0])
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_MultipleBootstrapIPs(t *testing.T) {
	// Test with multiple bootstrap IP addresses (IPv4 and IPv6)
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "9.9.9.9"
	stamp.ProviderName = "dns.quad9.net"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all bootstrap IPs were parsed correctly
	if len(parsedStamp.BootstrapIPs) != 3 {
		t.Errorf("expected 3 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}
	expectedIPs := []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe"}
	for i, expectedIP := range expectedIPs {
		if parsedStamp.BootstrapIPs[i] != expectedIP {
			t.Errorf("expected bootstrap IP %q at index %d but got %q", expectedIP, i, parsedStamp.BootstrapIPs[i])
		}
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_BootstrapIPsWithAllProps(t *testing.T) {
	// Test with bootstrap IPs and all properties
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog | ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "8.8.8.8:8853"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"8.8.8.8", "8.8.4.4"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all fields were preserved
	if parsedStamp.Props != stamp.Props {
		t.Errorf("expected props %v but got %v", stamp.Props, parsedStamp.Props)
	}
	if parsedStamp.ServerAddrStr != "8.8.8.8:8853" {
		t.Errorf("expected server address 8.8.8.8:8853 but got %q", parsedStamp.ServerAddrStr)
	}
	if len(parsedStamp.BootstrapIPs) != 2 {
		t.Errorf("expected 2 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_NoBootstrapIPs_BackwardCompatibility(t *testing.T) {
	// Test that DoT stamps without bootstrap IPs still work (backward compatibility)
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.0.0.1"
	stamp.ProviderName = "one.one.one.one"
	stamp.Hashes = [][]uint8{pk1}
	// No bootstrap IPs set

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify no bootstrap IPs
	if len(parsedStamp.BootstrapIPs) != 0 {
		t.Errorf("expected 0 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverTLS_BootstrapIPv6Only(t *testing.T) {
	// Test with IPv6-only bootstrap addresses
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "[2606:4700:4700::1111]"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify IPv6 bootstrap IPs
	if len(parsedStamp.BootstrapIPs) != 2 {
		t.Errorf("expected 2 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}
	if parsedStamp.BootstrapIPs[0] != "2606:4700:4700::1111" {
		t.Errorf("expected first bootstrap IP 2606:4700:4700::1111 but got %q", parsedStamp.BootstrapIPs[0])
	}
	if parsedStamp.BootstrapIPs[1] != "2606:4700:4700::1001" {
		t.Errorf("expected second bootstrap IP 2606:4700:4700::1001 but got %q", parsedStamp.BootstrapIPs[1])
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

// Bootstrap IP address tests for DoQ

func TestDNSOverQUIC_SingleBootstrapIP(t *testing.T) {
	// Test DoQ stamp with single bootstrap IP address
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"1.1.1.1"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify bootstrap IPs were parsed correctly
	if len(parsedStamp.BootstrapIPs) != 1 {
		t.Errorf("expected 1 bootstrap IP but got %d", len(parsedStamp.BootstrapIPs))
	}
	if parsedStamp.BootstrapIPs[0] != "1.1.1.1" {
		t.Errorf("expected bootstrap IP 1.1.1.1 but got %q", parsedStamp.BootstrapIPs[0])
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_MultipleBootstrapIPs(t *testing.T) {
	// Test with multiple bootstrap IP addresses (IPv4 and IPv6)
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "9.9.9.9"
	stamp.ProviderName = "dns.quad9.net"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all bootstrap IPs were parsed correctly
	if len(parsedStamp.BootstrapIPs) != 3 {
		t.Errorf("expected 3 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}
	expectedIPs := []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe"}
	for i, expectedIP := range expectedIPs {
		if parsedStamp.BootstrapIPs[i] != expectedIP {
			t.Errorf("expected bootstrap IP %q at index %d but got %q", expectedIP, i, parsedStamp.BootstrapIPs[i])
		}
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_BootstrapIPsWithAllProps(t *testing.T) {
	// Test with bootstrap IPs and all properties
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC | ServerInformalPropertyNoLog | ServerInformalPropertyNoFilter
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "8.8.8.8:8853"
	stamp.ProviderName = "dns.google"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"8.8.8.8", "8.8.4.4"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all fields were preserved
	if parsedStamp.Props != stamp.Props {
		t.Errorf("expected props %v but got %v", stamp.Props, parsedStamp.Props)
	}
	if parsedStamp.ServerAddrStr != "8.8.8.8:8853" {
		t.Errorf("expected server address 8.8.8.8:8853 but got %q", parsedStamp.ServerAddrStr)
	}
	if len(parsedStamp.BootstrapIPs) != 2 {
		t.Errorf("expected 2 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_NoBootstrapIPs_BackwardCompatibility(t *testing.T) {
	// Test that DoQ stamps without bootstrap IPs still work (backward compatibility)
	var stamp ServerStamp
	stamp.Props = ServerInformalPropertyDNSSEC
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.0.0.1"
	stamp.ProviderName = "one.one.one.one"
	stamp.Hashes = [][]uint8{pk1}
	// No bootstrap IPs set

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify no bootstrap IPs
	if len(parsedStamp.BootstrapIPs) != 0 {
		t.Errorf("expected 0 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}

func TestDNSOverQUIC_BootstrapIPv6Only(t *testing.T) {
	// Test with IPv6-only bootstrap addresses
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "[2606:4700:4700::1111]"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}
	stamp.BootstrapIPs = []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify IPv6 bootstrap IPs
	if len(parsedStamp.BootstrapIPs) != 2 {
		t.Errorf("expected 2 bootstrap IPs but got %d", len(parsedStamp.BootstrapIPs))
	}
	if parsedStamp.BootstrapIPs[0] != "2606:4700:4700::1111" {
		t.Errorf("expected first bootstrap IP 2606:4700:4700::1111 but got %q", parsedStamp.BootstrapIPs[0])
	}
	if parsedStamp.BootstrapIPs[1] != "2606:4700:4700::1001" {
		t.Errorf("expected second bootstrap IP 2606:4700:4700::1001 but got %q", parsedStamp.BootstrapIPs[1])
	}

	ps := parsedStamp.String()
	if ps != stampStr {
		t.Errorf("re-parsed stamp string is %q, but %q expected", ps, stampStr)
	}
}
