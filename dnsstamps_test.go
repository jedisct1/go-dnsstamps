package dnsstamps

import (
	"bytes"
	"encoding/base64"
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
	// Real-world Quad9 stamp: addr="9.9.9.10", hostname="dns9.quad9.net:443".
	// Per spec the port belongs on the hostname field; since 443 is the DoH
	// default, round-trip drops the explicit port and produces the canonical
	// (shorter) form.
	const q9 = `sdns://AgYAAAAAAAAACDkuOS45LjEwABJkbnM5LnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ`
	const canonical = `sdns://AgYAAAAAAAAACDkuOS45LjEwAA5kbnM5LnF1YWQ5Lm5ldAovZG5zLXF1ZXJ5`

	parsedStamp, err := NewServerStampFromString(q9)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "9.9.9.10:443" {
		t.Errorf("expected ServerAddrStr 9.9.9.10:443, got %q", parsedStamp.ServerAddrStr)
	}
	if parsedStamp.ProviderName != "dns9.quad9.net" {
		t.Errorf("expected ProviderName dns9.quad9.net (port stripped), got %q", parsedStamp.ProviderName)
	}
	ps := parsedStamp.String()
	if ps != canonical {
		t.Errorf("re-parsed stamp string is %q, but canonical %q expected", ps, canonical)
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
	// Legacy ODoH relay stamp emitted with port 1 on the addr field
	// ("[::1]:1"). The library now accepts this (backward compatibility) but
	// re-serializes it in the spec-conformant form with port on the hostname
	// field ("doh.example.com:1"), so the round-trip canonical form differs.
	const stamp = `sdns://hQcAAAAAAAAAB1s6OjFdOjEgw4Rr8kuek8pkJ0wOxnwezF4CT_ys0tdAGTUOgf5UauQPZG9oLmV4YW1wbGUuY29tBi9yZWxheQ`
	const canonical = `sdns://hQcAAAAAAAAABVs6OjFdIMOEa_JLnpPKZCdMDsZ8HsxeAk_8rNLXQBk1DoH-VGrkEWRvaC5leGFtcGxlLmNvbToxBi9yZWxheQ`

	parsedStamp, err := NewServerStampFromString(stamp)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStamp.ServerAddrStr != "[::1]:1" {
		t.Errorf("expected ServerAddrStr [::1]:1, got %q", parsedStamp.ServerAddrStr)
	}
	if parsedStamp.ProviderName != "doh.example.com" {
		t.Errorf("expected ProviderName doh.example.com, got %q", parsedStamp.ProviderName)
	}
	ps := parsedStamp.String()
	if ps != canonical {
		t.Errorf("re-parsed stamp string is %q, but canonical %q expected", ps, canonical)
	}

	// Re-parsing the canonical form must produce the same in-memory stamp.
	reparsed, err := NewServerStampFromString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if reparsed.ServerAddrStr != parsedStamp.ServerAddrStr || reparsed.ProviderName != parsedStamp.ProviderName {
		t.Errorf("canonical form does not round-trip: got addr=%q name=%q", reparsed.ServerAddrStr, reparsed.ProviderName)
	}
}

func TestRelayServerPair(t *testing.T) {
	const stamp = `sdns://hQcAAAAAAAAAB1s6OjFdOjEgw4Rr8kuek8pkJ0wOxnwezF4CT_ys0tdAGTUOgf5UauQPZG9oLmV4YW1wbGUuY29tBi9yZWxheQ/BQEAAAAAAAAAEG9kb2guZXhhbXBsZS5jb20HL3RhcmdldA`
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
	// Test with custom port 8853 - per spec the port is encoded on the
	// hostname field, so the addr field carries "1.1.1.1" and the hostname
	// field carries "cloudflare-dns.com:8853".
	const expected = `sdns://AwcAAAAAAAAABzEuMS4xLjEgw4Rr8kuek8pkJ0wOxnwezF4CT_ys0tdAGTUOgf5UauQXY2xvdWRmbGFyZS1kbnMuY29tOjg4NTM`

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
	// Test with custom port 8853 - per spec the port is encoded on the
	// hostname field, so the addr field carries "1.1.1.1" and the hostname
	// field carries "cloudflare-dns.com:8853".
	const expected = `sdns://BAcAAAAAAAAABzEuMS4xLjEgw4Rr8kuek8pkJ0wOxnwezF4CT_ys0tdAGTUOgf5UauQXY2xvdWRmbGFyZS1kbnMuY29tOjg4NTM`

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

// Hash length validation tests

func TestDoH_InvalidHashLength_TooShort(t *testing.T) {
	// Create a DoH stamp with 16-byte hash (should be rejected)
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Path = "/dns-query"
	// 16-byte hash instead of required 32 bytes
	stamp.Hashes = [][]uint8{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}}

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error for 16-byte hash, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}

func TestDoH_InvalidHashLength_TooLong(t *testing.T) {
	// Create a DoH stamp with 48-byte hash (should be rejected)
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "8.8.8.8"
	stamp.ProviderName = "dns.google"
	stamp.Path = "/dns-query"
	// 48-byte hash (oversized)
	stamp.Hashes = [][]uint8{{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	}}

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error for 48-byte hash, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}

func TestDoT_InvalidHashLength(t *testing.T) {
	// Test DoT with invalid hash length
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "9.9.9.9"
	stamp.ProviderName = "dns.quad9.net"
	// 20-byte hash (wrong size)
	stamp.Hashes = [][]uint8{{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14,
	}}

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error for 20-byte hash, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}

func TestDoQ_InvalidHashLength(t *testing.T) {
	// Test DoQ with 1-byte hash
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "1.0.0.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{{0xFF}} // Just 1 byte

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error for 1-byte hash, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}

func TestODoHRelay_InvalidHashLength(t *testing.T) {
	// Test ODoH Relay with invalid hash length
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeODoHRelay
	stamp.ServerAddrStr = "relay.example.com"
	stamp.ProviderName = "relay.example.com"
	stamp.Path = "/proxy"
	// 31-byte hash (one byte short)
	stamp.Hashes = [][]uint8{{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}}

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error for 31-byte hash, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}

func TestDoH_ValidHashLength_MultipleHashes(t *testing.T) {
	// Test that valid 32-byte hashes still work, including multiple hashes
	hash1 := pk1 // pk1 is 32 bytes from existing tests
	hash2 := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	}

	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "8.8.8.8"
	stamp.ProviderName = "dns.google"
	stamp.Path = "/dns-query"
	stamp.Hashes = [][]uint8{hash1, hash2}

	stampStr := stamp.String()
	parsedStamp, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatalf("unexpected error for valid 32-byte hashes: %v", err)
	}

	if len(parsedStamp.Hashes) != 2 {
		t.Errorf("expected 2 hashes but got %d", len(parsedStamp.Hashes))
	}
	for i, hash := range parsedStamp.Hashes {
		if len(hash) != 32 {
			t.Errorf("hash %d: expected 32 bytes but got %d", i, len(hash))
		}
	}
}

// Port-in-hostname tests (draft-denis-dns-stamps section 4.3.2 and friends).
// The spec places the optional port on the hostname field, not addr.

func TestDoH_PortFromHostnameField(t *testing.T) {
	// Spec-conformant DoH stamp: port encoded on hostname field. After parse,
	// the port is exposed on ServerAddrStr and ProviderName has no suffix.
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "1.1.1.1:8443"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Path = "/dns-query"

	encoded := stamp.String()
	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "1.1.1.1:8443" {
		t.Errorf("ServerAddrStr: want 1.1.1.1:8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName must not carry port suffix, got %q", parsed.ProviderName)
	}
}

func TestDoH_DefaultPortOmittedFromHostname(t *testing.T) {
	// When the port equals the DoH default (443), it must not be appended to
	// the hostname field on the wire.
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "1.1.1.1:443"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Path = "/dns-query"

	encoded := stamp.String()
	// Inspect the decoded wire bytes directly — a base64 substring check
	// is unreliable because the embedded ASCII may not start on a 3-byte
	// boundary in the binary blob.
	if bytes.Contains(decodeStamp(t, encoded), []byte("cloudflare-dns.com:443")) {
		t.Errorf("default port 443 leaked into wire bytes: %s", encoded)
	}

	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "1.1.1.1:443" {
		t.Errorf("ServerAddrStr: want 1.1.1.1:443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName: want cloudflare-dns.com, got %q", parsed.ProviderName)
	}
}

func TestDoH_LegacyPortInAddr_BackwardCompat(t *testing.T) {
	// Stamps emitted by older versions of this library put the port on the
	// addr field. Parsing must still accept them and surface the port on
	// ServerAddrStr.
	//
	// Wire content: addr="1.1.1.1:8443", hostname="cloudflare-dns.com".
	bin := []byte{
		0x02,                                           // DoH
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // props
	}
	addr := "1.1.1.1:8443"
	bin = append(bin, byte(len(addr)))
	bin = append(bin, []byte(addr)...)
	bin = append(bin, 0x00) // no hashes
	hostname := "cloudflare-dns.com"
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	parsed, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatalf("legacy port-in-addr stamp failed to parse: %v", err)
	}
	if parsed.ServerAddrStr != "1.1.1.1:8443" {
		t.Errorf("ServerAddrStr: want 1.1.1.1:8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName: want cloudflare-dns.com, got %q", parsed.ProviderName)
	}
}

func TestDoH_HostnamePortWinsOverAddrPort(t *testing.T) {
	// If a (malformed) stamp specifies port on both fields, the spec's
	// hostname-field port takes precedence.
	bin := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	addr := "1.1.1.1:111"
	bin = append(bin, byte(len(addr)))
	bin = append(bin, []byte(addr)...)
	bin = append(bin, 0x00)
	hostname := "cloudflare-dns.com:2222"
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	parsed, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "1.1.1.1:2222" {
		t.Errorf("hostname-field port must win: want 1.1.1.1:2222, got %q", parsed.ServerAddrStr)
	}
}

func TestDoT_PortRoundTripsViaHostname(t *testing.T) {
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "9.9.9.9:8853"
	stamp.ProviderName = "dns.quad9.net"
	stamp.Hashes = [][]uint8{pk1}

	encoded := stamp.String()
	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "9.9.9.9:8853" {
		t.Errorf("ServerAddrStr: want 9.9.9.9:8853, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "dns.quad9.net" {
		t.Errorf("ProviderName must be hostname only, got %q", parsed.ProviderName)
	}
}

func TestDoQ_PortRoundTripsViaHostname(t *testing.T) {
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoQ
	stamp.ServerAddrStr = "[2606:4700:4700::1111]:8853"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{pk1}

	encoded := stamp.String()
	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "[2606:4700:4700::1111]:8853" {
		t.Errorf("ServerAddrStr: want [2606:4700:4700::1111]:8853, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName must be hostname only, got %q", parsed.ProviderName)
	}
}

func TestODoHRelay_PortRoundTripsViaHostname(t *testing.T) {
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeODoHRelay
	stamp.ServerAddrStr = "1.2.3.4:8443"
	stamp.ProviderName = "relay.example.com"
	stamp.Path = "/proxy"
	stamp.Hashes = [][]uint8{pk1}

	encoded := stamp.String()
	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "1.2.3.4:8443" {
		t.Errorf("ServerAddrStr: want 1.2.3.4:8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "relay.example.com" {
		t.Errorf("ProviderName must be hostname only, got %q", parsed.ProviderName)
	}
}

func TestDoH_InvalidPortInHostnameRejected(t *testing.T) {
	bin := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	addr := "1.1.1.1"
	bin = append(bin, byte(len(addr)))
	bin = append(bin, []byte(addr)...)
	bin = append(bin, 0x00)
	hostname := "cloudflare-dns.com:99999" // out of range
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	if _, err := NewServerStampFromString(stampStr); err == nil {
		t.Error("expected error for out-of-range port in hostname field")
	}
}

// toBase64URL is a small helper for hand-built binary stamps in tests above.
func toBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeStamp strips the sdns:// prefix and returns the raw wire bytes so
// assertions can look at ASCII fields directly without relying on base64
// substring matches (which break when the embedded bytes don't align on a
// 3-byte boundary).
func decodeStamp(t *testing.T, stamp string) []byte {
	t.Helper()
	s := strings.TrimPrefix(stamp, StampScheme)
	bin, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decodeStamp: %v", err)
	}
	return bin
}

func TestODoHTarget_PortRoundTripsViaHostname(t *testing.T) {
	// Spec section 4.6: ODoH Target has no addr field, but the hostname
	// field may carry an optional ":port" suffix. After parse, the port
	// must be exposed on ServerAddrStr (":port") and ProviderName must be
	// the hostname only.
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeODoHTarget
	stamp.ServerAddrStr = ":8443"
	stamp.ProviderName = "odoh.example.com"
	stamp.Path = "/dns-query"

	encoded := stamp.String()
	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != ":8443" {
		t.Errorf("ServerAddrStr: want :8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "odoh.example.com" {
		t.Errorf("ProviderName must be hostname only, got %q", parsed.ProviderName)
	}
}

func TestODoHTarget_DefaultPortOmittedFromHostname(t *testing.T) {
	// Port 443 is the ODoH Target default — it must not appear in the
	// encoded hostname field, and a stamp lacking a port must parse with
	// ServerAddrStr empty.
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeODoHTarget
	stamp.ServerAddrStr = ":443"
	stamp.ProviderName = "odoh.example.com"
	stamp.Path = "/dns-query"

	encoded := stamp.String()
	if bytes.Contains(decodeStamp(t, encoded), []byte("odoh.example.com:443")) {
		t.Errorf("default port 443 leaked into wire bytes: %s", encoded)
	}

	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "" {
		t.Errorf("ServerAddrStr: want \"\" (default port stripped), got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "odoh.example.com" {
		t.Errorf("ProviderName: want odoh.example.com, got %q", parsed.ProviderName)
	}
}

func TestODoHTarget_ParseHostnamePortFromWire(t *testing.T) {
	// Hand-built ODoH Target stamp with port suffix on the hostname field.
	bin := []byte{
		0x05,                                           // ODoH Target
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // props
	}
	hostname := "odoh.example.com:8443"
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	parsed, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != ":8443" {
		t.Errorf("ServerAddrStr: want :8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "odoh.example.com" {
		t.Errorf("ProviderName must not carry port suffix, got %q", parsed.ProviderName)
	}
}

func TestDoH_TrailingColonInHostnameRejected(t *testing.T) {
	bin := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	addr := "1.1.1.1"
	bin = append(bin, byte(len(addr)))
	bin = append(bin, []byte(addr)...)
	bin = append(bin, 0x00)           // no hashes
	hostname := "cloudflare-dns.com:" // trailing colon, empty port
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	if _, err := NewServerStampFromString(stampStr); err == nil {
		t.Error("expected error for trailing colon (empty port) in hostname")
	}
}

func TestDoH_ServerAddrStrPortWinsOverStaleProviderNamePort(t *testing.T) {
	// If a caller leaves a stale ":port" on ProviderName, the encoder must
	// not let that override ServerAddrStr's port - ServerAddrStr is the
	// documented single source of truth.
	var stamp ServerStamp
	stamp.Proto = StampProtoTypeDoH
	stamp.ServerAddrStr = "1.1.1.1:443"
	stamp.ProviderName = "cloudflare-dns.com:8443" // stale - must be ignored
	stamp.Path = "/dns-query"

	encoded := stamp.String()
	wire := decodeStamp(t, encoded)
	if bytes.Contains(wire, []byte(":8443")) {
		t.Errorf("stale ProviderName port leaked to wire: %s", encoded)
	}

	parsed, err := NewServerStampFromString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != "1.1.1.1:443" {
		t.Errorf("ServerAddrStr: want 1.1.1.1:443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName: want cloudflare-dns.com, got %q", parsed.ProviderName)
	}
}

func TestDoH_EmptyAddrWithPortInHostname(t *testing.T) {
	// addr empty, hostname carries port - port must be surfaced via
	// ServerAddrStr as ":port" and ProviderName must be SNI-safe.
	bin := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	bin = append(bin, 0x00) // empty addr
	bin = append(bin, 0x00) // no hashes
	hostname := "cloudflare-dns.com:8443"
	bin = append(bin, byte(len(hostname)))
	bin = append(bin, []byte(hostname)...)
	path := "/dns-query"
	bin = append(bin, byte(len(path)))
	bin = append(bin, []byte(path)...)

	stampStr := "sdns://" + strings.TrimRight(toBase64URL(bin), "=")
	parsed, err := NewServerStampFromString(stampStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ServerAddrStr != ":8443" {
		t.Errorf("ServerAddrStr: want :8443, got %q", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName must not carry port suffix, got %q", parsed.ProviderName)
	}
}

func TestDoT_InvalidHashLength_MultipleHashes_OneInvalid(t *testing.T) {
	// Test that if one hash in a multi-hash set is invalid, parsing fails
	hash1 := pk1                      // Valid 32-byte hash
	hash2 := []byte{0x01, 0x02, 0x03} // Invalid 3-byte hash

	var stamp ServerStamp
	stamp.Proto = StampProtoTypeTLS
	stamp.ServerAddrStr = "1.1.1.1"
	stamp.ProviderName = "cloudflare-dns.com"
	stamp.Hashes = [][]uint8{hash1, hash2}

	stampStr := stamp.String()
	_, err := NewServerStampFromString(stampStr)
	if err == nil {
		t.Error("expected error when one of multiple hashes is invalid, but got none")
	}
	if err != nil && err.Error() != "Invalid stamp (certificate hash must be 32 bytes)" {
		t.Errorf("expected certificate hash error, got: %v", err)
	}
}
