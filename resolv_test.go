// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// --- IPv4 -------------------------------------------------------------------

func TestIPv4Create(t *testing.T) {
	ip, err := CreateIPv4("1.2.3.4")
	if err != nil {
		t.Fatalf("CreateIPv4: %v", err)
	}
	if got := ip.String(); got != "1.2.3.4" {
		t.Errorf("String = %q", got)
	}
	if hex.EncodeToString(ip.Addr[:]) != "01020304" {
		t.Errorf("Addr = %x", ip.Addr)
	}
	if got := ip.Inspect(); got != "#<Resolv::IPv4 1.2.3.4>" {
		t.Errorf("Inspect = %q", got)
	}
}

func TestIPv4CreateErrors(t *testing.T) {
	for _, s := range []string{"256.1.1.1", "1.2.3", "1.2.3.4.5", "::1", "01.2.3.4", "a.b.c.d", ""} {
		if _, err := CreateIPv4(s); err == nil {
			t.Errorf("CreateIPv4(%q) succeeded, want error", s)
		}
	}
}

func TestIPv4Equal(t *testing.T) {
	a, _ := CreateIPv4("1.2.3.4")
	b, _ := CreateIPv4("1.2.3.4")
	c, _ := CreateIPv4("4.3.2.1")
	if !a.Equal(b) {
		t.Error("equal addresses not Equal")
	}
	if a.Equal(c) {
		t.Error("unequal addresses Equal")
	}
}

func TestNewIPv4(t *testing.T) {
	ip, err := NewIPv4([]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Errorf("String = %q", ip.String())
	}
	if _, err := NewIPv4([]byte{1, 2, 3}); err == nil {
		t.Error("NewIPv4 with 3 bytes succeeded")
	}
}

func TestIPv4ToName(t *testing.T) {
	ip, _ := CreateIPv4("1.2.3.4")
	n := ip.ToName()
	if got := n.String(); got != "4.3.2.1.in-addr.arpa" {
		t.Errorf("ToName = %q", got)
	}
	if !n.Absolute {
		t.Error("ToName not absolute")
	}
}

func TestIPv4Regex(t *testing.T) {
	cases := map[string]bool{
		"192.168.0.1":     true,
		"0.0.0.0":         true,
		"255.255.255.255": true,
		"256.1.1.1":       false,
		"01.2.3.4":        false,
		"not-an-ip":       false,
		"a1.2.3.4b":       false,
		"1.2.3":           false,
	}
	for s, want := range cases {
		if got := IPv4Regex.MatchString(s); got != want {
			t.Errorf("IPv4Regex.MatchString(%q) = %v, want %v", s, got, want)
		}
	}
}

// --- IPv6 -------------------------------------------------------------------

func TestIPv6CreateAndString(t *testing.T) {
	cases := map[string]string{
		"2606:2800:220:1:248:1893:25c8:1946": "2606:2800:220:1:248:1893:25c8:1946",
		"2001:db8:0:0:0:0:0:1":               "2001:db8::1",
		"::1":                                "::1",
		"0:0:0:0:0:0:0:0":                    "::",
		"ff02:0:0:0:0:0:0:1":                 "ff02::1",
		"2001:0:0:1:0:0:0:1":                 "2001::1:0:0:0:1",
		"1:0:0:0:1:0:0:0":                    "1::1:0:0:0",
		"fe80::1":                            "fe80::1",
		"::ffff:192.168.1.1":                 "::ffff:c0a8:101",
		"::13.1.68.3":                        "::d01:4403",
		"1:2:3:4:5:6:7:8":                    "1:2:3:4:5:6:7:8",
		"0:0:0:0:0:0:1.2.3.4":                "::102:304",
	}
	for in, want := range cases {
		ip, err := CreateIPv6(in)
		if err != nil {
			t.Errorf("CreateIPv6(%q): %v", in, err)
			continue
		}
		if got := ip.String(); got != want {
			t.Errorf("CreateIPv6(%q).String() = %q, want %q", in, got, want)
		}
	}
}

func TestIPv6CreateErrors(t *testing.T) {
	for _, s := range []string{
		"not-ipv6", "1.2.3.4", "fe80::1%eth0", "::ffff:999.1.1.1",
		"1:2:3:4:5:6:300.1.1.1", "zzz", "",
	} {
		if _, err := CreateIPv6(s); err == nil {
			t.Errorf("CreateIPv6(%q) succeeded, want error", s)
		}
	}
}

func TestIPv6Inspect(t *testing.T) {
	ip, _ := CreateIPv6("::1")
	if got := ip.Inspect(); got != "#<Resolv::IPv6 ::1>" {
		t.Errorf("Inspect = %q", got)
	}
}

func TestIPv6Equal(t *testing.T) {
	a, _ := CreateIPv6("FE80::1")
	b, _ := CreateIPv6("fe80::1")
	c, _ := CreateIPv6("::2")
	if !a.Equal(b) {
		t.Error("case-insensitive addresses not Equal")
	}
	if a.Equal(c) {
		t.Error("distinct addresses Equal")
	}
}

func TestIPv6AddrHex(t *testing.T) {
	ip, _ := CreateIPv6("::1")
	if hex.EncodeToString(ip.Addr[:]) != "00000000000000000000000000000001" {
		t.Errorf("Addr = %x", ip.Addr)
	}
}

func TestNewIPv6(t *testing.T) {
	b := make([]byte, 16)
	b[15] = 1
	ip, err := NewIPv6(b)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "::1" {
		t.Errorf("String = %q", ip.String())
	}
	if _, err := NewIPv6([]byte{1, 2}); err == nil {
		t.Error("NewIPv6 with 2 bytes succeeded")
	}
}

func TestIPv6Regex(t *testing.T) {
	cases := map[string]bool{
		"::1":         true,
		"fe80::1%em1": true, // link-local form match? accepts (create rejects)
		"zzz":         false,
		"xx::1yy":     false,
	}
	for s, want := range cases {
		if got := IPv6Regex.MatchString(s); got != want {
			t.Errorf("IPv6Regex.MatchString(%q) = %v, want %v", s, got, want)
		}
	}
}

// --- Name -------------------------------------------------------------------

func TestNameBasics(t *testing.T) {
	n := NewName("www.example.com")
	if got := n.String(); got != "www.example.com" {
		t.Errorf("String = %q", got)
	}
	if n.Length() != 3 {
		t.Errorf("Length = %d", n.Length())
	}
	if n.Absolute {
		t.Error("non-dotted name marked absolute")
	}
	abs := NewName("www.example.com.")
	if !abs.Absolute {
		t.Error("dotted name not absolute")
	}
	if n.Equal(abs) {
		t.Error("absolute and relative names compared equal")
	}
}

func TestNameRootAndEmpty(t *testing.T) {
	root := NewName(".")
	if root.String() != "" || root.Length() != 0 || !root.Absolute {
		t.Errorf("root: %q len=%d abs=%v", root.String(), root.Length(), root.Absolute)
	}
	empty := NewName("")
	if empty.String() != "" || empty.Length() != 0 || empty.Absolute {
		t.Errorf("empty: %q len=%d abs=%v", empty.String(), empty.Length(), empty.Absolute)
	}
}

func TestNameCaseInsensitive(t *testing.T) {
	if !NewName("WWW.Example.COM").Equal(NewName("www.example.com")) {
		t.Error("case-insensitive names not equal")
	}
	if got := NewName("WWW.Example.COM").String(); got != "WWW.Example.COM" {
		t.Errorf("case not preserved in String: %q", got)
	}
}

func TestNameEqualLengthMismatch(t *testing.T) {
	if NewName("a.b").Equal(NewName("a.b.c")) {
		t.Error("different-length names equal")
	}
}

func TestNameInspect(t *testing.T) {
	if got := NewName("a.b").Inspect(); got != "#<Resolv::DNS::Name: a.b>" {
		t.Errorf("relative Inspect = %q", got)
	}
	if got := NewName("a.b.").Inspect(); got != "#<Resolv::DNS::Name: a.b.>" {
		t.Errorf("absolute Inspect = %q", got)
	}
}

func TestNameSubdomain(t *testing.T) {
	if !NewName("a.b.c").SubdomainOf(NewName("b.c")) {
		t.Error("a.b.c not subdomain of b.c")
	}
	if NewName("b.c").SubdomainOf(NewName("b.c")) {
		t.Error("b.c reported subdomain of itself")
	}
	if NewName("a.b.c.").SubdomainOf(NewName("b.c")) {
		t.Error("absolute/relative mismatch reported subdomain")
	}
	if NewName("a.x.c").SubdomainOf(NewName("b.c")) {
		t.Error("non-matching suffix reported subdomain")
	}
}

func TestLabelString(t *testing.T) {
	l := Label{Str: "Foo"}
	if l.String() != "Foo" {
		t.Errorf("Label.String = %q", l.String())
	}
	if !l.Equal(Label{Str: "foo"}) {
		t.Error("labels not case-insensitively equal")
	}
}

// --- Message ----------------------------------------------------------------

func TestEncodeQuestion(t *testing.T) {
	m := NewMessage(0x1234)
	m.AddQuestion(NewName("www.example.com"), TypeA, ClassIN)
	want := "12340000000100000000000003777777076578616d706c6503636f6d0000010001"
	if got := hex.EncodeToString(m.Encode()); got != want {
		t.Errorf("Encode =\n %s\nwant\n %s", got, want)
	}
}

// fullMessageHex is the golden encoding of a 10-answer IN response, produced by
// MRI 4.0.5 Resolv::DNS::Message#encode.
const fullMessageHex = "abcd85800001000a00000000076578616d706c6503636f6d0000010001c00c0001000100000e1000045db8d822c00c001c000100000e10001026062800022000010248189325c81946c00c000f0001000000640009000a046d61696cc00cc00c0010000100000064000c0568656c6c6f05776f726c64c00c0005000100000064000805616c696173c00cc00c00020001000000640006036e7331c00c013401330132013107696e2d61646472046172706100000c000100000064000704686f7374c00c045f736970045f746370c00c0021000100000064001d000a001413c409736970736572766572076578616d706c6503636f6d00c0e90006000100000064001ec0960561646d696ec0e978a3f17500001c2000000e100012750000000e10c0e9000d000100000064000c05496e74656c054c696e7578"

func buildFullMessage() *Message {
	m := NewMessage(0xabcd)
	m.QR, m.AA, m.RD, m.RA = 1, 1, 1, 1
	m.AddQuestion(NewName("example.com"), TypeA, ClassIN)
	a, _ := CreateIPv4("93.184.216.34")
	m.AddAnswer(NewName("example.com"), 3600, &A{Address: a})
	a6, _ := CreateIPv6("2606:2800:220:1:248:1893:25c8:1946")
	m.AddAnswer(NewName("example.com"), 3600, &AAAA{Address: a6})
	m.AddAnswer(NewName("example.com"), 100, &MX{Preference: 10, Exchange: NewName("mail.example.com")})
	m.AddAnswer(NewName("example.com"), 100, &TXT{Strings: []string{"hello", "world"}})
	m.AddAnswer(NewName("example.com"), 100, NewCNAME(NewName("alias.example.com")))
	m.AddAnswer(NewName("example.com"), 100, NewNS(NewName("ns1.example.com")))
	m.AddAnswer(NewName("4.3.2.1.in-addr.arpa"), 100, NewPTR(NewName("host.example.com")))
	m.AddAnswer(NewName("_sip._tcp.example.com"), 100, &SRV{Priority: 10, Weight: 20, Port: 5060, Target: NewName("sipserver.example.com")})
	m.AddAnswer(NewName("example.com"), 100, &SOA{
		MName: NewName("ns1.example.com"), RName: NewName("admin.example.com"),
		Serial: 2024010101, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600,
	})
	m.AddAnswer(NewName("example.com"), 100, &HINFO{CPU: "Intel", OS: "Linux"})
	return m
}

func TestEncodeFullMessage(t *testing.T) {
	if got := hex.EncodeToString(buildFullMessage().Encode()); got != fullMessageHex {
		t.Errorf("Encode =\n %s\nwant\n %s", got, fullMessageHex)
	}
}

func TestDecodeFullMessage(t *testing.T) {
	raw, _ := hex.DecodeString(fullMessageHex)
	m, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m.ID != 0xabcd || m.QR != 1 || m.AA != 1 || m.RD != 1 || m.RA != 1 {
		t.Errorf("header = %+v", m)
	}
	if len(m.Question) != 1 || len(m.Answer) != 10 {
		t.Fatalf("sections q=%d a=%d", len(m.Question), len(m.Answer))
	}
	// Re-encode must reproduce the exact bytes.
	if got := hex.EncodeToString(m.Encode()); got != fullMessageHex {
		t.Errorf("round-trip mismatch:\n %s", got)
	}
	// Spot-check typed accessors.
	a := m.Answer[0].Data.(*A)
	if a.Address.String() != "93.184.216.34" || a.TTL != 3600 {
		t.Errorf("A = %+v", a)
	}
	aaaa := m.Answer[1].Data.(*AAAA)
	if aaaa.Address.String() != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Errorf("AAAA = %+v", aaaa)
	}
	mx := m.Answer[2].Data.(*MX)
	if mx.Preference != 10 || mx.Exchange.String() != "mail.example.com" {
		t.Errorf("MX = %+v", mx)
	}
	txt := m.Answer[3].Data.(*TXT)
	if !reflect.DeepEqual(txt.Strings, []string{"hello", "world"}) {
		t.Errorf("TXT = %+v", txt)
	}
	cn := m.Answer[4].Data.(*CNAME)
	if cn.Name.String() != "alias.example.com" || cn.TypeValue() != TypeCNAME {
		t.Errorf("CNAME = %+v", cn)
	}
	ns := m.Answer[5].Data.(*NS)
	if ns.Name.String() != "ns1.example.com" || ns.TypeValue() != TypeNS {
		t.Errorf("NS = %+v", ns)
	}
	ptr := m.Answer[6].Data.(*PTR)
	if ptr.Name.String() != "host.example.com" || ptr.TypeValue() != TypePTR {
		t.Errorf("PTR = %+v", ptr)
	}
	srv := m.Answer[7].Data.(*SRV)
	if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 5060 || srv.Target.String() != "sipserver.example.com" {
		t.Errorf("SRV = %+v", srv)
	}
	soa := m.Answer[8].Data.(*SOA)
	if soa.MName.String() != "ns1.example.com" || soa.RName.String() != "admin.example.com" ||
		soa.Serial != 2024010101 || soa.Refresh != 7200 || soa.Retry != 3600 ||
		soa.Expire != 1209600 || soa.Minimum != 3600 {
		t.Errorf("SOA = %+v", soa)
	}
	hinfo := m.Answer[9].Data.(*HINFO)
	if hinfo.CPU != "Intel" || hinfo.OS != "Linux" {
		t.Errorf("HINFO = %+v", hinfo)
	}
}

func TestDecodeQuestionOnly(t *testing.T) {
	raw, _ := hex.DecodeString("12340000000100000000000003777777076578616d706c6503636f6d0000010001")
	m, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || len(m.Question) != 1 {
		t.Fatalf("m = %+v", m)
	}
	q := m.Question[0]
	if q.Name.String() != "www.example.com" || q.Type != TypeA || q.Class != ClassIN {
		t.Errorf("question = %+v", q)
	}
}

func TestEncodeAllSections(t *testing.T) {
	m := NewMessage(7)
	m.AddQuestion(NewName("a.com"), TypeA, ClassIN)
	a, _ := CreateIPv4("1.2.3.4")
	m.AddAnswer(NewName("a.com"), 1, &A{Address: a})
	m.AddAuthority(NewName("a.com"), 2, NewNS(NewName("ns.a.com")))
	m.AddAdditional(NewName("ns.a.com"), 3, &A{Address: a})
	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Answer) != 1 || len(got.Authority) != 1 || len(got.Additional) != 1 {
		t.Errorf("sections: %+v", got)
	}
	if got.Authority[0].TTL != 2 || got.Additional[0].TTL != 3 {
		t.Errorf("TTLs: auth=%d add=%d", got.Authority[0].TTL, got.Additional[0].TTL)
	}
}

func TestDecodeTruncated(t *testing.T) {
	// TC bit set: MRI returns after the header.
	m := NewMessage(99)
	m.TC = 1
	m.AddAnswer(NewName("a.com"), 1, &A{Address: IPv4{}})
	raw := m.Encode()
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.TC != 1 || len(got.Answer) != 0 {
		t.Errorf("truncated decode = %+v", got)
	}
}

func TestDecodeRCodeAndFlags(t *testing.T) {
	m := NewMessage(1)
	m.Opcode = 2
	m.RCode = 3
	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != 2 || got.RCode != 3 {
		t.Errorf("opcode=%d rcode=%d", got.Opcode, got.RCode)
	}
}

func TestGenericRecord(t *testing.T) {
	// TYPE 99 / CLASS IN is not specially modelled -> Generic round-trip.
	m := NewMessage(1)
	m.AddAnswer(NewName("x.com"), 5, &Generic{Type: 99, Class: ClassIN, Data: []byte{1, 2, 3}})
	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	g := got.Answer[0].Data.(*Generic)
	if g.Type != 99 || g.Class != ClassIN || !reflect.DeepEqual(g.Data, []byte{1, 2, 3}) || g.TTL != 5 {
		t.Errorf("Generic = %+v", g)
	}
}

func TestTXTMultiSegmentRoundTrip(t *testing.T) {
	long := make([]byte, 255)
	for i := range long {
		long[i] = 'a'
	}
	m := NewMessage(1)
	m.AddAnswer(NewName("x.com"), 0, &TXT{Strings: []string{string(long), "b"}})
	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	txt := got.Answer[0].Data.(*TXT)
	if len(txt.Strings) != 2 || txt.Strings[0] != string(long) || txt.Strings[1] != "b" {
		t.Errorf("TXT segments wrong: %d", len(txt.Strings))
	}
}

func TestNameCompressionPointer(t *testing.T) {
	// Two questions for the same name: the second must be a 0xC0 pointer.
	m := NewMessage(0)
	m.AddQuestion(NewName("example.com"), TypeA, ClassIN)
	m.AddQuestion(NewName("example.com"), TypeA, ClassIN)
	raw := m.Encode()
	// header(12) + name(13) + type/class(4) = 29; the 2nd question name is at 29.
	if raw[29] != 0xc0 || raw[30] != 0x0c {
		t.Errorf("expected compression pointer 0xc00c at 29, got %x%x", raw[29], raw[30])
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Question) != 2 || got.Question[1].Name.String() != "example.com" {
		t.Errorf("decoded questions = %+v", got.Question)
	}
}

// --- Decode error paths -----------------------------------------------------

func TestDecodeErrors(t *testing.T) {
	cases := map[string]string{
		"short header":     "1234",
		"truncated counts": "12340000",
		"bad name length":  "00000000000100000000000005aa", // qd=1, label len 5 but data short
	}
	for name, h := range cases {
		raw, _ := hex.DecodeString(h)
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: Decode succeeded, want error", name)
		}
	}
}

func TestDecodeForwardPointer(t *testing.T) {
	// qdcount=1, then a pointer to offset 12 (itself / non-backward) -> error.
	raw, _ := hex.DecodeString("000000000001000000000000c00c")
	if _, err := Decode(raw); err == nil {
		t.Error("forward/self pointer accepted")
	}
}

func TestDecodeRDataJunk(t *testing.T) {
	// Build an A record but claim RDLENGTH 5 with only 4 address bytes used:
	// decoder must report junk (index < limit). Hand-craft from a valid message.
	m := NewMessage(1)
	a, _ := CreateIPv4("1.2.3.4")
	m.AddAnswer(NewName("a"), 0, &A{Address: a})
	raw := m.Encode()
	// The RDLENGTH for the single A record is the 2 bytes right before the 4
	// address bytes (last 6 bytes are RDLENGTH(2)+addr(4)). Bump it to 5 and add
	// a trailing junk byte so the window holds 5 bytes but A consumes 4.
	raw[len(raw)-6] = 0
	raw[len(raw)-5] = 5
	raw = append(raw, 0xff)
	if _, err := Decode(raw); err == nil {
		t.Error("junk in RDATA window accepted")
	}
}

func TestDecodeRDataLimitExceeded(t *testing.T) {
	// RDLENGTH claims more bytes than the message holds.
	m := NewMessage(1)
	a, _ := CreateIPv4("1.2.3.4")
	m.AddAnswer(NewName("a"), 0, &A{Address: a})
	raw := m.Encode()
	raw[len(raw)-6] = 0xff
	raw[len(raw)-5] = 0xff
	if _, err := Decode(raw); err == nil {
		t.Error("over-long RDLENGTH accepted")
	}
}

func TestDecodeNameTooLong(t *testing.T) {
	// A name whose accumulated label data exceeds 255 octets must be rejected.
	var raw []byte
	raw = append(raw, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // header, qd=1
	for i := 0; i < 6; i++ {                              // 6 * 63 = 378 > 255
		raw = append(raw, 63)
		raw = append(raw, make([]byte, 63)...)
	}
	raw = append(raw, 0)
	if _, err := Decode(raw); err == nil {
		t.Error("over-long name accepted")
	}
}

func TestDecodeErrorString(t *testing.T) {
	e := &DecodeError{Msg: "boom"}
	if e.Error() != "boom" {
		t.Errorf("Error = %q", e.Error())
	}
}

// --- Hosts ------------------------------------------------------------------

const hostsContent = "127.0.0.1 localhost localhost.localdomain\n" +
	"192.168.1.10 host1 host1.local\n" +
	"::1 localhost6\n" +
	"# comment line\n" +
	"\n" +
	"  10.0.0.1 dup\n" + // leading whitespace exercised
	"10.0.0.2 dup # trailing comment\n"

func TestHostsParse(t *testing.T) {
	h := ParseHosts(hostsContent)

	if got, _ := h.GetAddress("localhost"); got != "127.0.0.1" {
		t.Errorf("GetAddress(localhost) = %q", got)
	}
	if got := h.GetAddresses("localhost"); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Errorf("GetAddresses(localhost) = %v", got)
	}
	if got, _ := h.GetName("127.0.0.1"); got != "localhost" {
		t.Errorf("GetName(127.0.0.1) = %q", got)
	}
	if got := h.GetNames("127.0.0.1"); !reflect.DeepEqual(got, []string{"localhost", "localhost.localdomain"}) {
		t.Errorf("GetNames(127.0.0.1) = %v", got)
	}
	// MRI reverses the per-name address list: last-seen first.
	if got := h.GetAddresses("dup"); !reflect.DeepEqual(got, []string{"10.0.0.2", "10.0.0.1"}) {
		t.Errorf("GetAddresses(dup) = %v", got)
	}
	if got, _ := h.GetAddress("host1.local"); got != "192.168.1.10" {
		t.Errorf("GetAddress(host1.local) = %q", got)
	}
}

func TestHostsMissing(t *testing.T) {
	h := ParseHosts(hostsContent)
	if _, err := h.GetAddress("nope"); err == nil {
		t.Error("GetAddress(nope) succeeded")
	}
	if _, err := h.GetName("9.9.9.9"); err == nil {
		t.Error("GetName(9.9.9.9) succeeded")
	}
	if got := h.GetAddresses("nope"); got != nil {
		t.Errorf("GetAddresses(nope) = %v", got)
	}
	if got := h.GetNames("9.9.9.9"); got != nil {
		t.Errorf("GetNames(9.9.9.9) = %v", got)
	}
}

func TestHostsWhitespaceOnly(t *testing.T) {
	h := ParseHosts("   \n\t\n")
	if got := h.GetAddresses("anything"); got != nil {
		t.Errorf("whitespace-only file produced entries: %v", got)
	}
}

func TestDefaultHostsFileName(t *testing.T) {
	if DefaultHostsFileName != "/etc/hosts" {
		t.Errorf("DefaultHostsFileName = %q", DefaultHostsFileName)
	}
}

// --- Per-record decoder error paths -----------------------------------------

// Each golden hex below is a single-answer message (owner name "a") produced by
// MRI 4.0.5. The RDLENGTH field lives at offset 23. setRDLen rewrites it (and
// trims trailing RDATA) so the inner decoder field-read overruns the narrowed
// window, exercising every decoder's mid-record error return.
const (
	msgA     = "0000000000000001000000000161000001000100000000000401020304"
	msgAAAA  = "000000000000000100000000016100001c000100000000001000000000000000000000000000000001"
	msgMX    = "000000000000000100000000016100000f0001000000000005000a016d00"
	msgTXT   = "00000000000000010000000001610000100001000000000003026869"
	msgHINFO = "000000000000000100000000016100000d00010000000000040163016f"
	msgSOA   = "0000000000000001000000000161000006000100000000001a016d000172000000000100000002000000030000000400000005"
	msgSRV   = "00000000000000010000000001610000210001000000000009000100020003017400"
	msgNS    = "00000000000000010000000001610000020001000000000003016e00"
)

const rdLenOffset = 23

func TestDecoderFieldErrors(t *testing.T) {
	// rdlen is chosen to fit before the field that should fail to read.
	cases := []struct {
		name  string
		msg   string
		rdlen int
	}{
		{"A short address", msgA, 2},
		{"AAAA short address", msgAAAA, 8},
		{"MX short preference", msgMX, 1},
		{"MX short exchange", msgMX, 2},
		{"TXT short string", msgTXT, 1},
		{"HINFO short cpu", msgHINFO, 0},
		{"HINFO short os", msgHINFO, 2},
		{"SOA short mname", msgSOA, 0},
		{"SOA short rname", msgSOA, 3},
		{"SOA short serial", msgSOA, 6},
		{"SRV short priority", msgSRV, 1},
		{"SRV short weight", msgSRV, 3},
		{"SRV short port", msgSRV, 5},
		{"SRV short target", msgSRV, 6},
		{"NS short name", msgNS, 0},
		{"A junk in window", msgA, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(c.msg)
			raw[rdLenOffset] = byte(c.rdlen >> 8)
			raw[rdLenOffset+1] = byte(c.rdlen)
			// Keep enough trailing bytes for "junk" cases (rdlen exceeds the real
			// RDATA) but trim for the truncation cases.
			end := rdLenOffset + 2 + c.rdlen
			if end > len(raw) {
				for len(raw) < end {
					raw = append(raw, 0)
				}
			} else {
				raw = raw[:end]
			}
			if _, err := Decode(raw); err == nil {
				t.Errorf("%s: Decode succeeded, want error", c.name)
			}
		})
	}
}

func TestDecodeOverlongRDLengthBeyondData(t *testing.T) {
	raw, _ := hex.DecodeString(msgA)
	raw[rdLenOffset] = 0xff
	raw[rdLenOffset+1] = 0xff
	if _, err := Decode(raw); err == nil {
		t.Error("RDLENGTH beyond message accepted")
	}
}

// TestDecodeAnswerNameError drives getRR's name-decode error and the
// authority/additional section error returns via a count that outruns the data.
func TestDecodeSectionCountOverrun(t *testing.T) {
	// Answer count = 1 but no answer bytes follow the header.
	answer, _ := hex.DecodeString("000000000001" + "0001" + "0000" + "0000")
	if _, err := Decode(answer); err == nil {
		t.Error("answer overrun accepted")
	}
	// Authority count = 1, none present.
	auth, _ := hex.DecodeString("0000" + "0000" + "0000" + "0001" + "0000")
	if _, err := Decode(auth); err == nil {
		t.Error("authority overrun accepted")
	}
	// Additional count = 1, none present.
	add, _ := hex.DecodeString("0000" + "0000" + "0000" + "0000" + "0001")
	if _, err := Decode(add); err == nil {
		t.Error("additional overrun accepted")
	}
}

// TestDecodeQuestionFieldErrors drives the question type/class read errors.
func TestDecodeQuestionFieldErrors(t *testing.T) {
	// qd=1, name "a" present, but TYPE truncated.
	noType, _ := hex.DecodeString("000000000001000000000000" + "0161" + "00")
	if _, err := Decode(noType); err == nil {
		t.Error("question without TYPE accepted")
	}
	// qd=1, name + TYPE present, CLASS truncated.
	noClass, _ := hex.DecodeString("000000000001000000000000" + "0161" + "00" + "0001")
	if _, err := Decode(noClass); err == nil {
		t.Error("question without CLASS accepted")
	}
}

// TestDecodeRRHeaderErrors drives getRR's TYPE/CLASS/TTL read errors.
func TestDecodeRRHeaderErrors(t *testing.T) {
	// an=1, name present, TYPE truncated.
	noType, _ := hex.DecodeString("000000000000" + "0001" + "00000000" + "0161" + "00")
	if _, err := Decode(noType); err == nil {
		t.Error("RR without TYPE accepted")
	}
	// an=1, name + TYPE, CLASS truncated.
	noClass, _ := hex.DecodeString("000000000000" + "0001" + "00000000" + "0161" + "00" + "0001")
	if _, err := Decode(noClass); err == nil {
		t.Error("RR without CLASS accepted")
	}
	// an=1, name + TYPE + CLASS, TTL truncated.
	noTTL, _ := hex.DecodeString("000000000000" + "0001" + "00000000" + "0161" + "00" + "0001" + "0001" + "0000")
	if _, err := Decode(noTTL); err == nil {
		t.Error("RR without TTL accepted")
	}
	// an=1, full header but RDLENGTH truncated.
	noRDLen, _ := hex.DecodeString("000000000000" + "0001" + "00000000" + "0161" + "00" + "0001" + "0001" + "00000000")
	if _, err := Decode(noRDLen); err == nil {
		t.Error("RR without RDLENGTH accepted")
	}
}

// TestNameEqualLabelMismatch covers Name.Equal's label-loop false branch.
func TestNameEqualLabelMismatch(t *testing.T) {
	if NewName("a.b").Equal(NewName("a.c")) {
		t.Error("a.b equal to a.c")
	}
}

// TestDecodeEmptyAndIDError covers the header-ID read failure on empty input.
func TestDecodeEmptyAndIDError(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Error("Decode(nil) succeeded")
	}
	if _, err := Decode([]byte{0x00}); err == nil {
		t.Error("Decode(1 byte) succeeded")
	}
}

// TestDecodeTruncatedPointer covers getLabels' pointer second-byte read error:
// a name ending on a lone 0xC0 byte.
func TestDecodeTruncatedPointer(t *testing.T) {
	// qd=1, then a single 0xC0 byte (high two bits set) with no low byte.
	raw, _ := hex.DecodeString("000000000001000000000000" + "c0")
	if _, err := Decode(raw); err == nil {
		t.Error("truncated compression pointer accepted")
	}
}

// TestDecodeAnswerNameError covers getRR's owner-name read error: an=1 but the
// answer section is empty, so getName overruns at the section start.
func TestDecodeAnswerNameError(t *testing.T) {
	raw, _ := hex.DecodeString("000000000000" + "0001" + "0000" + "0000")
	if _, err := Decode(raw); err == nil {
		t.Error("answer with no name accepted")
	}
}
