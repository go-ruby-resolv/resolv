// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import (
	"encoding/base64"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// rubyOracle runs a Resolv script under the system ruby and returns its stdout.
// It skips the test on Windows (the oracle frames binary DNS data, and the
// ruby-free deterministic suite already holds coverage at 100%) and wherever
// ruby is absent or older than 4.0. Binary message bytes are base64-framed so
// stdout text-mode never corrupts them; the script forces $stdout/$stdin to
// binary as a belt-and-braces guard.
func rubyOracle(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("oracle skipped on Windows (binary DNS data is base64-framed; deterministic tests hold 100%)")
	}
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not found; skipping MRI oracle")
	}
	const guard = `
$stdout.binmode
$stdin.binmode
abort("ruby too old") unless RUBY_VERSION >= "4.0"
require "resolv"
require "base64"
def frame(bytes); puts Base64.strict_encode64(bytes); end
`
	out, err := exec.Command("ruby", "-e", guard+script).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && strings.Contains(string(ee.Stderr), "ruby too old") {
			t.Skip("ruby older than 4.0; skipping MRI oracle")
		}
		t.Fatalf("ruby oracle failed: %v", err)
	}
	return strings.TrimRight(string(out), "\n")
}

func decodeFrame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}

// TestOracleQuestionMessage checks our question-message encoding byte-for-byte
// against MRI's Resolv::DNS::Message#encode.
func TestOracleQuestionMessage(t *testing.T) {
	want := decodeFrame(t, rubyOracle(t, `
m = Resolv::DNS::Message.new(0x1234)
m.add_question(Resolv::DNS::Name.create("www.example.com"), Resolv::DNS::Resource::IN::A)
frame(m.encode)
`))
	m := NewMessage(0x1234)
	m.AddQuestion(NewName("www.example.com"), TypeA, ClassIN)
	if got := m.Encode(); string(got) != string(want) {
		t.Errorf("question encode mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestOracleFullMessage checks the full 10-answer response encoding against MRI.
func TestOracleFullMessage(t *testing.T) {
	want := decodeFrame(t, rubyOracle(t, `
m = Resolv::DNS::Message.new(0xabcd)
m.qr = 1; m.aa = 1; m.rd = 1; m.ra = 1
m.add_question(Resolv::DNS::Name.create("example.com"), Resolv::DNS::Resource::IN::A)
m.add_answer(Resolv::DNS::Name.create("example.com"), 3600, Resolv::DNS::Resource::IN::A.new("93.184.216.34"))
m.add_answer(Resolv::DNS::Name.create("example.com"), 3600, Resolv::DNS::Resource::IN::AAAA.new("2606:2800:220:1:248:1893:25c8:1946"))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mail.example.com")))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::TXT.new("hello", "world"))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create("alias.example.com")))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("ns1.example.com")))
m.add_answer(Resolv::DNS::Name.create("4.3.2.1.in-addr.arpa"), 100, Resolv::DNS::Resource::IN::PTR.new(Resolv::DNS::Name.create("host.example.com")))
m.add_answer(Resolv::DNS::Name.create("_sip._tcp.example.com"), 100, Resolv::DNS::Resource::IN::SRV.new(10, 20, 5060, Resolv::DNS::Name.create("sipserver.example.com")))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::SOA.new(Resolv::DNS::Name.create("ns1.example.com"), Resolv::DNS::Name.create("admin.example.com"), 2024010101, 7200, 3600, 1209600, 3600))
m.add_answer(Resolv::DNS::Name.create("example.com"), 100, Resolv::DNS::Resource::IN::HINFO.new("Intel", "Linux"))
frame(m.encode)
`))
	if got := buildFullMessage().Encode(); string(got) != string(want) {
		t.Errorf("full encode mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestOracleDecodeReencode decodes the MRI-encoded full message and re-encodes
// it, requiring the bytes to match MRI exactly (round-trip through our coder).
func TestOracleDecodeReencode(t *testing.T) {
	want := decodeFrame(t, rubyOracle(t, `
m = Resolv::DNS::Message.new(0x4321)
m.add_answer(Resolv::DNS::Name.create("a.b.example.com"), 300, Resolv::DNS::Resource::IN::A.new("10.20.30.40"))
m.add_answer(Resolv::DNS::Name.create("c.b.example.com"), 300, Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create("a.b.example.com")))
frame(m.encode)
`))
	m, err := Decode(want)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := m.Encode(); string(got) != string(want) {
		t.Errorf("decode/re-encode mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestOracleIPv4 checks IPv4 parse + render against MRI.
func TestOracleIPv4(t *testing.T) {
	for _, s := range []string{"1.2.3.4", "0.0.0.0", "255.255.255.255", "192.168.1.1"} {
		want := rubyOracle(t, `puts Resolv::IPv4.create(`+quote(s)+`).to_s`)
		ip, err := CreateIPv4(s)
		if err != nil {
			t.Fatalf("CreateIPv4(%q): %v", s, err)
		}
		if ip.String() != want {
			t.Errorf("IPv4(%q) = %q, want %q", s, ip.String(), want)
		}
	}
}

// TestOracleIPv6 checks IPv6 parse + compression against MRI.
func TestOracleIPv6(t *testing.T) {
	cases := []string{
		"2606:2800:220:1:248:1893:25c8:1946",
		"2001:db8:0:0:0:0:0:1",
		"::1", "0:0:0:0:0:0:0:0",
		"2001:0:0:1:0:0:0:1", "1:0:0:0:1:0:0:0",
		"::ffff:192.168.1.1", "::13.1.68.3",
	}
	for _, s := range cases {
		want := rubyOracle(t, `puts Resolv::IPv6.create(`+quote(s)+`).to_s`)
		ip, err := CreateIPv6(s)
		if err != nil {
			t.Fatalf("CreateIPv6(%q): %v", s, err)
		}
		if ip.String() != want {
			t.Errorf("IPv6(%q) = %q, want %q", s, ip.String(), want)
		}
	}
}

// TestOracleNameWire checks that our name wire encoding (with compression)
// matches MRI for a multi-name message.
func TestOracleNameWire(t *testing.T) {
	want := decodeFrame(t, rubyOracle(t, `
m = Resolv::DNS::Message.new(0)
m.add_question(Resolv::DNS::Name.create("WWW.Example.COM"), Resolv::DNS::Resource::IN::A)
m.add_question(Resolv::DNS::Name.create("ftp.example.com"), Resolv::DNS::Resource::IN::A)
frame(m.encode)
`))
	m := NewMessage(0)
	m.AddQuestion(NewName("WWW.Example.COM"), TypeA, ClassIN)
	m.AddQuestion(NewName("ftp.example.com"), TypeA, ClassIN)
	if got := m.Encode(); string(got) != string(want) {
		t.Errorf("name wire mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestOracleHosts checks Hosts parsing/lookups against MRI's Resolv::Hosts over
// the same content (MRI reads a temp file; we take the string directly).
func TestOracleHosts(t *testing.T) {
	const content = "127.0.0.1 localhost localhost.localdomain\n" +
		"192.168.1.10 host1 host1.local\n" +
		"::1 localhost6\n" +
		"# comment\n\n" +
		"10.0.0.1 dup\n10.0.0.2 dup\n"
	out := rubyOracle(t, `
require "tempfile"
content = `+quote(content)+`
Tempfile.create("hosts") do |f|
  f.write(content); f.flush
  h = Resolv::Hosts.new(f.path)
  puts h.getaddress("localhost")
  puts h.getname("127.0.0.1")
  puts h.getnames("127.0.0.1").join(",")
  puts h.getaddresses("dup").join(",")
end
`)
	lines := strings.Split(out, "\n")
	h := ParseHosts(content)
	if got, _ := h.GetAddress("localhost"); got != lines[0] {
		t.Errorf("getaddress = %q, want %q", got, lines[0])
	}
	if got, _ := h.GetName("127.0.0.1"); got != lines[1] {
		t.Errorf("getname = %q, want %q", got, lines[1])
	}
	if got := strings.Join(h.GetNames("127.0.0.1"), ","); got != lines[2] {
		t.Errorf("getnames = %q, want %q", got, lines[2])
	}
	if got := strings.Join(h.GetAddresses("dup"), ","); got != lines[3] {
		t.Errorf("getaddresses(dup) = %q, want %q", got, lines[3])
	}
}

// quote renders a Go string as a Ruby double-quoted literal for the oracle
// scripts. Only the characters appearing in our test corpus need escaping.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "#", `\#`)
	return `"` + r.Replace(s) + `"`
}
