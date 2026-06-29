<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-resolv/brand/main/social/go-ruby-resolv-resolv.png" alt="go-ruby-resolv/resolv" width="720"></p>

# resolv — go-ruby-resolv

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-resolv.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the deterministic, pure-compute core of
Ruby's [`Resolv`](https://docs.ruby-lang.org/en/master/Resolv.html) library** — the
DNS wire format, domain names, resource records, address parsing, and `/etc/hosts`
parsing of MRI 4.0.5, **without any Ruby runtime**.

It encodes and decodes DNS messages byte-for-byte like
`Resolv::DNS::Message#encode` / `Resolv::DNS::Message.decode`, parses and renders
`Resolv::IPv4` / `Resolv::IPv6` addresses (with MRI's exact `::` compression),
builds `Resolv::DNS::Name`s with length-prefixed labels and `0xC0` compression
pointers, and reproduces `Resolv::Hosts`'s name↔address tables.

It is the DNS-primitive backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module with no dependency on the Ruby runtime — a sibling
of [go-ruby-regexp](https://github.com/go-ruby-regexp/regexp) (the Onigmo engine)
and [go-ruby-marshal](https://github.com/go-ruby-marshal/marshal).

> **What it is — and isn't.** The message/name/record encode-decode, the address
> grammar, and the hosts-file parse are fully deterministic and need **no
> interpreter**, so they live here as pure Go. The actual *resolution* — querying
> a server over UDP/TCP — is the host's job (rbgo wires sockets to these
> primitives); this library does **no networking and no file I/O**. `Resolv::Hosts`
> takes the file *content* as a string, and `Resolv.getaddress` (which hits the
> network) is out of scope.

## Features

Faithful port of Resolv's pure-compute surface, validated against the `ruby`
binary on every supported platform:

- **`Resolv::DNS::Message`** — full header (ID, QR/Opcode/AA/TC/RD/RA/RCODE), the
  question section, and the answer / authority / additional record sections.
  `Encode` and `Decode` round-trip byte-for-byte, including the truncation-bit
  short-circuit MRI applies on decode.
- **`Resolv::DNS::Name`** — dotted-name parse/print, the absolute (trailing-dot)
  flag, case-insensitive `Equal` and `SubdomainOf`, and wire encoding with
  RFC 1035 length-prefixed labels and case-insensitive `0xC0` **compression
  pointers** (with backward-pointer and 255-octet guards on decode).
- **Resource records** — `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `MX`, `TXT`, `SOA`,
  `SRV` (target encoded uncompressed, per MRI), `HINFO`, plus a `Generic`
  fallback that round-trips any other TYPE/CLASS opaquely.
- **`Resolv::IPv4` / `Resolv::IPv6`** — `Create` parse with the exact MRI
  `Regex`/`Regex256` acceptance set, canonical `String` rendering (IPv6 uses
  MRI's first-run `::` compression), the raw `Addr` bytes, `Equal`, and the
  exported `IPv4Regex` / `IPv6Regex` constants.
- **`Resolv::Hosts`** — parse `/etc/hosts`-format text into name↔address maps and
  query them with `GetAddress` / `GetAddresses` / `GetName` / `GetNames`,
  reproducing MRI's comment stripping, whitespace split, and reversed per-name
  address ordering.

CGO-free, dependency-free, **100% test coverage**, `gofmt` + `go vet` clean, and
green across the six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le,
s390x) and three OSes (Linux, macOS, Windows).

## Install

```sh
go get github.com/go-ruby-resolv/resolv
```

## Usage

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/go-ruby-resolv/resolv"
)

func main() {
	// Build and encode a DNS query (Resolv::DNS::Message#encode).
	m := resolv.NewMessage(0x1234)
	m.AddQuestion(resolv.NewName("www.example.com"), resolv.TypeA, resolv.ClassIN)
	fmt.Println(hex.EncodeToString(m.Encode()))
	// 12340000000100000000000003777777076578616d706c6503636f6d0000010001

	// Decode a response and read its records (Resolv::DNS::Message.decode).
	resp, _ := resolv.Decode(m.Encode())
	fmt.Println(resp.Question[0].Name) // www.example.com

	// Parse addresses (Resolv::IPv4 / Resolv::IPv6).
	ip, _ := resolv.CreateIPv6("2001:db8:0:0:0:0:0:1")
	fmt.Println(ip)               // 2001:db8::1

	// Parse a hosts table (Resolv::Hosts).
	h := resolv.ParseHosts("127.0.0.1 localhost\n")
	addr, _ := h.GetAddress("localhost")
	fmt.Println(addr)             // 127.0.0.1
}
```

## API

```go
// Messages
func NewMessage(id uint16) *Message
func (m *Message) AddQuestion(name Name, typ, class uint16)
func (m *Message) AddAnswer(name Name, ttl uint32, data Resource)
func (m *Message) AddAuthority(name Name, ttl uint32, data Resource)
func (m *Message) AddAdditional(name Name, ttl uint32, data Resource)
func (m *Message) Encode() []byte
func Decode(m []byte) (*Message, error)

// Names
func NewName(s string) Name
func (n Name) String() string
func (n Name) Equal(o Name) bool
func (n Name) SubdomainOf(other Name) bool

// Addresses
func CreateIPv4(s string) (IPv4, error)
func CreateIPv6(s string) (IPv6, error)
var IPv4Regex, IPv6Regex *regexp.Regexp

// Records: A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, HINFO, Generic

// Hosts
func ParseHosts(content string) *Hosts
func (h *Hosts) GetAddress(name string) (string, error)
func (h *Hosts) GetName(address string) (string, error)
```

## Tests & coverage

The suite pairs deterministic, ruby-free tests (which alone hold coverage at
100%, so the qemu cross-arch and Windows lanes pass the gate) with a
**differential MRI oracle**: messages, names, addresses, and hosts tables are
built here and compared byte-for-byte against the system `ruby`
(`Resolv::DNS::Message#encode`, `Resolv::IPv4/IPv6.create`, `Resolv::Hosts`). The
oracle `$stdout.binmode`s and **base64-frames** the binary DNS bytes so Windows
text-mode never pollutes them, gates on `RUBY_VERSION >= "4.0"`, and skips itself
where `ruby` is absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-resolv/resolv authors.
