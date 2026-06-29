// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// IPv4 is a pure-compute port of Ruby's Resolv::IPv4: it parses and renders a
// dotted-quad address and holds the canonical 4-byte form (Resolv::IPv4#address).
type IPv4 struct {
	// Addr is the raw 4-byte address (Ruby's @address String).
	Addr [4]byte
}

// IPv4Regex matches the textual forms Ruby's Resolv::IPv4::Regex accepts: a
// dotted quad of four octets, each 0..255 with no leading zeros (anchored).
// It mirrors MRI's Regex256 alternation exactly.
var IPv4Regex = regexp.MustCompile(
	`\A(` + regex256 + `)\.(` + regex256 + `)\.(` + regex256 + `)\.(` + regex256 + `)\z`)

const regex256 = `0|1(?:[0-9][0-9]?)?|2(?:[0-4][0-9]?|5[0-5]?|[6-9])?|[3-9][0-9]?`

// CreateIPv4 builds an IPv4 from a dotted-quad string, matching
// Resolv::IPv4.create. It returns an error (Ruby raises ArgumentError) when the
// text does not match IPv4Regex or an octet is out of range.
func CreateIPv4(s string) (IPv4, error) {
	m := IPv4Regex.FindStringSubmatch(s)
	if m == nil {
		return IPv4{}, fmt.Errorf("cannot interpret as IPv4 address: %q", s)
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		// IPv4Regex's Regex256 already constrains each octet to 0..255, so Atoi
		// always succeeds and fits in a byte.
		n, _ := strconv.Atoi(m[i+1])
		b[i] = byte(n)
	}
	return IPv4{Addr: b}, nil
}

// NewIPv4 wraps a raw 4-byte address (Resolv::IPv4.new from wire bytes).
func NewIPv4(b []byte) (IPv4, error) {
	if len(b) != 4 {
		return IPv4{}, fmt.Errorf("IPv4 address expects 4 bytes but %d bytes", len(b))
	}
	var a [4]byte
	copy(a[:], b)
	return IPv4{Addr: a}, nil
}

// String renders the dotted-quad form (Resolv::IPv4#to_s).
func (ip IPv4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip.Addr[0], ip.Addr[1], ip.Addr[2], ip.Addr[3])
}

// Inspect renders Resolv::IPv4#inspect.
func (ip IPv4) Inspect() string { return "#<Resolv::IPv4 " + ip.String() + ">" }

// Equal reports address equality (Resolv::IPv4#==).
func (ip IPv4) Equal(o IPv4) bool { return ip.Addr == o.Addr }

// ToName turns the address into its in-addr.arpa reverse Name
// (Resolv::IPv4#to_name).
func (ip IPv4) ToName() Name {
	s := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip.Addr[3], ip.Addr[2], ip.Addr[1], ip.Addr[0])
	return NewName(s)
}

// IPv6 is a pure-compute port of Ruby's Resolv::IPv6: it parses the textual IPv6
// forms and holds the canonical 16-byte form (Resolv::IPv6#address).
//
// MRI's Resolv::IPv6.create only consults the 8Hex, CompressedHex, 6Hex4Dec and
// CompressedHex4Dec forms — never the link-local %zone forms — so CreateIPv6
// rejects a %zone string exactly as MRI does, even though IPv6Regex (the
// Resolv::IPv6::Regex constant, used by match?) accepts it.
type IPv6 struct {
	// Addr is the raw 16-byte address (Ruby's @address String).
	Addr [16]byte
}

// The component IPv6 regexps, mirroring MRI's Resolv::IPv6::Regex_* constants.
var (
	regex8Hex          = `(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}`
	regexCompressedHex = `((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::` +
		`((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)`
	regex6Hex4Dec = `((?:[0-9A-Fa-f]{1,4}:){6,6})` +
		`(\d+)\.(\d+)\.(\d+)\.(\d+)`
	regexCompressedHex4Dec = `((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::` +
		`((?:[0-9A-Fa-f]{1,4}:)*)` +
		`(\d+)\.(\d+)\.(\d+)\.(\d+)`
	regex8HexLinkLocal          = `[Ff][Ee]80(?::[0-9A-Fa-f]{1,4}){7}%[-0-9A-Za-z._~]+`
	regexCompressedHexLinkLocal = `[Ff][Ee]80:(?:` +
		`((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::` +
		`((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)` +
		`|:((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)` +
		`)?:[0-9A-Fa-f]{1,4}%[-0-9A-Za-z._~]+`

	re8Hex          = regexp.MustCompile(`\A` + regex8Hex + `\z`)
	reCompressedHex = regexp.MustCompile(`\A` + regexCompressedHex + `\z`)
	re6Hex4Dec      = regexp.MustCompile(`\A` + regex6Hex4Dec + `\z`)
	reCompHex4Dec   = regexp.MustCompile(`\A` + regexCompressedHex4Dec + `\z`)

	// IPv6Regex is the composite matcher (Resolv::IPv6::Regex): a textual IPv6
	// address in any of its accepted forms. Each alternative is fully anchored,
	// so this matches exactly the strings CreateIPv6 accepts.
	IPv6Regex = regexp.MustCompile(
		`(?:\A` + regex8Hex + `\z)` +
			`|(?:\A` + regexCompressedHex + `\z)` +
			`|(?:\A` + regex6Hex4Dec + `\z)` +
			`|(?:\A` + regexCompressedHex4Dec + `\z)` +
			`|(?:\A` + regex8HexLinkLocal + `\z)` +
			`|(?:\A` + regexCompressedHexLinkLocal + `\z)`)

	reHexGroup = regexp.MustCompile(`[0-9A-Fa-f]+`)
)

// CreateIPv6 builds an IPv6 from a textual address, matching Resolv::IPv6.create.
// It returns an error (Ruby raises ArgumentError) for input matching none of the
// accepted forms or with an out-of-range embedded IPv4 octet.
func CreateIPv6(s string) (IPv6, error) {
	var addr [16]byte
	switch {
	case re8Hex.MatchString(s):
		copy(addr[:], packGroups(s))
	case reCompressedHex.MatchString(s):
		m := reCompressedHex.FindStringSubmatch(s)
		a1 := packGroups(m[1])
		a2 := packGroups(m[2])
		copy(addr[:], a1)
		copy(addr[16-len(a2):], a2)
	case re6Hex4Dec.MatchString(s):
		m := re6Hex4Dec.FindStringSubmatch(s)
		a, b, c, d, ok := parse4Dec(m[2], m[3], m[4], m[5])
		if !ok {
			return IPv6{}, fmt.Errorf("not numeric IPv6 address: %s", s)
		}
		copy(addr[:], packGroups(m[1]))
		addr[12], addr[13], addr[14], addr[15] = a, b, c, d
	case reCompHex4Dec.MatchString(s):
		m := reCompHex4Dec.FindStringSubmatch(s)
		a, b, c, d, ok := parse4Dec(m[3], m[4], m[5], m[6])
		if !ok {
			return IPv6{}, fmt.Errorf("not numeric IPv6 address: %s", s)
		}
		a1 := packGroups(m[1])
		a2 := packGroups(m[2])
		copy(addr[:], a1)
		copy(addr[12-len(a2):12], a2)
		addr[12], addr[13], addr[14], addr[15] = a, b, c, d
	default:
		return IPv6{}, fmt.Errorf("not numeric IPv6 address: %s", s)
	}
	return IPv6{Addr: addr}, nil
}

// packGroups packs colon-separated hex groups into bytes (network order).
func packGroups(s string) []byte {
	if s == "" {
		return nil
	}
	groups := reHexGroup.FindAllString(s, -1)
	out := make([]byte, 0, len(groups)*2)
	for _, g := range groups {
		v, _ := strconv.ParseUint(g, 16, 32)
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

// parse4Dec parses four decimal octet strings, reporting whether each is 0..255.
func parse4Dec(sa, sb, sc, sd string) (a, b, c, d byte, ok bool) {
	na, _ := strconv.Atoi(sa)
	nb, _ := strconv.Atoi(sb)
	nc, _ := strconv.Atoi(sc)
	nd, _ := strconv.Atoi(sd)
	if na > 255 || nb > 255 || nc > 255 || nd > 255 {
		return 0, 0, 0, 0, false
	}
	return byte(na), byte(nb), byte(nc), byte(nd), true
}

// NewIPv6 wraps a raw 16-byte address (Resolv::IPv6.new from wire bytes).
func NewIPv6(b []byte) (IPv6, error) {
	if len(b) != 16 {
		return IPv6{}, fmt.Errorf("IPv6 address must be 16 bytes")
	}
	var a [16]byte
	copy(a[:], b)
	return IPv6{Addr: a}, nil
}

// reZeroRun matches MRI's compression substitution target: the first run of one
// or more all-zero groups of length >= 2 (sub(/(^|:)0(:0)+(:|$)/, '::')).
var reZeroRun = regexp.MustCompile(`(^|:)0(:0)+(:|$)`)

// String renders the canonical textual form (Resolv::IPv6#to_s): the eight
// groups in lowercase hex with no leading zeros, then MRI's first-run zero
// compression. A zone suffix is appended verbatim.
func (ip IPv6) String() string {
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		v := uint16(ip.Addr[i*2])<<8 | uint16(ip.Addr[i*2+1])
		groups[i] = strconv.FormatUint(uint64(v), 16)
	}
	s := strings.Join(groups, ":")
	// MRI uses String#sub, which replaces only the FIRST match; Go's
	// ReplaceAllString would collapse every zero run, so substitute once by hand.
	if loc := reZeroRun.FindStringIndex(s); loc != nil {
		s = s[:loc[0]] + "::" + s[loc[1]:]
	}
	return s
}

// Inspect renders Resolv::IPv6#inspect.
func (ip IPv6) Inspect() string { return "#<Resolv::IPv6 " + ip.String() + ">" }

// Equal reports address equality (Resolv::IPv6#==).
func (ip IPv6) Equal(o IPv6) bool { return ip.Addr == o.Addr }
