// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultHostsFileName is Resolv::Hosts::DefaultFileName on a POSIX system.
const DefaultHostsFileName = "/etc/hosts"

// Hosts is a pure-compute port of Ruby's Resolv::Hosts: a parsed /etc/hosts
// table mapping names to addresses and back. It performs no file I/O — the host
// supplies the file content as a string (ParseHosts) — but reproduces MRI's
// parsing and lookup semantics, including the reversed address order per name.
type Hosts struct {
	name2addr map[string][]string
	addr2name map[string][]string
}

// reWS matches MRI's whitespace splitter (line.split(/\s+/)).
var reWS = regexp.MustCompile(`\s+`)

// reComment matches MRI's comment stripper (line.sub!(/#.*/, ”)).
var reComment = regexp.MustCompile(`#.*`)

// ParseHosts parses /etc/hosts-format text into a Hosts table, replicating MRI's
// Resolv::Hosts#lazy_initialize: each line has its comment stripped and is split
// on whitespace into an address and its hostnames; the per-name address lists
// are reversed (so the last-seen address for a name is returned first).
func ParseHosts(content string) *Hosts {
	h := &Hosts{name2addr: map[string][]string{}, addr2name: map[string][]string{}}
	for _, line := range strings.Split(content, "\n") {
		line = reComment.ReplaceAllString(line, "")
		fields := splitWS(line)
		if len(fields) == 0 {
			continue
		}
		addr, hostnames := fields[0], fields[1:]
		h.addr2name[addr] = append(h.addr2name[addr], hostnames...)
		for _, hostname := range hostnames {
			h.name2addr[hostname] = append(h.name2addr[hostname], addr)
		}
	}
	for name, arr := range h.name2addr {
		reverse(arr)
		h.name2addr[name] = arr
	}
	return h
}

// splitWS reproduces Ruby's String#split(/\s+/): a leading whitespace run yields
// an empty leading field, which MRI then discards via `next unless addr`. Here we
// mirror that by dropping a leading empty field so the address is the first real
// token.
func splitWS(s string) []string {
	if s == "" {
		return nil
	}
	parts := reWS.Split(s, -1)
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	// A line that was only whitespace (or empty after comment strip) yields a
	// single trailing empty field; treat it as no fields.
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func reverse(a []string) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// GetAddress returns the first address for name (Resolv::Hosts#getaddress),
// reporting an error when the name is absent.
func (h *Hosts) GetAddress(name string) (string, error) {
	if addrs := h.name2addr[name]; len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no name: %s", name)
}

// GetAddresses returns all addresses for name (Resolv::Hosts#getaddresses).
func (h *Hosts) GetAddresses(name string) []string {
	return append([]string(nil), h.name2addr[name]...)
}

// GetName returns the first hostname for address (Resolv::Hosts#getname),
// reporting an error when the address is absent.
func (h *Hosts) GetName(address string) (string, error) {
	if names := h.addr2name[address]; len(names) > 0 {
		return names[0], nil
	}
	return "", fmt.Errorf("no address: %s", address)
}

// GetNames returns all hostnames for address (Resolv::Hosts#getnames).
func (h *Hosts) GetNames(address string) []string {
	return append([]string(nil), h.addr2name[address]...)
}
