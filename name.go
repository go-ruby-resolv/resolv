// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import "strings"

// Label is a single DNS label (Ruby's Resolv::DNS::Label::Str). It preserves the
// original byte string while comparing case-insensitively over ASCII, per RFC
// 4343, exactly as MRI does (@downcase = string.b.downcase).
type Label struct {
	// Str is the label's bytes as supplied (Resolv::DNS::Label::Str#string).
	Str string
}

// downcase returns the ASCII-lowercased comparison key (MRI's @downcase).
func (l Label) downcase() string { return asciiDowncase(l.Str) }

// String renders the label verbatim (Resolv::DNS::Label::Str#to_s).
func (l Label) String() string { return l.Str }

// Equal reports case-insensitive (ASCII) label equality (Label::Str#==).
func (l Label) Equal(o Label) bool { return l.downcase() == o.downcase() }

// asciiDowncase lowercases ASCII A-Z only, leaving other bytes untouched, to
// match Ruby's String#downcase on a binary string.
func asciiDowncase(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// Name is a pure-compute port of Ruby's Resolv::DNS::Name: an ordered list of
// labels plus an absolute flag (trailing dot). It carries no wire bytes; wire
// encoding/decoding (with 0xC0 compression) lives on the Message coder.
type Name struct {
	// Labels are the dot-separated components, most-significant first.
	Labels []Label
	// Absolute reports whether the source had a trailing dot.
	Absolute bool
}

// NewName builds a Name from a dotted string (Resolv::DNS::Name.create). The
// labels are the maximal non-dot runs (MRI's Label.split, /[^\.]+/), and the
// name is absolute iff the string ends in a dot.
func NewName(s string) Name {
	var labels []Label
	for _, part := range strings.Split(s, ".") {
		if part != "" {
			labels = append(labels, Label{Str: part})
		}
	}
	return Name{Labels: labels, Absolute: strings.HasSuffix(s, ".")}
}

// NewNameLabels builds a Name directly from labels and an absolute flag, as the
// wire decoder does (Resolv::DNS::Name.new defaults absolute=true).
func NewNameLabels(labels []Label, absolute bool) Name {
	return Name{Labels: labels, Absolute: absolute}
}

// String renders the dotted name without a trailing dot, even when absolute
// (Resolv::DNS::Name#to_s).
func (n Name) String() string {
	parts := make([]string, len(n.Labels))
	for i, l := range n.Labels {
		parts[i] = l.Str
	}
	return strings.Join(parts, ".")
}

// Inspect renders Resolv::DNS::Name#inspect, appending a dot when absolute.
func (n Name) Inspect() string {
	dot := ""
	if n.Absolute {
		dot = "."
	}
	return "#<Resolv::DNS::Name: " + n.String() + dot + ">"
}

// Length returns the label count (Resolv::DNS::Name#length).
func (n Name) Length() int { return len(n.Labels) }

// Equal reports name equality (Resolv::DNS::Name#==): same absolute flag and
// case-insensitively equal labels.
func (n Name) Equal(o Name) bool {
	if n.Absolute != o.Absolute || len(n.Labels) != len(o.Labels) {
		return false
	}
	for i := range n.Labels {
		if !n.Labels[i].Equal(o.Labels[i]) {
			return false
		}
	}
	return true
}

// SubdomainOf reports whether n is a strict subdomain of other
// (Resolv::DNS::Name#subdomain_of?): same absolute flag, strictly more labels,
// and a matching suffix.
func (n Name) SubdomainOf(other Name) bool {
	if n.Absolute != other.Absolute {
		return false
	}
	ol := len(other.Labels)
	if len(n.Labels) <= ol {
		return false
	}
	tail := n.Labels[len(n.Labels)-ol:]
	for i := range tail {
		if !tail[i].Equal(other.Labels[i]) {
			return false
		}
	}
	return true
}
