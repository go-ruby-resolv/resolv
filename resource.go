// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

// ClassIN is the DNS IN class value (Resolv::DNS::Resource::IN::ClassValue == 1).
const ClassIN = 1

// DNS resource record TYPE values, matching MRI's Resolv::DNS::Resource TypeValue
// constants.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypeWKS   = 11
	TypePTR   = 12
	TypeHINFO = 13
	TypeMINFO = 14
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
)

// Resource is the wire-level interface every record implements: it knows its
// TYPE/CLASS and how to encode/decode its RDATA. The encoder writes the owner
// name, type, class, TTL and a 16-bit length around EncodeRData; the decoder
// reads them and calls DecodeRData within the length window.
type Resource interface {
	// TypeValue is the record's DNS TYPE (Resolv::DNS::Resource::TypeValue).
	TypeValue() uint16
	// ClassValue is the record's DNS CLASS (Resolv::DNS::Resource::ClassValue).
	ClassValue() uint16
	// EncodeRData writes the record's RDATA to the encoder.
	EncodeRData(e *MessageEncoder)
}

// rdataDecoder decodes a record's RDATA from a decoder positioned at the RDATA
// (within its length window).
type rdataDecoder func(d *MessageDecoder) (Resource, error)

// rdataDecoders maps (type<<16 | class) to the matching RDATA decoder. Unknown
// (type, class) pairs fall back to Generic, exactly like MRI's
// Resource.get_class returning a Generic subclass.
var rdataDecoders = map[uint32]rdataDecoder{
	key(TypeA, ClassIN):     decodeA,
	key(TypeAAAA, ClassIN):  decodeAAAA,
	key(TypeNS, ClassIN):    decodeDomainName(TypeNS, makeNS),
	key(TypeCNAME, ClassIN): decodeDomainName(TypeCNAME, makeCNAME),
	key(TypePTR, ClassIN):   decodeDomainName(TypePTR, makePTR),
	key(TypeMX, ClassIN):    decodeMX,
	key(TypeTXT, ClassIN):   decodeTXT,
	key(TypeSOA, ClassIN):   decodeSOA,
	key(TypeSRV, ClassIN):   decodeSRV,
	key(TypeHINFO, ClassIN): decodeHINFO,
}

func key(t, c uint16) uint32 { return uint32(t)<<16 | uint32(c) }

// A is Resolv::DNS::Resource::IN::A — an IPv4 address record.
type A struct {
	Address IPv4
	TTL     uint32
}

func (A) TypeValue() uint16               { return TypeA }
func (A) ClassValue() uint16              { return ClassIN }
func (a A) EncodeRData(e *MessageEncoder) { e.putBytes(a.Address.Addr[:]) }

func decodeA(d *MessageDecoder) (Resource, error) {
	b, err := d.getBytes(4)
	if err != nil {
		return nil, err
	}
	ip, _ := NewIPv4(b)
	return &A{Address: ip}, nil
}

// AAAA is Resolv::DNS::Resource::IN::AAAA — an IPv6 address record.
type AAAA struct {
	Address IPv6
	TTL     uint32
}

func (AAAA) TypeValue() uint16               { return TypeAAAA }
func (AAAA) ClassValue() uint16              { return ClassIN }
func (a AAAA) EncodeRData(e *MessageEncoder) { e.putBytes(a.Address.Addr[:]) }

func decodeAAAA(d *MessageDecoder) (Resource, error) {
	b, err := d.getBytes(16)
	if err != nil {
		return nil, err
	}
	ip, _ := NewIPv6(b)
	return &AAAA{Address: ip}, nil
}

// DomainName is the shared body of the single-Name records (NS, CNAME, PTR).
// Each concrete type carries its own TYPE so equality and dispatch stay precise.
type DomainName struct {
	Name Name
	TTL  uint32
	typ  uint16
}

func (n DomainName) TypeValue() uint16 { return n.typ }
func (DomainName) ClassValue() uint16  { return ClassIN }
func (n DomainName) EncodeRData(e *MessageEncoder) {
	e.putName(n.Name, true)
}

// NS is Resolv::DNS::Resource::IN::NS — an authoritative name server.
type NS struct{ DomainName }

// CNAME is Resolv::DNS::Resource::IN::CNAME — the canonical name for an alias.
type CNAME struct{ DomainName }

// PTR is Resolv::DNS::Resource::IN::PTR — a pointer to another name.
type PTR struct{ DomainName }

func makeNS(n Name) Resource    { return &NS{DomainName{Name: n, typ: TypeNS}} }
func makeCNAME(n Name) Resource { return &CNAME{DomainName{Name: n, typ: TypeCNAME}} }
func makePTR(n Name) Resource   { return &PTR{DomainName{Name: n, typ: TypePTR}} }

// NewNS, NewCNAME and NewPTR build the single-Name records.
func NewNS(n Name) *NS       { return &NS{DomainName{Name: n, typ: TypeNS}} }
func NewCNAME(n Name) *CNAME { return &CNAME{DomainName{Name: n, typ: TypeCNAME}} }
func NewPTR(n Name) *PTR     { return &PTR{DomainName{Name: n, typ: TypePTR}} }

func decodeDomainName(typ uint16, make func(Name) Resource) rdataDecoder {
	return func(d *MessageDecoder) (Resource, error) {
		n, err := d.getName()
		if err != nil {
			return nil, err
		}
		return make(n), nil
	}
}

// MX is Resolv::DNS::Resource::IN::MX — a mail exchanger.
type MX struct {
	Preference uint16
	Exchange   Name
	TTL        uint32
}

func (MX) TypeValue() uint16  { return TypeMX }
func (MX) ClassValue() uint16 { return ClassIN }
func (m MX) EncodeRData(e *MessageEncoder) {
	e.putUint16(m.Preference)
	e.putName(m.Exchange, true)
}

func decodeMX(d *MessageDecoder) (Resource, error) {
	pref, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	n, err := d.getName()
	if err != nil {
		return nil, err
	}
	return &MX{Preference: pref, Exchange: n}, nil
}

// TXT is Resolv::DNS::Resource::IN::TXT — one or more character-strings.
type TXT struct {
	Strings []string
	TTL     uint32
}

func (TXT) TypeValue() uint16  { return TypeTXT }
func (TXT) ClassValue() uint16 { return ClassIN }
func (t TXT) EncodeRData(e *MessageEncoder) {
	for _, s := range t.Strings {
		e.putString(s)
	}
}

func decodeTXT(d *MessageDecoder) (Resource, error) {
	var ss []string
	for d.index < d.limit {
		s, err := d.getString()
		if err != nil {
			return nil, err
		}
		ss = append(ss, s)
	}
	return &TXT{Strings: ss}, nil
}

// HINFO is Resolv::DNS::Resource::IN::HINFO — host CPU/OS information.
type HINFO struct {
	CPU string
	OS  string
	TTL uint32
}

func (HINFO) TypeValue() uint16  { return TypeHINFO }
func (HINFO) ClassValue() uint16 { return ClassIN }
func (h HINFO) EncodeRData(e *MessageEncoder) {
	e.putString(h.CPU)
	e.putString(h.OS)
}

func decodeHINFO(d *MessageDecoder) (Resource, error) {
	cpu, err := d.getString()
	if err != nil {
		return nil, err
	}
	os, err := d.getString()
	if err != nil {
		return nil, err
	}
	return &HINFO{CPU: cpu, OS: os}, nil
}

// SOA is Resolv::DNS::Resource::IN::SOA — a start-of-authority record.
type SOA struct {
	MName   Name
	RName   Name
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
	TTL     uint32
}

func (SOA) TypeValue() uint16  { return TypeSOA }
func (SOA) ClassValue() uint16 { return ClassIN }
func (s SOA) EncodeRData(e *MessageEncoder) {
	e.putName(s.MName, true)
	e.putName(s.RName, true)
	e.putUint32(s.Serial)
	e.putUint32(s.Refresh)
	e.putUint32(s.Retry)
	e.putUint32(s.Expire)
	e.putUint32(s.Minimum)
}

func decodeSOA(d *MessageDecoder) (Resource, error) {
	mname, err := d.getName()
	if err != nil {
		return nil, err
	}
	rname, err := d.getName()
	if err != nil {
		return nil, err
	}
	vals := make([]uint32, 5)
	for i := range vals {
		v, err := d.getUint32()
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return &SOA{MName: mname, RName: rname, Serial: vals[0], Refresh: vals[1],
		Retry: vals[2], Expire: vals[3], Minimum: vals[4]}, nil
}

// SRV is Resolv::DNS::Resource::IN::SRV — a service location record. Its target
// name is encoded without compression, matching MRI (put_name compress: false).
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Name
	TTL      uint32
}

func (SRV) TypeValue() uint16  { return TypeSRV }
func (SRV) ClassValue() uint16 { return ClassIN }
func (s SRV) EncodeRData(e *MessageEncoder) {
	e.putUint16(s.Priority)
	e.putUint16(s.Weight)
	e.putUint16(s.Port)
	e.putName(s.Target, false)
}

func decodeSRV(d *MessageDecoder) (Resource, error) {
	pri, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	wt, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	port, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	target, err := d.getName()
	if err != nil {
		return nil, err
	}
	return &SRV{Priority: pri, Weight: wt, Port: port, Target: target}, nil
}

// Generic is Resolv::DNS::Resource::Generic — an opaque record for a TYPE/CLASS
// pair the library does not model specially. It round-trips the raw RDATA.
type Generic struct {
	Type  uint16
	Class uint16
	Data  []byte
	TTL   uint32
}

func (g Generic) TypeValue() uint16             { return g.Type }
func (g Generic) ClassValue() uint16            { return g.Class }
func (g Generic) EncodeRData(e *MessageEncoder) { e.putBytes(g.Data) }
