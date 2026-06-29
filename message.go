// Copyright (c) the go-ruby-resolv/resolv authors
//
// SPDX-License-Identifier: BSD-3-Clause

package resolv

import "strings"

// DecodeError reports malformed DNS wire data, matching the failures MRI's
// Resolv::DNS::DecodeError signals (truncated input, junk in an RDATA window,
// a forward/over-long name pointer).
type DecodeError struct{ Msg string }

func (e *DecodeError) Error() string { return e.Msg }

// Question is one entry of a Message's question section: a name plus the queried
// TYPE/CLASS (Resolv::DNS::Message#question yields [name, typeclass]).
type Question struct {
	Name  Name
	Type  uint16
	Class uint16
}

// RR is one resource record in an answer/authority/additional section: an owner
// name, a TTL, and the typed RDATA (Resolv::DNS::Message#answer yields
// [name, ttl, data]).
type RR struct {
	Name Name
	TTL  uint32
	Data Resource
}

// Message is a pure-compute port of Ruby's Resolv::DNS::Message: a DNS header,
// the question section, and the three resource-record sections. It encodes to
// and decodes from the RFC 1035 wire format with 0xC0 name compression.
type Message struct {
	ID         uint16
	QR         uint16
	Opcode     uint16
	AA         uint16
	TC         uint16
	RD         uint16
	RA         uint16
	RCode      uint16
	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
}

// NewMessage builds an empty Message with the given ID (Resolv::DNS::Message.new).
func NewMessage(id uint16) *Message { return &Message{ID: id} }

// AddQuestion appends a question (Resolv::DNS::Message#add_question).
func (m *Message) AddQuestion(name Name, typ, class uint16) {
	m.Question = append(m.Question, Question{Name: name, Type: typ, Class: class})
}

// AddAnswer appends an answer record (Resolv::DNS::Message#add_answer).
func (m *Message) AddAnswer(name Name, ttl uint32, data Resource) {
	m.Answer = append(m.Answer, RR{Name: name, TTL: ttl, Data: data})
}

// AddAuthority appends an authority record (Resolv::DNS::Message#add_authority).
func (m *Message) AddAuthority(name Name, ttl uint32, data Resource) {
	m.Authority = append(m.Authority, RR{Name: name, TTL: ttl, Data: data})
}

// AddAdditional appends an additional record (Resolv::DNS::Message#add_additional).
func (m *Message) AddAdditional(name Name, ttl uint32, data Resource) {
	m.Additional = append(m.Additional, RR{Name: name, TTL: ttl, Data: data})
}

// flags packs the 16-bit flags word from the header fields (MRI's encode).
func (m *Message) flags() uint16 {
	return (m.QR&1)<<15 |
		(m.Opcode&15)<<11 |
		(m.AA&1)<<10 |
		(m.TC&1)<<9 |
		(m.RD&1)<<8 |
		(m.RA&1)<<7 |
		(m.RCode & 15)
}

// Encode serialises the Message to DNS wire bytes (Resolv::DNS::Message#encode).
func (m *Message) Encode() []byte {
	e := newMessageEncoder()
	e.putUint16(m.ID)
	e.putUint16(m.flags())
	e.putUint16(uint16(len(m.Question)))
	e.putUint16(uint16(len(m.Answer)))
	e.putUint16(uint16(len(m.Authority)))
	e.putUint16(uint16(len(m.Additional)))
	for _, q := range m.Question {
		e.putName(q.Name, true)
		e.putUint16(q.Type)
		e.putUint16(q.Class)
	}
	for _, section := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, rr := range section {
			e.putName(rr.Name, true)
			e.putUint16(rr.Data.TypeValue())
			e.putUint16(rr.Data.ClassValue())
			e.putUint32(rr.TTL)
			e.putLength16(func() { rr.Data.EncodeRData(e) })
		}
	}
	return e.data
}

// MessageEncoder accumulates wire bytes and a name-compression table, mirroring
// Ruby's Resolv::DNS::Message::MessageEncoder.
type MessageEncoder struct {
	data  []byte
	names map[string]int
}

func newMessageEncoder() *MessageEncoder {
	return &MessageEncoder{names: map[string]int{}}
}

func (e *MessageEncoder) putBytes(b []byte) { e.data = append(e.data, b...) }

func (e *MessageEncoder) putUint16(v uint16) {
	e.data = append(e.data, byte(v>>8), byte(v))
}

func (e *MessageEncoder) putUint32(v uint32) {
	e.data = append(e.data, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// putString writes a length-prefixed character-string (MRI put_string).
func (e *MessageEncoder) putString(s string) {
	e.data = append(e.data, byte(len(s)))
	e.data = append(e.data, s...)
}

// putLength16 reserves a 16-bit length, runs body, then back-patches the length
// of the bytes body wrote (MRI put_length16).
func (e *MessageEncoder) putLength16(body func()) {
	lenIndex := len(e.data)
	e.data = append(e.data, 0, 0)
	start := len(e.data)
	body()
	n := len(e.data) - start
	e.data[lenIndex] = byte(n >> 8)
	e.data[lenIndex+1] = byte(n)
}

// putName writes a domain name, optionally using 0xC0 compression pointers to
// earlier identical label suffixes (MRI put_name / put_labels). The compression
// table keys on the downcased label suffix joined by NUL, and a pointer is only
// recorded for offsets below 0x4000, exactly as MRI does.
func (e *MessageEncoder) putName(n Name, compress bool) {
	labels := n.Labels
	for i := range labels {
		suffix := labels[i:]
		k := suffixKey(suffix)
		if compress {
			if idx, ok := e.names[k]; ok {
				e.putUint16(uint16(0xc000 | idx))
				return
			}
		}
		if len(e.data) < 0x4000 {
			e.names[k] = len(e.data)
		}
		e.putString(labels[i].Str)
	}
	e.data = append(e.data, 0)
}

// suffixKey builds MRI's compression-table key for a label suffix. MRI keys
// @names on the live label-array, whose Hash identity uses Label::Str#hash /
// #eql? — both case-insensitive over ASCII (@downcase). So the key is the
// ASCII-downcased label sequence; this is what makes DNS name compression match
// case-insensitively (e.g. "ftp.example.com" reuses an earlier "Example.COM").
func suffixKey(labels []Label) string {
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = l.downcase()
	}
	return strings.Join(parts, "\x00")
}

// Decode parses DNS wire bytes into a Message (Resolv::DNS::Message.decode).
// When the truncation (TC) bit is set, MRI returns after the header, so Decode
// does the same and leaves the sections empty.
func Decode(m []byte) (*Message, error) {
	d := &MessageDecoder{data: m, limit: len(m)}
	o := &Message{}
	id, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	flag, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	counts := make([]uint16, 4)
	for i := range counts {
		c, err := d.getUint16()
		if err != nil {
			return nil, err
		}
		counts[i] = c
	}
	o.ID = id
	o.TC = (flag >> 9) & 1
	o.RCode = flag & 15
	if o.TC != 0 {
		return o, nil
	}
	o.QR = (flag >> 15) & 1
	o.Opcode = (flag >> 11) & 15
	o.AA = (flag >> 10) & 1
	o.RD = (flag >> 8) & 1
	o.RA = (flag >> 7) & 1
	for i := uint16(0); i < counts[0]; i++ {
		q, err := d.getQuestion()
		if err != nil {
			return nil, err
		}
		o.Question = append(o.Question, q)
	}
	sections := []*[]RR{&o.Answer, &o.Authority, &o.Additional}
	for s, n := range counts[1:] {
		for i := uint16(0); i < n; i++ {
			rr, err := d.getRR()
			if err != nil {
				return nil, err
			}
			*sections[s] = append(*sections[s], rr)
		}
	}
	return o, nil
}

// MessageDecoder reads wire bytes with a movable limit for RDATA windows,
// mirroring Ruby's Resolv::DNS::Message::MessageDecoder.
type MessageDecoder struct {
	data  []byte
	index int
	limit int
}

var errLimit = &DecodeError{Msg: "limit exceeded"}

func (d *MessageDecoder) getBytes(n int) ([]byte, error) {
	if d.limit < d.index+n {
		return nil, errLimit
	}
	b := d.data[d.index : d.index+n]
	d.index += n
	return b, nil
}

func (d *MessageDecoder) getUint16() (uint16, error) {
	b, err := d.getBytes(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (d *MessageDecoder) getUint32() (uint32, error) {
	b, err := d.getBytes(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

// getString reads a length-prefixed character-string (MRI get_string).
func (d *MessageDecoder) getString() (string, error) {
	if d.limit <= d.index {
		return "", errLimit
	}
	n := int(d.data[d.index])
	if d.limit < d.index+1+n {
		return "", errLimit
	}
	s := string(d.data[d.index+1 : d.index+1+n])
	d.index += 1 + n
	return s, nil
}

// getName reads a possibly-compressed domain name (MRI get_name/get_labels).
func (d *MessageDecoder) getName() (Name, error) {
	labels, err := d.getLabels()
	if err != nil {
		return Name{}, err
	}
	return NewNameLabels(labels, true), nil
}

// getLabels walks the label sequence, following 0xC0 compression pointers. It
// enforces MRI's invariants: pointers must be strictly backward and the
// uncompressed name must stay within 255 octets.
func (d *MessageDecoder) getLabels() ([]Label, error) {
	prevIndex := d.index
	saveIndex := -1
	var out []Label
	size := -1
	for {
		if d.limit <= d.index {
			return nil, errLimit
		}
		b := d.data[d.index]
		switch {
		case b == 0:
			d.index++
			if saveIndex >= 0 {
				d.index = saveIndex
			}
			return out, nil
		case b >= 192:
			ptr, err := d.getUint16()
			if err != nil {
				return nil, err
			}
			idx := int(ptr & 0x3fff)
			if prevIndex <= idx {
				return nil, &DecodeError{Msg: "non-backward name pointer"}
			}
			prevIndex = idx
			if saveIndex < 0 {
				saveIndex = d.index
			}
			d.index = idx
		default:
			l, err := d.getString()
			if err != nil {
				return nil, err
			}
			out = append(out, Label{Str: l})
			size += 1 + len(l)
			if size > 255 {
				return nil, &DecodeError{Msg: "name label data exceed 255 octets"}
			}
		}
	}
}

func (d *MessageDecoder) getQuestion() (Question, error) {
	name, err := d.getName()
	if err != nil {
		return Question{}, err
	}
	typ, err := d.getUint16()
	if err != nil {
		return Question{}, err
	}
	class, err := d.getUint16()
	if err != nil {
		return Question{}, err
	}
	return Question{Name: name, Type: typ, Class: class}, nil
}

// getRR reads one resource record, decoding its RDATA within a 16-bit length
// window (MRI get_rr / get_length16). The decoded TTL is stamped onto the
// record's TTL field so the typed value mirrors MRI's @ttl.
func (d *MessageDecoder) getRR() (RR, error) {
	name, err := d.getName()
	if err != nil {
		return RR{}, err
	}
	typ, err := d.getUint16()
	if err != nil {
		return RR{}, err
	}
	class, err := d.getUint16()
	if err != nil {
		return RR{}, err
	}
	ttl, err := d.getUint32()
	if err != nil {
		return RR{}, err
	}
	res, err := d.getLength16(func() (Resource, error) {
		if dec, ok := rdataDecoders[key(typ, class)]; ok {
			return dec(d)
		}
		// The RDATA window is already bounded within the data by getLength16, so
		// the remaining bytes can be taken directly.
		b, _ := d.getBytes(d.limit - d.index)
		data := make([]byte, len(b))
		copy(data, b)
		return &Generic{Type: typ, Class: class, Data: data}, nil
	})
	if err != nil {
		return RR{}, err
	}
	setTTL(res, ttl)
	return RR{Name: name, TTL: ttl, Data: res}, nil
}

// getLength16 reads a 16-bit length, narrows the limit to that window, runs body,
// and verifies body consumed the window exactly (MRI get_length16).
func (d *MessageDecoder) getLength16(body func() (Resource, error)) (Resource, error) {
	n, err := d.getUint16()
	if err != nil {
		return nil, err
	}
	saveLimit := d.limit
	if d.index+int(n) > len(d.data) {
		return nil, errLimit
	}
	d.limit = d.index + int(n)
	res, err := body()
	if err != nil {
		return nil, err
	}
	// Every field read is bounded by the window limit, so a decoder can only
	// stop short of it (leftover RDATA), never past it; MRI's symmetric
	// "limit exceeded" branch is therefore unreachable here.
	if d.index < d.limit {
		return nil, &DecodeError{Msg: "junk exists"}
	}
	d.limit = saveLimit
	return res, nil
}

// setTTL stamps the decoded TTL onto the typed record, matching MRI stamping
// @ttl after decode_rdata.
func setTTL(r Resource, ttl uint32) {
	switch v := r.(type) {
	case *A:
		v.TTL = ttl
	case *AAAA:
		v.TTL = ttl
	case *NS:
		v.TTL = ttl
	case *CNAME:
		v.TTL = ttl
	case *PTR:
		v.TTL = ttl
	case *MX:
		v.TTL = ttl
	case *TXT:
		v.TTL = ttl
	case *HINFO:
		v.TTL = ttl
	case *SOA:
		v.TTL = ttl
	case *SRV:
		v.TTL = ttl
	case *Generic:
		v.TTL = ttl
	}
}
