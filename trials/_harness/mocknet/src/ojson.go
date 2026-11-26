package main

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
)

// obj is a JSON object that keeps key order (the real APIs have a stable
// field order and some clients print responses verbatim).
type obj []kv

type kv struct {
	K string
	V any
}

func (o *obj) set(k string, v any) { *o = append(*o, kv{k, v}) }

func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(e.K)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalNoEscape(e.V)
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// num is a float printed with a fixed number of decimals (5.0, 0.00, 85).
type num struct {
	v   float64
	dec int
}

func (n num) MarshalJSON() ([]byte, error) {
	if math.IsNaN(n.v) || math.IsInf(n.v, 0) {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatFloat(n.v, 'f', n.dec, 64)), nil
}
