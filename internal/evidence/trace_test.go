package evidence

import (
	"path/filepath"
	"testing"
)

func TestTraceSignAndLoad(t *testing.T) {
	key := []byte("k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1")
	dir := t.TempDir()
	p, id, err := NextPath(dir)
	if err != nil || id != "trace-0001" {
		t.Fatal(id, err)
	}
	rec := NewRecorder()
	rec.Add(Event{Channel: ChanEgress, Host: "a.example.com", Port: 443})
	rec.Add(Event{Channel: ChanEgress, Host: "a.example.com", Port: 443})
	tr := &Trace{Format: Format, ID: id, Events: rec.Events()}
	if err := Write(p, tr, key); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, tr, key); err == nil {
		t.Fatal("traces must never be overwritten")
	}
	got, err := Load(p, key)
	if err != nil || len(got.Events) != 1 || got.Events[0].Count != 2 || !got.HasEgress("*.example.com", 443) {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := Load(p, []byte("other")); err == nil {
		t.Fatal("wrong key must fail")
	}
	if _, id2, _ := NextPath(dir); id2 != "trace-0002" {
		t.Fatal(id2)
	}
	_ = filepath.Base(p)
}

func TestHostMatches(t *testing.T) {
	for _, c := range []struct {
		p, h string
		ok   bool
	}{{"a.example.com", "A.example.com.", true}, {"*.example.com", "x.example.com", true}, {"*.example.com", "example.com", false},
		{"*.example.com", "x.evil-example.com", false}, {"*.example.com", "a.b.example.com", true}} {
		if HostMatches(c.p, c.h) != c.ok {
			t.Errorf("%v", c)
		}
	}
}
