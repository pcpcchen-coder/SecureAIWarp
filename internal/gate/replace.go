package gate

import (
	"bytes"
	"io"
)

// replacingReader streams src while replacing every occurrence of each
// needle, including occurrences split across reads. It is used to redact
// real secret values from responses and to detect decoys in record mode.
type replacingReader struct {
	src     io.Reader
	olds    [][]byte
	news    [][]byte
	maxOld  int
	buf     []byte
	out     []byte
	eof     bool
	err     error
	onMatch func(idx int)
}

func newReplacingReader(src io.Reader, olds, news [][]byte, onMatch func(int)) *replacingReader {
	m := 0
	for _, o := range olds {
		if len(o) > m {
			m = len(o)
		}
	}
	return &replacingReader{src: src, olds: olds, news: news, maxOld: m, onMatch: onMatch}
}

func (r *replacingReader) process(final bool) {
	i := 0
	for {
		best, bestK := -1, -1
		for k, old := range r.olds {
			if len(old) == 0 {
				continue
			}
			if j := bytes.Index(r.buf[i:], old); j >= 0 && (best < 0 || j < best) {
				best, bestK = j, k
			}
		}
		if best >= 0 {
			r.out = append(r.out, r.buf[i:i+best]...)
			r.out = append(r.out, r.news[bestK]...)
			if r.onMatch != nil {
				r.onMatch(bestK)
			}
			i += best + len(r.olds[bestK])
			continue
		}
		keep := 0
		if !final && r.maxOld > 1 {
			keep = r.maxOld - 1
			if keep > len(r.buf)-i {
				keep = len(r.buf) - i
			}
		}
		r.out = append(r.out, r.buf[i:len(r.buf)-keep]...)
		i = len(r.buf) - keep
		break
	}
	r.buf = append(r.buf[:0], r.buf[i:]...)
}

func (r *replacingReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.eof {
			if len(r.buf) > 0 {
				r.process(true)
				continue
			}
			return 0, r.err
		}
		chunk := make([]byte, 32<<10)
		n, err := r.src.Read(chunk)
		r.buf = append(r.buf, chunk[:n]...)
		if err != nil {
			r.eof = true
			r.err = err
			r.process(true)
		} else {
			r.process(false)
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

// replaceAll applies the replacement to a whole string.
func replaceAll(s string, olds, news [][]byte) (string, bool) {
	b := []byte(s)
	changed := false
	for k, o := range olds {
		if len(o) > 0 && bytes.Contains(b, o) {
			b = bytes.ReplaceAll(b, o, news[k])
			changed = true
		}
	}
	return string(b), changed
}
