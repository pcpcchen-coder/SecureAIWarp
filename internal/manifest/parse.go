package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// MaxManifestSize bounds the manifest file size.
const MaxManifestSize = 1 << 20

// Loaded is a parsed manifest together with its raw bytes hash.
type Loaded struct {
	Manifest *Manifest
	Path     string
	SHA256   string // hex digest of the raw file bytes
}

// LoadFile reads and strictly parses a manifest file.
func LoadFile(path string) (*Loaded, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("無法開啟宣告檔 %s：%w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("無法讀取宣告檔：%w", err)
	}
	if len(raw) > MaxManifestSize {
		return nil, fmt.Errorf("宣告檔超過 %d 位元組上限", MaxManifestSize)
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &Loaded{Manifest: m, Path: path, SHA256: hex.EncodeToString(sum[:])}, nil
}

// Parse strictly decodes manifest bytes. It rejects unknown fields, multiple
// documents, anchors/aliases, merge keys and explicit tags so that the file
// stays plain, comparable data.
func Parse(raw []byte) (*Manifest, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("宣告檔是空的")
		}
		return nil, fmt.Errorf("YAML 語法錯誤：%w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("宣告檔只能包含一份 YAML 文件")
	}
	if err := checkPlain(&root); err != nil {
		return nil, err
	}
	var m Manifest
	strict := yaml.NewDecoder(bytes.NewReader(raw))
	strict.KnownFields(true)
	if err := strict.Decode(&m); err != nil {
		return nil, fmt.Errorf("宣告格式錯誤（封閉格式，不接受未知欄位或錯誤型別）：%w", err)
	}
	return &m, nil
}

var allowedTags = map[string]bool{
	"": true, "!!str": true, "!!int": true, "!!float": true, "!!bool": true,
	"!!null": true, "!!map": true, "!!seq": true,
}

func checkPlain(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("第 %d 行：不允許使用 YAML 別名（*）", n.Line)
	}
	if n.Anchor != "" {
		return fmt.Errorf("第 %d 行：不允許使用 YAML 錨點（&）", n.Line)
	}
	if n.Style&yaml.TaggedStyle != 0 || !allowedTags[n.Tag] {
		return fmt.Errorf("第 %d 行：不允許使用 YAML 標記 %q", n.Line, n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "<<" && n.Content[i].Tag == "!!merge" {
				return fmt.Errorf("第 %d 行：不允許使用合併鍵（<<）", n.Content[i].Line)
			}
		}
	}
	for _, c := range n.Content {
		if err := checkPlain(c); err != nil {
			return err
		}
	}
	return nil
}

// Marshal renders a manifest back to YAML (used by draft).
func Marshal(m *Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
