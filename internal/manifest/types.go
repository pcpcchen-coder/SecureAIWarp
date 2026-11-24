// Package manifest defines the warp.yaml declaration format, its strict
// parser and the deterministic checker (lint). The manifest is pure data:
// no conditions, no scripts, no executable content.
package manifest

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// FormatVersion is the only manifest format version this core accepts.
const FormatVersion = "0.1"

// Manifest is the complete, closed schema of warp.yaml. Unknown fields are
// rejected by the parser.
type Manifest struct {
	Warp           string      `yaml:"warp" json:"warp"`
	App            App         `yaml:"app" json:"app"`
	Runtime        Runtime     `yaml:"runtime" json:"runtime"`
	Files          []FileGrant `yaml:"files,omitempty" json:"files,omitempty"`
	Network        Network     `yaml:"network,omitempty" json:"network,omitempty"`
	Secrets        []Secret    `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	AI             *AI         `yaml:"ai,omitempty" json:"ai,omitempty"`
	Data           *Data       `yaml:"data,omitempty" json:"data,omitempty"`
	SupplyChain    *Supply     `yaml:"supply_chain,omitempty" json:"supply_chain,omitempty"`
	Exceptions     []Exception `yaml:"exceptions" json:"exceptions"`
	Evidence       []Evidence  `yaml:"evidence" json:"evidence"`
	DeniedByDesign []Denied    `yaml:"denied_by_design,omitempty" json:"denied_by_design,omitempty"`
}

// App describes the wrapped application.
type App struct {
	Name        string   `yaml:"name" json:"name"`
	DisplayName string   `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Version     string   `yaml:"version" json:"version"`
	Kind        string   `yaml:"kind" json:"kind"`
	Entry       []string `yaml:"entry" json:"entry"`
	Digest      string   `yaml:"digest" json:"digest"`
	AuthorNote  string   `yaml:"author_note,omitempty" json:"author_note,omitempty"`
}

// Runtime covers the process channel.
type Runtime struct {
	Isolation  string     `yaml:"isolation" json:"isolation"`
	Resources  Resources  `yaml:"resources,omitempty" json:"resources,omitempty"`
	Spawn      string     `yaml:"spawn" json:"spawn"`
	Background StrictBool `yaml:"background" json:"background"`
}

// Resources are best-effort limits applied by the isolation backend.
type Resources struct {
	CPU    float64 `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory string  `yaml:"memory,omitempty" json:"memory,omitempty"`
	Pids   int     `yaml:"pids,omitempty" json:"pids,omitempty"`
	Disk   string  `yaml:"disk,omitempty" json:"disk,omitempty"`
}

// FileGrant is one mount in the synthetic file system.
type FileGrant struct {
	Path    string `yaml:"path" json:"path"`
	Mode    string `yaml:"mode" json:"mode"`
	Purpose string `yaml:"purpose" json:"purpose"`
}

// Network holds the egress and ingress channels.
type Network struct {
	Egress  []Egress  `yaml:"egress,omitempty" json:"egress,omitempty"`
	Ingress []Ingress `yaml:"ingress,omitempty" json:"ingress,omitempty"`
}

// Egress is one allowed outbound destination (host + port).
type Egress struct {
	Host    string        `yaml:"host" json:"host"`
	Port    int           `yaml:"port" json:"port"`
	Via     string        `yaml:"via,omitempty" json:"via,omitempty"`
	LAN     StrictBool    `yaml:"lan,omitempty" json:"lan,omitempty"`
	Purpose string        `yaml:"purpose" json:"purpose"`
	Limits  *EgressLimits `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// EgressLimits are traffic caps for one destination.
type EgressLimits struct {
	UploadPerDay string `yaml:"upload_per_day,omitempty" json:"upload_per_day,omitempty"`
}

// Ingress is one port the app listens on inside the shell.
type Ingress struct {
	Listen  int    `yaml:"listen" json:"listen"`
	Expose  string `yaml:"expose" json:"expose"`
	Auth    string `yaml:"auth" json:"auth"`
	Purpose string `yaml:"purpose" json:"purpose"`
}

// Secret is a credential the app needs. With gate-only visibility the app
// only ever sees a placeholder; the real value is injected by the egress gate.
type Secret struct {
	Name       string     `yaml:"name" json:"name"`
	ProvidedBy string     `yaml:"provided_by" json:"provided_by"`
	Bind       SecretBind `yaml:"bind" json:"bind"`
	Visibility string     `yaml:"visibility" json:"visibility"`
	Purpose    string     `yaml:"purpose" json:"purpose"`
}

// SecretBind ties a secret to one destination host and injection point.
type SecretBind struct {
	Host   string       `yaml:"host" json:"host"`
	Inject SecretInject `yaml:"inject" json:"inject"`
}

// SecretInject says where the gate places the real value.
type SecretInject struct {
	Header string `yaml:"header" json:"header"`
}

// AI declares model usage. In phase 1 this is declared-only: the AI gate is
// not implemented and the label says so.
type AI struct {
	Providers []AIProvider `yaml:"providers,omitempty" json:"providers,omitempty"`
	Budget    *AIBudget    `yaml:"budget,omitempty" json:"budget,omitempty"`
	Tools     []AITool     `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// AIProvider is a model endpoint.
type AIProvider struct {
	Host   string   `yaml:"host" json:"host"`
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
}

// AIBudget caps spending.
type AIBudget struct {
	DailyUSD         float64 `yaml:"daily_usd" json:"daily_usd"`
	PerRequestTokens int     `yaml:"per_request_tokens,omitempty" json:"per_request_tokens,omitempty"`
}

// AITool is a tool the app offers to a model.
type AITool struct {
	Name string `yaml:"name" json:"name"`
	Risk string `yaml:"risk" json:"risk"`
	Gate string `yaml:"gate,omitempty" json:"gate,omitempty"`
}

// Data declares data classes and flows (declared-only in phase 1).
type Data struct {
	Classes   []DataClass    `yaml:"classes,omitempty" json:"classes,omitempty"`
	Flows     []DataFlow     `yaml:"flows,omitempty" json:"flows,omitempty"`
	Retention *DataRetention `yaml:"retention,omitempty" json:"retention,omitempty"`
}

// DataClass is one category of processed data.
type DataClass struct {
	ID     string `yaml:"id" json:"id"`
	Source string `yaml:"source" json:"source"`
}

// DataFlow is an allowed destination for a data class.
type DataFlow struct {
	Class   string   `yaml:"class" json:"class"`
	To      []string `yaml:"to" json:"to"`
	Purpose string   `yaml:"purpose" json:"purpose"`
}

// DataRetention describes how long data is kept.
type DataRetention struct {
	Location string `yaml:"location" json:"location"`
	Days     int    `yaml:"days" json:"days"`
}

// Supply summarises the supply chain (declared-only in phase 1).
type Supply struct {
	SBOM         string      `yaml:"sbom,omitempty" json:"sbom,omitempty"`
	BuildSources []string    `yaml:"build_sources,omitempty" json:"build_sources,omitempty"`
	Scan         *SupplyScan `yaml:"scan,omitempty" json:"scan,omitempty"`
}

// SupplyScan is the summary of a dependency scan.
type SupplyScan struct {
	Date               string   `yaml:"date" json:"date"`
	Critical           int      `yaml:"critical" json:"critical"`
	High               int      `yaml:"high" json:"high"`
	SuspiciousPackages []string `yaml:"suspicious_packages" json:"suspicious_packages"`
}

// Exception records a human-approved deviation from a soft rule.
type Exception struct {
	Rule       string `yaml:"rule" json:"rule"`
	Grant      string `yaml:"grant" json:"grant"`
	Reason     string `yaml:"reason" json:"reason"`
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
	ApprovedAt string `yaml:"approved_at" json:"approved_at"`
}

// Evidence links a grant to a recorded trace.
type Evidence struct {
	Grant       string `yaml:"grant" json:"grant"`
	ObservedIn  string `yaml:"observed_in" json:"observed_in"`
	TriggeredBy string `yaml:"triggered_by" json:"triggered_by"`
}

// Denied documents an observed behaviour that is intentionally not granted.
type Denied struct {
	Behavior string `yaml:"behavior" json:"behavior"`
	Reason   string `yaml:"reason" json:"reason"`
}

// StrictBool only accepts a YAML boolean (true/false). yaml.v3 would
// otherwise also accept YAML 1.1 words such as "yes", "no", "on" or "off",
// even when quoted.
type StrictBool bool

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *StrictBool) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!bool" || (n.Value != "true" && n.Value != "false") {
		return fmt.Errorf("第 %d 行：必須是 true 或 false", n.Line)
	}
	*b = n.Value == "true"
	return nil
}

// Enumerations.
var (
	Kinds       = []string{"cli", "desktop", "local-web", "hosted", "mcp-server", "agent", "job"}
	Isolations  = []string{"process", "container", "microvm", "wasm"}
	SpawnModes  = []string{"none", "listed", "any"}
	FileModes   = []string{"ro", "rw"}
	Exposures   = []string{"loopback", "lan", "public"}
	AuthModes   = []string{"none", "local-token", "token", "oidc"}
	Providers   = []string{"recipient", "author"}
	Visibility  = []string{"gate-only", "app-visible"}
	ToolRisks   = []string{"low", "medium", "high"}
	ToolGates   = []string{"consent"}
	EgressVias  = []string{"ai-gate"}
	SupportedOS = "linux"
)

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}
