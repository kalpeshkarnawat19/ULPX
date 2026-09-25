// Package main implements the ULPF Canonical IR (Intermediate Representation)
// normalizer conforming to ULPF-X Build Guide Stage 4 and PRD Section 4.
//
// Scope guard: Does not use ECS or OCSF as the internal source of truth.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"time"
)

var (
	eventIDRegex = regexp.MustCompile(`^(?:[0-7][0-9A-HJKMNP-TV-Z]{25}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$`)
	sha256Regex  = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	semverRegex  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// EventInfo represents core event metadata.
type EventInfo struct {
	Class   string `json:"class"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
	Time    string `json:"time"`
}

// SourceInfo represents the originating device/agent.
type SourceInfo struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	DeviceID string `json:"device_id"`
}

// Endpoint represents a network host/port.
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// NetworkInfo represents network transport details.
type NetworkInfo struct {
	Protocol string `json:"protocol,omitempty"`
}

// UserInfo represents human or service identities.
type UserInfo struct {
	Name   string `json:"name,omitempty"`
	ID     string `json:"id,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// DeviceInfo represents endpoint device attributes.
type DeviceInfo struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
}

// HTTPInfo represents web and REST transaction metadata.
type HTTPInfo struct {
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	URL        string `json:"url,omitempty"`
}

// DNSInfo represents domain name resolution metadata.
type DNSInfo struct {
	QueryName    string `json:"query_name,omitempty"`
	QueryType    string `json:"query_type,omitempty"`
	ResponseCode string `json:"response_code,omitempty"`
}

// AlertInfo represents detection and security alert metadata.
type AlertInfo struct {
	Severity string `json:"severity,omitempty"`
	Name     string `json:"name,omitempty"`
	Category string `json:"category,omitempty"`
}

// ParserMetadata identifies the certified parser that processed this event.
type ParserMetadata struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// RawProvenance preserves cryptographic linkage to the immutable raw store.
type RawProvenance struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}

// QualityReport records extraction confidence and mapping health.
type QualityReport struct {
	MappingScore float64 `json:"mapping_score"`
	Status       string  `json:"status"`
}

// NormalizedEvent is the schema-neutral ULPF Canonical IR model conforming to
// packages/contracts/normalized_event.schema.json.
type NormalizedEvent struct {
	SchemaVersion string                 `json:"schema_version"`
	EventID       string                 `json:"event_id"`
	Event         EventInfo              `json:"event"`
	Source        SourceInfo             `json:"source"`
	Src           *Endpoint              `json:"src,omitempty"`
	Dst           *Endpoint              `json:"dst,omitempty"`
	Network       *NetworkInfo           `json:"network,omitempty"`
	User          *UserInfo              `json:"user,omitempty"`
	Device        *DeviceInfo            `json:"device,omitempty"`
	HTTP          *HTTPInfo              `json:"http,omitempty"`
	DNS           *DNSInfo               `json:"dns,omitempty"`
	Alert         *AlertInfo             `json:"alert,omitempty"`
	Parser        ParserMetadata         `json:"parser"`
	Raw           RawProvenance          `json:"raw"`
	Quality       QualityReport          `json:"quality"`
	Extensions    map[string]interface{} `json:"extensions"`
}

// Validate checks that NormalizedEvent satisfies normalized_event.schema.json.
func (e *NormalizedEvent) Validate() error {
	if e.SchemaVersion != "1.0" {
		return fmt.Errorf("invalid schema_version %q: must be '1.0'", e.SchemaVersion)
	}

	if !eventIDRegex.MatchString(e.EventID) {
		return fmt.Errorf("invalid event_id %q: must match ULID or UUID pattern", e.EventID)
	}

	if e.Event.Class == "" {
		return fmt.Errorf("event.class is required")
	}
	if e.Event.Action == "" {
		return fmt.Errorf("event.action is required")
	}
	if e.Event.Outcome != "success" && e.Event.Outcome != "failure" && e.Event.Outcome != "unknown" {
		return fmt.Errorf("invalid event.outcome %q: must be success, failure, or unknown", e.Event.Outcome)
	}
	if _, err := time.Parse(time.RFC3339, e.Event.Time); err != nil {
		if _, errNano := time.Parse(time.RFC3339Nano, e.Event.Time); errNano != nil {
			return fmt.Errorf("event.time %q is not valid RFC3339: %w", e.Event.Time, err)
		}
	}

	if e.Source.Vendor == "" {
		return fmt.Errorf("source.vendor is required")
	}
	if e.Source.Product == "" {
		return fmt.Errorf("source.product is required")
	}
	if e.Source.DeviceID == "" {
		return fmt.Errorf("source.device_id is required")
	}

	if e.Src != nil {
		if e.Src.IP != "" && net.ParseIP(e.Src.IP) == nil {
			return fmt.Errorf("invalid src.ip %q", e.Src.IP)
		}
		if e.Src.Port < 0 || e.Src.Port > 65535 {
			return fmt.Errorf("invalid src.port %d", e.Src.Port)
		}
	}

	if e.Dst != nil {
		if e.Dst.IP != "" && net.ParseIP(e.Dst.IP) == nil {
			return fmt.Errorf("invalid dst.ip %q", e.Dst.IP)
		}
		if e.Dst.Port < 0 || e.Dst.Port > 65535 {
			return fmt.Errorf("invalid dst.port %d", e.Dst.Port)
		}
	}

	if e.Parser.ID == "" {
		return fmt.Errorf("parser.id is required")
	}
	if !semverRegex.MatchString(e.Parser.Version) {
		return fmt.Errorf("invalid parser.version %q: must match semver", e.Parser.Version)
	}

	if e.Raw.Ref == "" {
		return fmt.Errorf("raw.ref is required")
	}
	if !sha256Regex.MatchString(e.Raw.SHA256) {
		return fmt.Errorf("invalid raw.sha256 %q: must match 64 hex characters", e.Raw.SHA256)
	}

	if e.Quality.MappingScore < 0 || e.Quality.MappingScore > 1.0 {
		return fmt.Errorf("quality.mapping_score %.2f must be between 0 and 1", e.Quality.MappingScore)
	}
	if e.Quality.Status != "VERIFIED" && e.Quality.Status != "REVIEW_REQUIRED" && e.Quality.Status != "ABSTAINED" {
		return fmt.Errorf("invalid quality.status %q", e.Quality.Status)
	}

	if e.Extensions == nil {
		return fmt.Errorf("extensions map cannot be nil (must be object)")
	}

	return nil
}

// ToJSON serializes the NormalizedEvent to JSON bytes.
func (e *NormalizedEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}
