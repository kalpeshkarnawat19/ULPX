// Package ecs implements a deterministic adapter that projects ULPF Canonical IR
// events into Elastic Common Schema (ECS v8.11.0) without mutating the source event.
//
// Scope guard: Do not mutate canonical events during export.
package ecs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters"
)

// ECSVersion specifies the ECS schema specification version.
const ECSVersion = "8.11.0"

// ECSMetadata contains ECS version information.
type ECSMetadata struct {
	Version string `json:"version"`
}

// EventFields models core ECS event categorization and execution state.
type EventFields struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Category []string `json:"category"`
	Type     []string `json:"type,omitempty"`
	Action   string   `json:"action"`
	Outcome  string   `json:"outcome"`
	Reason   string   `json:"reason,omitempty"`
}

// EndpointFields models network source and destination endpoints.
type EndpointFields struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// NetworkFields models transport and network metadata.
type NetworkFields struct {
	Transport string `json:"transport,omitempty"`
}

// UserFields models user identity attributes.
type UserFields struct {
	Name   string `json:"name,omitempty"`
	ID     string `json:"id,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// HostFields models endpoint host and device attributes.
type HostFields struct {
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// HTTPRequestFields models HTTP request properties.
type HTTPRequestFields struct {
	Method string `json:"method,omitempty"`
}

// HTTPResponseFields models HTTP response properties.
type HTTPResponseFields struct {
	StatusCode int `json:"status_code,omitempty"`
}

// HTTPFields models HTTP transaction metadata.
type HTTPFields struct {
	Request  *HTTPRequestFields  `json:"request,omitempty"`
	Response *HTTPResponseFields `json:"response,omitempty"`
}

// URLFields models URL details.
type URLFields struct {
	Original string `json:"original,omitempty"`
}

// DNSQuestionFields models DNS query questions.
type DNSQuestionFields struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// DNSFields models DNS transaction metadata.
type DNSFields struct {
	Question     *DNSQuestionFields `json:"question,omitempty"`
	ResponseCode string             `json:"response_code,omitempty"`
}

// ObserverFields models telemetry collector / sensor identity.
type ObserverFields struct {
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Name    string `json:"name,omitempty"`
}

// ECSEvent represents the exported Elastic Common Schema event.
type ECSEvent struct {
	Timestamp   string                 `json:"@timestamp"`
	ECS         ECSMetadata            `json:"ecs"`
	Event       EventFields            `json:"event"`
	Source      *EndpointFields        `json:"source,omitempty"`
	Destination *EndpointFields        `json:"destination,omitempty"`
	Network     *NetworkFields         `json:"network,omitempty"`
	User        *UserFields            `json:"user,omitempty"`
	Host        *HostFields            `json:"host,omitempty"`
	HTTP        *HTTPFields            `json:"http,omitempty"`
	URL         *URLFields             `json:"url,omitempty"`
	DNS         *DNSFields             `json:"dns,omitempty"`
	Observer    *ObserverFields        `json:"observer,omitempty"`
	Labels      map[string]interface{} `json:"labels,omitempty"`
}

// Exporter provides pure, deterministic projection from ULPF Canonical IR to ECS.
type Exporter struct{}

// NewExporter creates an ECS exporter.
func NewExporter() *Exporter {
	return &Exporter{}
}

// Export projects a NormalizedEvent into an ECSEvent.
// Scope guard: The input ir is strictly read-only and remains completely unmutated.
func (e *Exporter) Export(ir *exporters.NormalizedEvent) (*ECSEvent, error) {
	if ir == nil {
		return nil, fmt.Errorf("canonical event cannot be nil")
	}
	if err := ir.Validate(); err != nil {
		return nil, fmt.Errorf("cannot export invalid canonical event: %w", err)
	}

	// 1. Map Event Categories & Types
	categories := mapECSCategories(ir.Event.Class)
	types := mapECSTypes(ir.Event.Action, ir.Event.Outcome)

	eventFields := EventFields{
		ID:       ir.EventID,
		Kind:     "event",
		Category: categories,
		Type:     types,
		Action:   ir.Event.Action,
		Outcome:  ir.Event.Outcome,
	}
	if ir.Alert != nil && ir.Alert.Name != "" {
		eventFields.Reason = ir.Alert.Name
	}

	out := &ECSEvent{
		Timestamp: ir.Event.Time,
		ECS: ECSMetadata{
			Version: ECSVersion,
		},
		Event: eventFields,
	}

	// 2. Source Endpoint
	if ir.Src != nil && (ir.Src.IP != "" || ir.Src.Port > 0) {
		out.Source = &EndpointFields{
			IP:   ir.Src.IP,
			Port: ir.Src.Port,
		}
	}

	// 3. Destination Endpoint
	if ir.Dst != nil && (ir.Dst.IP != "" || ir.Dst.Port > 0) {
		out.Destination = &EndpointFields{
			IP:   ir.Dst.IP,
			Port: ir.Dst.Port,
		}
	}

	// 4. Network
	if ir.Network != nil && ir.Network.Protocol != "" {
		out.Network = &NetworkFields{
			Transport: strings.ToLower(ir.Network.Protocol),
		}
	}

	// 5. User
	if ir.User != nil && (ir.User.Name != "" || ir.User.ID != "" || ir.User.Domain != "") {
		out.User = &UserFields{
			Name:   ir.User.Name,
			ID:     ir.User.ID,
			Domain: ir.User.Domain,
		}
	}

	// 6. Host / Device
	if ir.Device != nil && (ir.Device.Hostname != "" || ir.Device.IP != "" || ir.Device.MAC != "") {
		out.Host = &HostFields{
			Name: ir.Device.Hostname,
			IP:   ir.Device.IP,
			MAC:  ir.Device.MAC,
		}
	}

	// 7. HTTP & URL
	if ir.HTTP != nil {
		httpFields := &HTTPFields{}
		if ir.HTTP.Method != "" {
			httpFields.Request = &HTTPRequestFields{Method: ir.HTTP.Method}
		}
		if ir.HTTP.StatusCode > 0 {
			httpFields.Response = &HTTPResponseFields{StatusCode: ir.HTTP.StatusCode}
		}
		if httpFields.Request != nil || httpFields.Response != nil {
			out.HTTP = httpFields
		}
		if ir.HTTP.URL != "" {
			out.URL = &URLFields{Original: ir.HTTP.URL}
		}
	}

	// 8. DNS
	if ir.DNS != nil && (ir.DNS.QueryName != "" || ir.DNS.QueryType != "" || ir.DNS.ResponseCode != "") {
		dnsFields := &DNSFields{
			ResponseCode: ir.DNS.ResponseCode,
		}
		if ir.DNS.QueryName != "" || ir.DNS.QueryType != "" {
			dnsFields.Question = &DNSQuestionFields{
				Name: ir.DNS.QueryName,
				Type: ir.DNS.QueryType,
			}
		}
		out.DNS = dnsFields
	}

	// 9. Observer
	if ir.Source.Vendor != "" || ir.Source.Product != "" || ir.Source.DeviceID != "" {
		out.Observer = &ObserverFields{
			Vendor:  ir.Source.Vendor,
			Product: ir.Source.Product,
			Name:    ir.Source.DeviceID,
		}
	}

	// 10. Labels: provenance and extensions
	labels := make(map[string]interface{})
	labels["raw_ref"] = ir.Raw.Ref
	labels["raw_sha256"] = ir.Raw.SHA256
	labels["parser_id"] = ir.Parser.ID
	labels["parser_version"] = ir.Parser.Version
	labels["quality_status"] = ir.Quality.Status

	for k, v := range ir.Extensions {
		labels[k] = v
	}
	out.Labels = labels

	return out, nil
}

// ExportJSON serializes the exported ECS event to JSON bytes.
func (e *Exporter) ExportJSON(ir *exporters.NormalizedEvent) ([]byte, error) {
	ecsEvent, err := e.Export(ir)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ecsEvent)
}

func mapECSCategories(class string) []string {
	c := strings.ToUpper(class)
	switch {
	case strings.Contains(c, "NETWORK"):
		return []string{"network"}
	case strings.Contains(c, "AUTH") || strings.Contains(c, "IDENTITY"):
		return []string{"authentication"}
	case strings.Contains(c, "HTTP") || strings.Contains(c, "WEB"):
		return []string{"web"}
	case strings.Contains(c, "ALERT") || strings.Contains(c, "INCIDENT"):
		return []string{"threat"}
	case strings.Contains(c, "PROCESS") || strings.Contains(c, "ENDPOINT"):
		return []string{"process"}
	case strings.Contains(c, "FILE"):
		return []string{"file"}
	default:
		return []string{"configuration"}
	}
}

func mapECSTypes(action, outcome string) []string {
	act := strings.ToLower(action)
	switch {
	case outcome == "failure" || act == "block" || act == "blocked" || act == "deny" || act == "denied":
		return []string{"denied"}
	case outcome == "success" || act == "allow" || act == "allowed":
		return []string{"allowed"}
	default:
		return []string{"info"}
	}
}
