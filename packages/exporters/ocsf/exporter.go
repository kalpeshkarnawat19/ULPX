// Package ocsf implements a deterministic adapter that projects ULPF Canonical IR
// events into Open Cybersecurity Schema Framework (OCSF v1.1.0) without mutating the source event.
//
// Scope guard: Do not mutate canonical events during export.
package ocsf

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters"
)

// OCSFVersion specifies the OCSF schema specification version.
const OCSFVersion = "1.1.0"

// OCSF Class UIDs
const (
	ClassSystemActivity  = 1001
	ClassSecurityFinding = 2001
	ClassAuthentication  = 3002
	ClassNetworkActivity = 4001
	ClassHTTPActivity    = 6003
)

// OCSF Category UIDs
const (
	CategorySystemActivity         = 1
	CategoryFindings               = 2
	CategoryIdentityAndAccessMgmt  = 3
	CategoryNetworkActivity        = 4
	CategoryApplicationActivity    = 6
)

// ProductInfo identifies the sensor/device that observed the event.
type ProductInfo struct {
	VendorName string `json:"vendor_name"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	Version    string `json:"version,omitempty"`
}

// Metadata contains schema version, unique identifiers, and product details.
type Metadata struct {
	Version      string      `json:"version"`
	UID          string      `json:"uid"`
	OriginalTime string      `json:"original_time"`
	Product      ProductInfo `json:"product"`
}

// Endpoint models a network host and port in OCSF.
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// ConnectionInfo models transport layer attributes.
type ConnectionInfo struct {
	ProtocolName string `json:"protocol_name,omitempty"`
}

// User models user identity in OCSF.
type User struct {
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// Actor models the actor/user initiating an activity.
type Actor struct {
	User *User `json:"user,omitempty"`
}

// Device models endpoint host machine details.
type Device struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
}

// URLInfo models URL details in OCSF.
type URLInfo struct {
	URLString string `json:"url_string,omitempty"`
}

// HTTPRequest models HTTP request attributes.
type HTTPRequest struct {
	HTTPMethod string   `json:"http_method,omitempty"`
	URL        *URLInfo `json:"url,omitempty"`
}

// HTTPResponse models HTTP response attributes.
type HTTPResponse struct {
	Code int `json:"code,omitempty"`
}

// Finding models security alerts or detection findings.
type Finding struct {
	Title    string   `json:"title,omitempty"`
	Types    []string `json:"types,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

// OCSFEvent represents an event projected into OCSF schema.
type OCSFEvent struct {
	ClassUID       int                    `json:"class_uid"`
	ClassName      string                 `json:"class_name"`
	CategoryUID    int                    `json:"category_uid"`
	CategoryName   string                 `json:"category_name"`
	ActivityID     int                    `json:"activity_id"`
	ActivityName   string                 `json:"activity_name"`
	TypeUID        int                    `json:"type_uid"`
	Time           int64                  `json:"time"`
	TimeDT         string                 `json:"time_dt"`
	Metadata       Metadata               `json:"metadata"`
	Status         string                 `json:"status"`
	StatusID       int                    `json:"status_id"`
	StatusDetail   string                 `json:"status_detail,omitempty"`
	SrcEndpoint    *Endpoint              `json:"src_endpoint,omitempty"`
	DstEndpoint    *Endpoint              `json:"dst_endpoint,omitempty"`
	ConnectionInfo *ConnectionInfo        `json:"connection_info,omitempty"`
	Actor          *Actor                 `json:"actor,omitempty"`
	Device         *Device                `json:"device,omitempty"`
	HTTPRequest    *HTTPRequest           `json:"http_request,omitempty"`
	HTTPResponse   *HTTPResponse          `json:"http_response,omitempty"`
	Finding        *Finding               `json:"finding,omitempty"`
	Unmapped       map[string]interface{} `json:"unmapped,omitempty"`
}

// Exporter provides pure, deterministic projection from ULPF Canonical IR to OCSF.
type Exporter struct{}

// NewExporter creates an OCSF exporter.
func NewExporter() *Exporter {
	return &Exporter{}
}

// Export projects a NormalizedEvent into an OCSFEvent.
// Scope guard: The input ir is strictly read-only and remains completely unmutated.
func (e *Exporter) Export(ir *exporters.NormalizedEvent) (*OCSFEvent, error) {
	if ir == nil {
		return nil, fmt.Errorf("canonical event cannot be nil")
	}
	if err := ir.Validate(); err != nil {
		return nil, fmt.Errorf("cannot export invalid canonical event: %w", err)
	}

	// 1. Resolve Class and Category
	classUID, className, catUID, catName := resolveClassAndCategory(ir)
	activityID := resolveActivityID(classUID, ir.Event.Action)
	typeUID := classUID*100 + activityID

	// 2. Parse Timestamp to Milliseconds
	t, err := time.Parse(time.RFC3339, ir.Event.Time)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, ir.Event.Time)
	}
	timeMillis := t.UnixMilli()

	// 3. Resolve Status
	status, statusID := resolveStatus(ir.Event.Outcome)

	out := &OCSFEvent{
		ClassUID:     classUID,
		ClassName:    className,
		CategoryUID:  catUID,
		CategoryName: catName,
		ActivityID:   activityID,
		ActivityName: ir.Event.Action,
		TypeUID:      typeUID,
		Time:         timeMillis,
		TimeDT:       ir.Event.Time,
		Metadata: Metadata{
			Version:      OCSFVersion,
			UID:          ir.EventID,
			OriginalTime: ir.Event.Time,
			Product: ProductInfo{
				VendorName: ir.Source.Vendor,
				Name:       ir.Source.Product,
				UID:        ir.Source.DeviceID,
				Version:    ir.Parser.Version,
			},
		},
		Status:   status,
		StatusID: statusID,
	}

	// 4. Source & Destination Endpoints
	if ir.Src != nil && (ir.Src.IP != "" || ir.Src.Port > 0) {
		out.SrcEndpoint = &Endpoint{
			IP:   ir.Src.IP,
			Port: ir.Src.Port,
		}
	}
	if ir.Dst != nil && (ir.Dst.IP != "" || ir.Dst.Port > 0) {
		out.DstEndpoint = &Endpoint{
			IP:   ir.Dst.IP,
			Port: ir.Dst.Port,
		}
	}

	// 5. Connection Info
	if ir.Network != nil && ir.Network.Protocol != "" {
		out.ConnectionInfo = &ConnectionInfo{
			ProtocolName: strings.ToUpper(ir.Network.Protocol),
		}
	}

	// 6. User / Actor
	if ir.User != nil && (ir.User.Name != "" || ir.User.ID != "" || ir.User.Domain != "") {
		out.Actor = &Actor{
			User: &User{
				Name:   ir.User.Name,
				UID:    ir.User.ID,
				Domain: ir.User.Domain,
			},
		}
	}

	// 7. Device
	if ir.Device != nil && (ir.Device.Hostname != "" || ir.Device.IP != "" || ir.Device.MAC != "") {
		out.Device = &Device{
			Hostname: ir.Device.Hostname,
			IP:       ir.Device.IP,
			MAC:      ir.Device.MAC,
		}
	}

	// 8. HTTP
	if ir.HTTP != nil {
		if ir.HTTP.Method != "" || ir.HTTP.URL != "" {
			req := &HTTPRequest{HTTPMethod: ir.HTTP.Method}
			if ir.HTTP.URL != "" {
				req.URL = &URLInfo{URLString: ir.HTTP.URL}
			}
			out.HTTPRequest = req
		}
		if ir.HTTP.StatusCode > 0 {
			out.HTTPResponse = &HTTPResponse{Code: ir.HTTP.StatusCode}
		}
	}

	// 9. Alert / Finding
	if ir.Alert != nil && (ir.Alert.Name != "" || ir.Alert.Category != "" || ir.Alert.Severity != "") {
		finding := &Finding{
			Title:    ir.Alert.Name,
			Severity: ir.Alert.Severity,
		}
		if ir.Alert.Category != "" {
			finding.Types = []string{ir.Alert.Category}
		}
		out.Finding = finding
	}

	// 10. Unmapped / Extensions preservation
	unmapped := make(map[string]interface{})
	unmapped["raw_ref"] = ir.Raw.Ref
	unmapped["raw_sha256"] = ir.Raw.SHA256
	unmapped["parser_id"] = ir.Parser.ID
	unmapped["quality_status"] = ir.Quality.Status

	if ir.DNS != nil && (ir.DNS.QueryName != "" || ir.DNS.QueryType != "") {
		unmapped["dns"] = ir.DNS
	}
	for k, v := range ir.Extensions {
		unmapped[k] = v
	}
	out.Unmapped = unmapped

	return out, nil
}

// ExportJSON serializes the exported OCSF event to JSON bytes.
func (e *Exporter) ExportJSON(ir *exporters.NormalizedEvent) ([]byte, error) {
	ocsfEvent, err := e.Export(ir)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ocsfEvent)
}

func resolveClassAndCategory(ir *exporters.NormalizedEvent) (classUID int, className string, catUID int, catName string) {
	cls := strings.ToUpper(ir.Event.Class)
	switch {
	case strings.Contains(cls, "NETWORK"):
		return ClassNetworkActivity, "Network Activity", CategoryNetworkActivity, "Network Activity"
	case strings.Contains(cls, "AUTH") || strings.Contains(cls, "IDENTITY"):
		return ClassAuthentication, "Authentication", CategoryIdentityAndAccessMgmt, "Identity & Access Management"
	case strings.Contains(cls, "HTTP") || strings.Contains(cls, "WEB"):
		return ClassHTTPActivity, "HTTP Activity", CategoryApplicationActivity, "Application Activity"
	case strings.Contains(cls, "ALERT") || strings.Contains(cls, "INCIDENT") || strings.Contains(cls, "FINDING"):
		return ClassSecurityFinding, "Security Finding", CategoryFindings, "Findings"
	default:
		return ClassSystemActivity, "System Activity", CategorySystemActivity, "System Activity"
	}
}

func resolveActivityID(classUID int, action string) int {
	act := strings.ToLower(action)
	switch classUID {
	case ClassNetworkActivity:
		switch {
		case strings.Contains(act, "open") || strings.Contains(act, "start"):
			return 1
		case strings.Contains(act, "close") || strings.Contains(act, "end"):
			return 2
		case strings.Contains(act, "deny") || strings.Contains(act, "denied") || strings.Contains(act, "block") || strings.Contains(act, "blocked") || strings.Contains(act, "drop"):
			return 6 // Deny
		default:
			return 99 // Other
		}
	case ClassAuthentication:
		switch {
		case strings.Contains(act, "login") || strings.Contains(act, "logon") || strings.Contains(act, "auth"):
			return 1 // Logon
		case strings.Contains(act, "logout") || strings.Contains(act, "logoff"):
			return 2 // Logoff
		default:
			return 99
		}
	case ClassHTTPActivity:
		switch {
		case strings.Contains(act, "connect") || strings.Contains(act, "get") || strings.Contains(act, "post"):
			return 1
		default:
			return 99
		}
	case ClassSecurityFinding:
		return 1 // Create
	default:
		return 99 // Other
	}
}

func resolveStatus(outcome string) (string, int) {
	switch strings.ToLower(outcome) {
	case "success":
		return "Success", 1
	case "failure":
		return "Failure", 2
	default:
		return "Unknown", 0
	}
}
