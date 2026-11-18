// Package output defines the result envelope shared by every MCP tool. Tool
// handlers keep their own typed outputs; the registration boundary moves
// those payloads below untrusted_data and promotes the signed event_id used
// for feedback.
//
// The JSON object boundary is the delimiter. Values are always produced by
// encoding/json before they become json.RawMessage, so externally authored
// quotes, braces, and fake sibling fields cannot escape untrusted_data. This
// is defence in depth rather than semantic prompt-injection prevention: an
// MCP host must still treat the subtree as data and enforce confirmation,
// least privilege, and egress policy outside the model.
package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/entur/go-mcpkit/retrieved"
)

// SchemaVersion is the tool-result contract version.
const SchemaVersion = 2

const (
	KiB = 1024

	// MaxJSONKeyBytes bounds dynamic map keys such as trace/profile/metric
	// labels. Struct property names pass through unchanged and are far shorter.
	MaxJSONKeyBytes = 512
)

// Policy is the final, centrally enforced backstop for one tool's successful
// result. MaxEnvelopeBytes includes the complete schema-v2 object, including
// event_id and JSON property overhead. Tool-level projectors should use
// tighter field and collection limits where they can preserve domain-specific
// truncation metadata; this policy guarantees that a missed string or
// multiplicative array still cannot create an unbounded MCP result.
type Policy struct {
	MaxEnvelopeBytes int
	MaxStringBytes   int
}

// Envelope is the public wire shape returned by every successful MCP tool.
// UntrustedData is encoded only from a server-produced Go value; callers must
// never construct it from unchecked raw JSON.
type Envelope struct {
	SchemaVersion int             `json:"schema_version"`
	EventID       string          `json:"event_id,omitempty"`
	UntrustedData json.RawMessage `json:"untrusted_data"`
}

// Wrap converts a typed tool output into the v2 public envelope. A top-level
// string event_id is removed from the payload and promoted to the envelope
// root. Non-object outputs are valid and remain unchanged below
// untrusted_data.
func Wrap(value any, policy Policy) (Envelope, error) {
	if policy.MaxEnvelopeBytes <= 0 || policy.MaxStringBytes <= 0 {
		return Envelope{}, fmt.Errorf("invalid output policy: envelope=%d string=%d", policy.MaxEnvelopeBytes, policy.MaxStringBytes)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal tool output: %w", err)
	}

	eventID, data, err := splitEventID(raw)
	if err != nil {
		return Envelope{}, err
	}
	if eventID != "" && retrieved.Opaque(eventID, 128) != eventID {
		return Envelope{}, errors.New("tool output event_id is not a bounded opaque token")
	}
	data, err = normalizeData(data, policy.MaxStringBytes)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		UntrustedData: data,
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, fmt.Errorf("measure tool-result envelope: %w", err)
	}
	if len(wire) > policy.MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: schema-v2 envelope is %d bytes (max %d)", ErrResultTooLarge, len(wire), policy.MaxEnvelopeBytes)
	}
	return envelope, nil
}

// normalizeData recursively normalizes every JSON string value and every
// dynamic object key. Tool projectors retain their tighter semantic caps;
// this is the exhaustive backstop for fields missed by that review. UseNumber
// prevents the round trip from losing precision on large integer values.
func normalizeData(raw []byte, maxStringBytes int) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode untrusted_data: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	normalized, err := normalizeValue(value, maxStringBytes)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal normalized untrusted_data: %w", err)
	}
	return json.RawMessage(out), nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode untrusted_data: multiple JSON values")
		}
		return fmt.Errorf("decode untrusted_data trailing data: %w", err)
	}
	return nil
}

func normalizeValue(value any, maxStringBytes int) (any, error) {
	switch v := value.(type) {
	case string:
		return retrieved.Block(v, maxStringBytes), nil
	case []any:
		for i := range v {
			normalized, err := normalizeValue(v[i], maxStringBytes)
			if err != nil {
				return nil, err
			}
			v[i] = normalized
		}
		return v, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			normalizedKey := retrieved.Inline(key, MaxJSONKeyBytes)
			if _, exists := out[normalizedKey]; exists {
				return nil, errors.New("normalize untrusted_data: object keys collide after normalization")
			}
			normalizedChild, err := normalizeValue(child, maxStringBytes)
			if err != nil {
				return nil, err
			}
			out[normalizedKey] = normalizedChild
		}
		return out, nil
	default:
		return value, nil
	}
}

func splitEventID(raw []byte) (string, json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", json.RawMessage(raw), nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", nil, fmt.Errorf("decode object tool output: %w", err)
	}
	eventRaw, ok := fields["event_id"]
	if !ok {
		return "", json.RawMessage(raw), nil
	}
	var eventID string
	if err := json.Unmarshal(eventRaw, &eventID); err != nil {
		return "", nil, fmt.Errorf("decode tool output event_id: %w", err)
	}
	delete(fields, "event_id")
	data, err := json.Marshal(fields)
	if err != nil {
		return "", nil, fmt.Errorf("marshal untrusted_data: %w", err)
	}
	return eventID, json.RawMessage(data), nil
}
