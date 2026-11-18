package output

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// The fixtures below cover every shape the inference produces for a record:
// a nested struct, a struct slice, a fixed struct array, a nullable pointer
// object, a typed map of structs, a map of struct slices, an embedded
// struct, and plain scalar maps. v1 is the schema a client cached; v2 adds a
// field at every one of those record locations.

type openLeafV1 struct {
	Name string `json:"name"`
}

type openEmbeddedV1 struct {
	Inherited string `json:"inherited"`
}

type openFixtureV1 struct {
	EventID string `json:"event_id"`
	openEmbeddedV1
	State    string                  `json:"state" jsonschema:"ok or failed"`
	Count    int                     `json:"count"`
	Nested   openLeafV1              `json:"nested"`
	List     []openLeafV1            `json:"list"`
	Pair     [2]openLeafV1           `json:"pair"`
	Pointer  *openLeafV1             `json:"pointer"`
	ByName   map[string]openLeafV1   `json:"by_name"`
	Groups   map[string][]openLeafV1 `json:"groups"`
	Flags    map[string]bool         `json:"flags"`
	Optional string                  `json:"optional,omitempty"`
}

type openLeafV2 struct {
	Name  string `json:"name"`
	Added string `json:"added"`
}

type openEmbeddedV2 struct {
	Inherited string `json:"inherited"`
	Promoted  string `json:"promoted"`
}

type openFixtureV2 struct {
	EventID string `json:"event_id"`
	openEmbeddedV2
	State    string                  `json:"state"`
	Count    int                     `json:"count"`
	Nested   openLeafV2              `json:"nested"`
	List     []openLeafV2            `json:"list"`
	Pair     [2]openLeafV2           `json:"pair"`
	Pointer  *openLeafV2             `json:"pointer"`
	ByName   map[string]openLeafV2   `json:"by_name"`
	Groups   map[string][]openLeafV2 `json:"groups"`
	Flags    map[string]bool         `json:"flags"`
	Optional string                  `json:"optional,omitempty"`
	TopAdded int                     `json:"top_added"`
}

func openFixtureV2Value() openFixtureV2 {
	leaf := openLeafV2{Name: "n", Added: "new"}
	return openFixtureV2{
		EventID:        "signed-token",
		openEmbeddedV2: openEmbeddedV2{Inherited: "i", Promoted: "new"},
		State:          "ok",
		Count:          1,
		Nested:         leaf,
		List:           []openLeafV2{leaf},
		Pair:           [2]openLeafV2{leaf, leaf},
		Pointer:        &leaf,
		ByName:         map[string]openLeafV2{"k": leaf},
		Groups:         map[string][]openLeafV2{"g": {leaf}},
		Flags:          map[string]bool{"f": true},
		TopAdded:       7,
	}
}

// cachedSchema simulates what a client keeps after tools/list: the marshalled
// descriptor, decoded again and compiled.
func cachedSchema(t *testing.T, schema *jsonschema.Schema) *jsonschema.Resolved {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	return cachedSchemaJSON(t, raw)
}

func cachedSchemaJSON(t *testing.T, raw []byte) *jsonschema.Resolved {
	t.Helper()
	var cached jsonschema.Schema
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatalf("decode cached schema: %v", err)
	}
	resolved, err := cached.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve cached schema: %v", err)
	}
	return resolved
}

// wireEnvelope wraps value as the registration boundary does and decodes the bytes a
// client receives as structuredContent.
func wireEnvelope(t *testing.T, value any) map[string]any {
	t.Helper()
	envelope, err := Wrap(value, testPolicy)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return decoded
}

func TestSchemaForOpensEveryNestedRecord(t *testing.T) {
	schema, err := SchemaFor[openFixtureV1](SchemaText{})
	if err != nil {
		t.Fatalf("SchemaFor: %v", err)
	}
	paths, err := ClosedRecordPaths(schema)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("closed records below the envelope root: %v", paths)
	}
	if !isFalseSchema(schema.AdditionalProperties) {
		t.Fatal("envelope root is no longer closed")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), `"additionalProperties":false}`) {
		t.Fatalf("root closure is not marshalled as false: %s", raw)
	}

	data := schema.Properties["untrusted_data"]
	for _, name := range []string{"by_name", "groups"} {
		value := data.Properties[name].AdditionalProperties
		if value == nil || isFalseSchema(value) {
			t.Fatalf("%s lost its typed map value schema: %#v", name, value)
		}
	}
	if got := data.Properties["by_name"].AdditionalProperties; got.Type != "object" || got.Properties["name"] == nil || !slices.Contains(got.Required, "name") {
		t.Fatalf("typed map value schema not preserved: %#v", got)
	}
	if got := data.Properties["flags"].AdditionalProperties; got == nil || got.Type != "boolean" {
		t.Fatalf("scalar map value schema not preserved: %#v", got)
	}
}

// TestSchemaForChangesOnlyRecordClosure pins the transformation to exactly
// what additive outputs and nil maps need: the opened payload schema equals the inferred one
// with every false additionalProperties deleted and every Go map admitting
// null (plus the moved event_id and the untrusted_data description). Types,
// consts, enums, required lists, descriptions and map value schemas all
// survive.
func TestSchemaForChangesOnlyRecordClosure(t *testing.T) {
	opened, err := SchemaFor[openFixtureV1](SchemaText{})
	if err != nil {
		t.Fatal(err)
	}
	inferred, err := jsonschema.For[openFixtureV1](nil)
	if err != nil {
		t.Fatal(err)
	}
	removeEventID(inferred)
	inferred.Description = untrustedDataDescription

	want := decodeJSON(t, inferred)
	stripFalseAdditionalProperties(want)
	properties := want.(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"by_name", "groups", "flags"} {
		properties[name].(map[string]any)["type"] = []any{"null", "object"}
	}
	got := decodeJSON(t, opened.Properties["untrusted_data"])
	if !reflect.DeepEqual(got, want) {
		gotRaw, _ := json.Marshal(got)
		wantRaw, _ := json.Marshal(want)
		t.Fatalf("opening changed more than record closure\ngot:  %s\nwant: %s", gotRaw, wantRaw)
	}
	if !strings.Contains(mustJSON(t, inferred), `"additionalProperties":false`) {
		t.Fatal("fixture no longer exercises inferred closure")
	}
}

// TestSchemaForAdmitsNilMaps: a nil map marshals as null,
// so a result whose map field is nil must validate against the schema
// published for its type, exactly as a nil slice already does. The map's
// value schema is kept, and a struct (named properties) never becomes
// nullable.
func TestSchemaForAdmitsNilMaps(t *testing.T) {
	schema, err := SchemaFor[openFixtureV1](SchemaText{})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]openFixtureV1{
		"nil maps":      {EventID: "signed-token"},
		"populated map": {EventID: "signed-token", ByName: map[string]openLeafV1{"a": {Name: "a"}}, Flags: map[string]bool{"f": true}},
	} {
		envelope, err := Wrap(value, Policy{MaxEnvelopeBytes: 1 << 16, MaxStringBytes: 1 << 10})
		if err != nil {
			t.Fatal(err)
		}
		var instance any
		if err := json.Unmarshal([]byte(mustJSON(t, envelope)), &instance); err != nil {
			t.Fatal(err)
		}
		if err := resolved.Validate(instance); err != nil {
			t.Errorf("%s: result rejected by the schema published for its own type: %v", name, err)
		}
	}
	envelope, err := Wrap(openFixtureV1{EventID: "signed-token", ByName: map[string]openLeafV1{"a": {}}}, Policy{MaxEnvelopeBytes: 1 << 16, MaxStringBytes: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	var instance map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, envelope)), &instance); err != nil {
		t.Fatal(err)
	}
	instance["untrusted_data"].(map[string]any)["by_name"] = map[string]any{"a": "not a record"}
	if err := resolved.Validate(instance); err == nil {
		t.Error("a map value of the wrong type validated; the map's value schema was lost")
	}
	data := schema.Properties["untrusted_data"]
	if got := data.Properties["nested"].Type; got != "object" {
		t.Errorf("a struct-typed record became %q/%v; only maps may admit null", got, data.Properties["nested"].Types)
	}
	if got := data.Type; got != "object" {
		t.Errorf("the payload root became %q/%v; only maps may admit null", got, data.Types)
	}
}

func closedRecord(props ...string) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{}, AdditionalProperties: falseSchema()}
	for _, p := range props {
		s.Properties[p] = &jsonschema.Schema{Type: "string"}
		s.Required = append(s.Required, p)
	}
	return s
}

func payloadRef(name string) *jsonschema.Schema {
	return &jsonschema.Schema{Ref: payloadPointer + "/$defs/" + name}
}

// TestSchemaForDataOpensEverySupportedLocation covers the monotone
// positions a hand-built payload may use: named properties, a nullable
// object, array and tuple items, additional items, a typed map's value, a
// local definition reached by $ref, allOf, anyOf, then and else.
func TestSchemaForDataOpensEverySupportedLocation(t *testing.T) {
	data := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"nested":   closedRecord("x"),
			"nullable": {Types: []string{"null", "object"}, Properties: map[string]*jsonschema.Schema{"x": {Type: "string"}}, AdditionalProperties: falseSchema()},
			"list":     {Type: "array", Items: closedRecord("x")},
			"tuple":    {Type: "array", PrefixItems: []*jsonschema.Schema{closedRecord("x")}, AdditionalItems: closedRecord("y")},
			"map":      {Type: "object", AdditionalProperties: closedRecord("x")},
			"ref":      payloadRef("leaf"),
			"all":      {AllOf: []*jsonschema.Schema{closedRecord("x")}},
			"any":      {AnyOf: []*jsonschema.Schema{closedRecord("x"), {Type: "null"}}},
			"cond":     {If: &jsonschema.Schema{Type: "object"}, Then: closedRecord("x"), Else: closedRecord("y")},
		},
		Defs:                 map[string]*jsonschema.Schema{"leaf": closedRecord("x")},
		AdditionalProperties: falseSchema(),
	}
	schema, err := SchemaForData(data, SchemaText{})
	if err != nil {
		t.Fatalf("SchemaForData: %v", err)
	}
	paths, err := ClosedRecordPaths(schema)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("closed records survived: %v", paths)
	}
	if before, _ := ClosedRecordPaths(&jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"d": data}}); len(before) == 0 {
		t.Fatal("SchemaForData mutated the caller's schema")
	}
	if got := schema.Properties["untrusted_data"].Defs["leaf"]; !slices.Contains(got.Required, "x") || got.Properties["x"].Type != "string" {
		t.Fatalf("$defs entry lost its constraints: %#v", got)
	}

	// Every previously valid result stays valid, and a property added at
	// every record location validates too.
	cached := cachedSchema(t, schema)
	leaf := func(extra bool) map[string]any {
		m := map[string]any{"x": "v", "y": "v"}
		if extra {
			m["added"] = true
		}
		return m
	}
	for _, extra := range []bool{false, true} {
		value := map[string]any{
			"nested": leaf(extra), "nullable": leaf(extra), "list": []any{leaf(extra)},
			"tuple": []any{leaf(extra), leaf(extra)}, "map": map[string]any{"k": leaf(extra)},
			"ref": leaf(extra), "all": leaf(extra), "any": leaf(extra), "cond": leaf(extra),
		}
		if extra {
			value["added"] = 1
		}
		if err := cached.Validate(wireEnvelope(t, value)); err != nil {
			t.Errorf("extra=%v: rejected: %v", extra, err)
		}
	}
	if cached.Validate(wireEnvelope(t, map[string]any{"nested": map[string]any{"x": 1}})) == nil {
		t.Error("a mistyped known field passed")
	}
}

// semanticCounterexamples are payloads where removing a closure is not a
// widening: each instance validates against the closed schema and would be
// rejected once the closure were removed. SchemaFor must refuse them.
var semanticCounterexamples = map[string]struct {
	data     func() *jsonschema.Schema
	instance string
	reason   string
}{
	"closure under not": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {Not: closedRecord("x")}}}
		},
		instance: `{"v":{"x":"ok","extra":true}}`,
		reason:   "under not",
	},
	"closure in an if condition": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {If: closedRecord("x"), Then: &jsonschema.Schema{Required: []string{"flag"}}}}}
		},
		instance: `{"v":{"x":"ok","extra":true}}`,
		reason:   "under if",
	},
	"oneOf branches that overlap once opened": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {OneOf: []*jsonschema.Schema{closedRecord("x"), closedRecord("x", "y")}}}}
		},
		instance: `{"v":{"x":"ok","y":"also"}}`,
		reason:   "under oneOf",
	},
	"shared definition used in a safe and an unsafe context": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{
				Properties: map[string]*jsonschema.Schema{"safe": payloadRef("leaf"), "v": {Not: payloadRef("leaf")}},
				Defs:       map[string]*jsonschema.Schema{"leaf": closedRecord("x")},
			}
		},
		instance: `{"safe":{"x":"ok"},"v":{"x":"ok","extra":true}}`,
		reason:   "under not",
	},
	"shared node used in a safe and an unsafe context": {
		data: func() *jsonschema.Schema {
			shared := closedRecord("x")
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"safe": shared, "v": {Not: shared}}}
		},
		instance: `{"safe":{"x":"ok"},"v":{"x":"ok","extra":true}}`,
		reason:   "under not",
	},
}

func TestSchemaForDataRejectsClosuresThatOpeningWouldNarrow(t *testing.T) {
	for name, tc := range semanticCounterexamples {
		t.Run(name, func(t *testing.T) {
			// The counterexample is real: valid when closed, invalid when the
			// closure is naively removed.
			original := tc.data()
			var payload map[string]any
			if err := json.Unmarshal([]byte(tc.instance), &payload); err != nil {
				t.Fatal(err)
			}
			instance := map[string]any{"untrusted_data": payload}
			if err := cachedSchema(t, wrapForTest(original)).Validate(instance); err != nil {
				t.Fatalf("instance is not valid against the closed schema, so the case proves nothing: %v", err)
			}
			naive := decodeJSON(t, wrapForTest(original))
			stripFalseAdditionalProperties(naive)
			if cachedSchemaJSON(t, []byte(mustJSON(t, naive))).Validate(instance) == nil {
				t.Fatal("naive opening still accepts the instance, so the case proves nothing")
			}

			before := mustJSON(t, original)
			_, err := SchemaForData(original, SchemaText{})
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("SchemaForData error = %v, want a refusal %q", err, tc.reason)
			}
			if mustJSON(t, original) != before {
				t.Fatal("SchemaForData modified the caller's schema")
			}
		})
	}
}

// wrapForTest places a payload schema at untrusted_data of a minimal
// document, without opening it, so its $refs resolve as they would once
// published.
func wrapForTest(data *jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"untrusted_data": data.CloneSchemas()}}
}

func TestOpenPayloadRefusesBeforeMutating(t *testing.T) {
	data := &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{
		"a": closedRecord("x"),
		"z": {Not: closedRecord("x")},
	}, AdditionalProperties: falseSchema()}
	before := mustJSON(t, data)
	if err := openPayload(data); err == nil {
		t.Fatal("openPayload accepted a closure under not")
	}
	if mustJSON(t, data) != before {
		t.Fatalf("a refused payload was partly opened:\nbefore: %s\nafter:  %s", before, mustJSON(t, data))
	}
}

func TestSchemaForDataRejectsOtherRecordRestrictions(t *testing.T) {
	two := 2
	cases := map[string]*jsonschema.Schema{
		"unevaluatedProperties false": {Type: "object", UnevaluatedProperties: falseSchema()},
		"unevaluatedProperties typed": {Type: "object", UnevaluatedProperties: &jsonschema.Schema{Type: "string"}},
		"propertyNames":               {Type: "object", PropertyNames: &jsonschema.Schema{Pattern: "^[a-z]+$"}},
		"maxProperties":               {Type: "object", MaxProperties: &two},
		"patternProperties":           {Type: "object", PatternProperties: map[string]*jsonschema.Schema{"^x": {Type: "string"}}},
		"dependentRequired":           {Type: "object", DependentRequired: map[string][]string{"a": {"b"}}},
		"dependentSchemas":            {Type: "object", DependentSchemas: map[string]*jsonschema.Schema{"a": {Required: []string{"b"}}}},
		"record with typed extras":    {Type: "object", Properties: map[string]*jsonschema.Schema{"x": {Type: "string"}}, AdditionalProperties: &jsonschema.Schema{Type: "string"}},
		"remote ref":                  {Ref: "https://example.com/schema"},
		"ref outside the payload":     {Ref: "#/properties/schema_version"},
		"unresolved ref":              {Ref: payloadPointer + "/$defs/missing"},
		"dynamic ref":                 {DynamicRef: "#meta"},
		"nested $id":                  {ID: "https://example.com/x"},
		"closure under contains":      {Type: "array", Contains: closedRecord("x")},
	}
	for name, restriction := range cases {
		t.Run(name, func(t *testing.T) {
			data := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{"v": restriction}}
			if _, err := SchemaForData(data, SchemaText{}); err == nil {
				t.Fatal("SchemaForData accepted a schema that can reject added properties or cannot be inspected")
			}
		})
	}
	// true is not a restriction.
	open := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{
		"v": {Type: "object", UnevaluatedProperties: &jsonschema.Schema{}, PropertyNames: &jsonschema.Schema{}},
	}}
	if _, err := SchemaForData(open, SchemaText{}); err != nil {
		t.Fatalf("true unevaluatedProperties/propertyNames refused: %v", err)
	}
}

// propertySensitivePredicates carry no closure at all, yet once the
// payload's own closure is removed, an added property makes a previously
// valid result invalid because a predicate in a non-monotone position (or a
// pinned object literal) sees the property set. valid and added are payload
// instances without and with one added property at the object the
// predicate inspects.
var propertySensitivePredicates = map[string]struct {
	data   func() *jsonschema.Schema
	valid  string
	added  string
	reason string
}{
	"if on property count (review round 1)": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Type: "object", AdditionalProperties: falseSchema(), If: &jsonschema.Schema{MinProperties: jsonschema.Ptr(1)}, Then: falseSchema()}
		},
		valid: `{}`, added: `{"added":true}`, reason: "minProperties under if",
	},
	"not on property count": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {Type: "object", Not: &jsonschema.Schema{MinProperties: jsonschema.Ptr(2)}}}}
		},
		valid: `{"v":{"a":1}}`, added: `{"v":{"a":1,"added":true}}`, reason: "minProperties under not",
	},
	"oneOf branch selected by required": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {Type: "object", OneOf: []*jsonschema.Schema{
				{Required: []string{"a"}}, {Required: []string{"added"}},
			}}}}
		},
		valid: `{"v":{"a":1}}`, added: `{"v":{"a":1,"added":true}}`, reason: "required under oneOf",
	},
	"$ref into a property-sensitive predicate": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{
				Properties: map[string]*jsonschema.Schema{"v": {Type: "object", If: payloadRef("selector"), Then: falseSchema()}},
				Defs:       map[string]*jsonschema.Schema{"selector": {Required: []string{"added"}}},
			}
		},
		valid: `{"v":{"a":1}}`, added: `{"v":{"a":1,"added":true}}`, reason: "required under if",
	},
	"contains counting objects by property": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {Type: "array", Items: &jsonschema.Schema{Type: "object"},
				Contains: &jsonschema.Schema{Required: []string{"added"}}, MinContains: jsonschema.Ptr(0), MaxContains: jsonschema.Ptr(0)}}}
		},
		valid: `{"v":[{"a":1}]}`, added: `{"v":[{"a":1,"added":true}]}`, reason: "required under contains",
	},
	"uniqueItems on an array of objects (review round 2)": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"rows": {Type: "array", Items: &jsonschema.Schema{Type: "object"}, UniqueItems: true}}}
		},
		valid: `{"rows":[{"id":1},{"id":1,"added":true}]}`, added: `{"rows":[{"id":1,"added":true},{"id":1,"added":true}]}`, reason: "uniqueItems",
	},
	"not uniqueItems (review round 2)": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{Type: "object", AdditionalProperties: falseSchema(), Properties: map[string]*jsonschema.Schema{
				"rows": {Type: "array", Items: &jsonschema.Schema{Type: "object"}, Not: &jsonschema.Schema{UniqueItems: true}},
			}}
		},
		valid: `{"rows":[{"id":1},{"id":1}]}`, added: `{"rows":[{"id":1,"added":true},{"id":1}]}`, reason: "uniqueItems",
	},
	"$ref into uniqueItems": {
		data: func() *jsonschema.Schema {
			return &jsonschema.Schema{
				Properties: map[string]*jsonschema.Schema{"rows": {Type: "array", Items: &jsonschema.Schema{Type: "object"}, Not: payloadRef("distinct")}},
				Defs:       map[string]*jsonschema.Schema{"distinct": {UniqueItems: true}},
			}
		},
		valid: `{"rows":[{"id":1},{"id":1}]}`, added: `{"rows":[{"id":1,"added":true},{"id":1}]}`, reason: "uniqueItems",
	},
	"const pinning an object": {
		data: func() *jsonschema.Schema {
			value := any(map[string]any{"a": 1})
			return &jsonschema.Schema{Properties: map[string]*jsonschema.Schema{"v": {Const: &value}}}
		},
		valid: `{"v":{"a":1}}`, added: `{"v":{"a":1,"added":true}}`, reason: "const pins an object",
	},
}

func TestSchemaForDataRejectsPropertySensitivePredicates(t *testing.T) {
	for name, tc := range propertySensitivePredicates {
		t.Run(name, func(t *testing.T) {
			original := tc.data()
			// The hole is real: with every closure naively removed, the
			// result without the addition validates and the one with it
			// does not.
			naive := decodeJSON(t, wrapForTest(original))
			stripFalseAdditionalProperties(naive)
			cached := cachedSchemaJSON(t, []byte(mustJSON(t, naive)))
			for instance, wantValid := range map[string]bool{tc.valid: true, tc.added: false} {
				var payload any
				if err := json.Unmarshal([]byte(instance), &payload); err != nil {
					t.Fatal(err)
				}
				if err := cached.Validate(map[string]any{"untrusted_data": payload}); (err == nil) != wantValid {
					t.Fatalf("naively opened schema: %s valid=%v, want %v, so the case proves nothing", instance, err == nil, wantValid)
				}
			}
			// The wire guard cannot certify the naively opened schema open.
			if paths, err := ClosedRecordPaths(naive); err != nil || len(paths) == 0 {
				t.Fatalf("ClosedRecordPaths certified a property-sensitive schema open (paths=%v err=%v)", paths, err)
			}

			before := mustJSON(t, original)
			_, err := SchemaForData(original, SchemaText{})
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("SchemaForData error = %v, want a refusal naming %q", err, tc.reason)
			}
			if mustJSON(t, original) != before {
				t.Fatal("SchemaForData modified the caller's schema")
			}
		})
	}
}

// TestSchemaForDataAcceptsPropertyInsensitivePredicates keeps the allowlist
// usable: predicates that cannot see an added property stay supported in
// every non-monotone position, and the result is certified open.
func TestSchemaForDataAcceptsPropertyInsensitivePredicates(t *testing.T) {
	str := any("x")
	data := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{
		"cond":  {If: &jsonschema.Schema{Type: "object"}, Then: closedRecord("x"), Else: closedRecord("y")},
		"not":   {Not: &jsonschema.Schema{Type: "string", Enum: []any{"a", "b"}}},
		"one":   {OneOf: []*jsonschema.Schema{{Type: "string", MaxLength: jsonschema.Ptr(3)}, {Type: "object"}}},
		"const": {Not: &jsonschema.Schema{Const: &str, Description: "never x"}},
		"list":  {Type: "array", Contains: &jsonschema.Schema{Type: "integer", Minimum: jsonschema.Ptr(1.0)}, MaxContains: jsonschema.Ptr(2)},
		"leaf":  closedRecord("x"),
	}, AdditionalProperties: falseSchema()}
	schema, err := SchemaForData(data, SchemaText{})
	if err != nil {
		t.Fatalf("SchemaForData refused property-insensitive predicates: %v", err)
	}
	if paths, err := ClosedRecordPaths(schema); err != nil || len(paths) != 0 {
		t.Fatalf("ClosedRecordPaths = %v, %v; want open", paths, err)
	}
	cached := cachedSchema(t, schema)
	value := map[string]any{"cond": map[string]any{"x": "v", "added": 1}, "one": map[string]any{"added": 1}, "leaf": map[string]any{"x": "v", "added": 1}, "added": 1}
	if err := cached.Validate(wireEnvelope(t, value)); err != nil {
		t.Fatalf("an added property was rejected: %v", err)
	}
}

// TestSchemaForDataRetainsUnrelatedFalseSchemas: only the record-closing
// additionalProperties false is removed. A forbidden property, a closed
// tuple and a false schema under not keep their meaning.
func TestSchemaForDataRetainsUnrelatedFalseSchemas(t *testing.T) {
	data := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{
		"forbidden": falseSchema(),
		"tuple":     {Type: "array", PrefixItems: []*jsonschema.Schema{{Type: "string"}}, Items: falseSchema()},
		"anything":  {Not: falseSchema()},
	}, AdditionalProperties: falseSchema()}
	schema, err := SchemaForData(data, SchemaText{})
	if err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, schema.Properties["untrusted_data"])
	for _, want := range []string{`"forbidden":false`, `"items":false`, `"not":false`} {
		if !strings.Contains(got, want) {
			t.Errorf("opened payload lost %s: %s", want, got)
		}
	}
	if strings.Contains(got, `"additionalProperties":false`) {
		t.Errorf("record closure survived: %s", got)
	}
	cached := cachedSchema(t, schema)
	if cached.Validate(wireEnvelope(t, map[string]any{"forbidden": 1})) == nil {
		t.Error("forbidden property accepted")
	}
	if cached.Validate(wireEnvelope(t, map[string]any{"tuple": []any{"a", "b"}})) == nil {
		t.Error("closed tuple accepted an extra item")
	}
}

// TestSchemaChildrenCoversEverySchemaValuedField enumerates jsonschema.Schema
// by reflection, so a schema-valued field added in a library upgrade fails
// here until schemaChildren classifies it. The expected kinds are an
// independent review of each keyword's polarity.
func TestSchemaChildrenCoversEverySchemaValuedField(t *testing.T) {
	want := map[string]childKind{
		"Properties": monotone, "Items": monotone, "ItemsArray": monotone, "PrefixItems": monotone,
		"AdditionalItems": monotone, "UnevaluatedItems": monotone, "AllOf": monotone, "AnyOf": monotone,
		"Then": monotone, "Else": monotone, "ContentSchema": monotone, "AdditionalProperties": monotone,
		"Defs": definition, "Definitions": definition,
		"Not": nonMonotone, "If": nonMonotone, "OneOf": nonMonotone, "Contains": nonMonotone,
		"PatternProperties": restricting, "PropertyNames": restricting, "UnevaluatedProperties": restricting,
		"DependencySchemas": restricting, "DependentSchemas": restricting,
	}
	schemaPtr := reflect.TypeFor[*jsonschema.Schema]()
	schemaSlice := reflect.TypeFor[[]*jsonschema.Schema]()
	schemaMap := reflect.TypeFor[map[string]*jsonschema.Schema]()
	seen := map[string]bool{}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[jsonschema.Schema]()) {
		parent := &jsonschema.Schema{}
		value := reflect.ValueOf(parent).Elem().FieldByIndex(field.Index)
		child := closedRecord("x")
		switch field.Type {
		case schemaPtr:
			value.Set(reflect.ValueOf(child))
		case schemaSlice:
			value.Set(reflect.ValueOf([]*jsonschema.Schema{child}))
		case schemaMap:
			value.Set(reflect.ValueOf(map[string]*jsonschema.Schema{"k": child}))
		default:
			continue
		}
		seen[field.Name] = true
		expected, reviewed := want[field.Name]
		if !reviewed {
			t.Errorf("jsonschema.Schema.%s is schema-valued but has no reviewed polarity", field.Name)
			continue
		}
		children := schemaChildren(parent)
		if len(children) != 1 || children[0].schema != child {
			t.Errorf("schemaChildren does not list jsonschema.Schema.%s exactly once: %+v", field.Name, children)
			continue
		}
		if children[0].kind != expected {
			t.Errorf("jsonschema.Schema.%s kind = %d, want %d", field.Name, children[0].kind, expected)
		}
		err := openPayload(parent)
		switch expected {
		case monotone, definition:
			if err != nil || child.AdditionalProperties != nil {
				t.Errorf("%s: err=%v, closure removed=%v; want opened", field.Name, err, child.AdditionalProperties == nil)
			}
		default:
			if err == nil || child.AdditionalProperties == nil {
				t.Errorf("%s: err=%v, closure removed=%v; want refused and untouched", field.Name, err, child.AdditionalProperties == nil)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("reviewed field %s no longer exists on jsonschema.Schema", name)
		}
	}
}

func TestOpenPayloadToleratesSharedAndCyclicNodes(t *testing.T) {
	shared := &jsonschema.Schema{Type: "object", AdditionalProperties: falseSchema()}
	cyclic := &jsonschema.Schema{Type: "object", AdditionalProperties: falseSchema()}
	cyclic.Properties = map[string]*jsonschema.Schema{"self": cyclic, "a": shared, "b": shared}
	if err := openPayload(cyclic); err != nil {
		t.Fatal(err)
	}
	if cyclic.AdditionalProperties != nil || shared.AdditionalProperties != nil {
		t.Fatal("shared or cyclic node left closed")
	}
}

func TestClosedRecordPathsFindsEveryClosureSpelling(t *testing.T) {
	cases := map[string]struct {
		schema string
		want   []string
	}{
		"root exempt":           {`{"type":"object","additionalProperties":false}`, nil},
		"literal false":         {`{"properties":{"a":{"type":"object","additionalProperties":false}}}`, []string{"/properties/a/additionalProperties"}},
		"not empty":             {`{"properties":{"a":{"additionalProperties":{"not":{}}}}}`, []string{"/properties/a/additionalProperties"}},
		"not true":              {`{"items":{"additionalProperties":{"not":true}}}`, []string{"/items/additionalProperties"}},
		"under not":             {`{"properties":{"a":{"not":{"additionalProperties":false}}}}`, []string{"/properties/a/not/additionalProperties"}},
		"unevaluated":           {`{"anyOf":[{"unevaluatedProperties":false}]}`, []string{"/anyOf/0/unevaluatedProperties"}},
		"unevaluated typed":     {`{"anyOf":[{"unevaluatedProperties":{"type":"string"}}]}`, []string{"/anyOf/0/unevaluatedProperties"}},
		"property names":        {`{"$defs":{"d":{"propertyNames":{"pattern":"^a"}}}}`, []string{"/$defs/d/propertyNames"}},
		"max properties":        {`{"properties":{"a/b":{"maxProperties":3}}}`, []string{"/properties/a~1b/maxProperties"}},
		"pattern properties":    {`{"properties":{"a":{"patternProperties":{"^x":{}}}}}`, []string{"/properties/a/patternProperties"}},
		"dependent required":    {`{"properties":{"a":{"dependentRequired":{"x":["y"]}}}}`, []string{"/properties/a/dependentRequired"}},
		"record typed extras":   {`{"properties":{"a":{"properties":{"x":{}},"additionalProperties":{"type":"string"}}}}`, []string{"/properties/a/additionalProperties"}},
		"remote ref":            {`{"properties":{"a":{"$ref":"https://example.com/s"}}}`, []string{"/properties/a/$ref"}},
		"dynamic ref":           {`{"properties":{"a":{"$dynamicRef":"#m"}}}`, []string{"/properties/a/$dynamicRef"}},
		"tuple items":           {`{"items":[{"additionalProperties":false}]}`, []string{"/items/0/additionalProperties"}},
		"map value":             {`{"additionalProperties":{"type":"object","additionalProperties":false}}`, []string{"/additionalProperties/additionalProperties"}},
		"dependencies":          {`{"properties":{"a":{"dependencies":{"b":["c"],"d":{"additionalProperties":false}}}}}`, []string{"/properties/a/dependencies", "/properties/a/dependencies/d/additionalProperties"}},
		"open map value":        {`{"properties":{"m":{"additionalProperties":{"type":"string"}}}}`, nil},
		"true additional":       {`{"properties":{"m":{"properties":{"x":{}},"additionalProperties":true}}}`, nil},
		"true unevaluated":      {`{"properties":{"m":{"unevaluatedProperties":true,"propertyNames":{}}}}`, nil},
		"property schema false": {`{"properties":{"never":false}}`, nil},
		"closed tuple items":    {`{"properties":{"t":{"prefixItems":[{}],"items":false}}}`, nil},
		"resolved local ref":    {`{"properties":{"untrusted_data":{"properties":{"a":{"$ref":"#/properties/untrusted_data/$defs/d"}},"$defs":{"d":{"type":"string"}}}}}`, nil},
		"unresolved local ref":  {`{"properties":{"a":{"$ref":"#/properties/untrusted_data/$defs/d"}}}`, []string{"/properties/a/$ref"}},
		"if minProperties":      {`{"properties":{"a":{"if":{"minProperties":1},"then":false}}}`, []string{"/properties/a/if/minProperties"}},
		"oneOf required":        {`{"properties":{"a":{"oneOf":[{"required":["x"]},{"required":["y"]}]}}}`, []string{"/properties/a/oneOf/0/required", "/properties/a/oneOf/1/required"}},
		"not via ref":           {`{"$defs":{"s":{"minProperties":2}},"properties":{"a":{"not":{"$ref":"#/$defs/s"}}}}`, []string{"/properties/a/not/$ref/minProperties"}},
		"contains properties":   {`{"properties":{"a":{"contains":{"properties":{"x":{"type":"string"}}}}}}`, []string{"/properties/a/contains/properties"}},
		"const object":          {`{"properties":{"a":{"const":{"k":1}}}}`, []string{"/properties/a/const"}},
		"enum with object":      {`{"properties":{"a":{"enum":["s",[{"k":1}]]}}}`, []string{"/properties/a/enum"}},
		"unique items":          {`{"properties":{"a":{"type":"array","uniqueItems":true}}}`, []string{"/properties/a/uniqueItems"}},
		"not unique items":      {`{"properties":{"a":{"not":{"uniqueItems":true}}}}`, []string{"/properties/a/not/uniqueItems"}},
		"unique items false":    {`{"properties":{"a":{"type":"array","uniqueItems":false}}}`, nil},
		"type-only predicates":  {`{"properties":{"a":{"if":{"type":"object"},"then":{"required":["x"]},"not":{"type":"string","enum":["x"]},"oneOf":[{"type":"string"},{"type":"object"}]}}}`, nil},
		"defs not in context":   {`{"$defs":{"s":{"minProperties":2}},"properties":{"a":{"$ref":"#/$defs/s"}}}`, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var schema any
			if err := json.Unmarshal([]byte(tc.schema), &schema); err != nil {
				t.Fatal(err)
			}
			got, err := ClosedRecordPaths(schema)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("paths = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAddedFieldsValidateAgainstCachedOpenedSchema is the additive-release
// regression: a
// client caches the v1 descriptor, the server starts returning v2 with a
// field added at every record location, and the cached validator still
// accepts the result, with every added field intact.
func TestAddedFieldsValidateAgainstCachedOpenedSchema(t *testing.T) {
	schema, err := SchemaFor[openFixtureV1](SchemaText{})
	if err != nil {
		t.Fatal(err)
	}
	cached := cachedSchema(t, schema)
	instance := wireEnvelope(t, openFixtureV2Value())
	if err := cached.Validate(instance); err != nil {
		t.Fatalf("v2 result rejected by the cached v1 schema: %v", err)
	}

	if instance["event_id"] != "signed-token" {
		t.Errorf("root event_id = %v", instance["event_id"])
	}
	data := instance["untrusted_data"].(map[string]any)
	if _, leaked := data["event_id"]; leaked {
		t.Error("event_id leaked below untrusted_data")
	}
	object := func(v any) map[string]any { return v.(map[string]any) }
	first := func(v any) map[string]any { return v.([]any)[0].(map[string]any) }
	for where, value := range map[string]any{
		"top_added":         data["top_added"],
		"promoted":          data["promoted"],
		"nested.added":      object(data["nested"])["added"],
		"list[0].added":     first(data["list"])["added"],
		"pair[0].added":     first(data["pair"])["added"],
		"pointer.added":     object(data["pointer"])["added"],
		"by_name.k.added":   object(object(data["by_name"])["k"])["added"],
		"groups.g[0].added": first(object(data["groups"])["g"])["added"],
	} {
		if value == nil {
			t.Errorf("added field %s was not carried in the result", where)
		}
	}
}

// TestCachedOpenedSchemaStillRejectsRootAndKnownFieldViolations keeps the
// opened schema useful: it validates the envelope and every known field.
func TestCachedOpenedSchemaStillRejectsRootAndKnownFieldViolations(t *testing.T) {
	schema, err := SchemaFor[openFixtureV1](SchemaText{})
	if err != nil {
		t.Fatal(err)
	}
	cached := cachedSchema(t, schema)
	cases := map[string]func(root, data map[string]any){
		"extra root property":      func(root, _ map[string]any) { root["instructions"] = "x" },
		"wrong schema_version":     func(root, _ map[string]any) { root["schema_version"] = 3 },
		"missing schema_version":   func(root, _ map[string]any) { delete(root, "schema_version") },
		"missing untrusted_data":   func(root, _ map[string]any) { delete(root, "untrusted_data") },
		"missing required eventID": func(root, _ map[string]any) { delete(root, "event_id") },
		"non-string event_id":      func(root, _ map[string]any) { root["event_id"] = 1 },
		"wrong known type":         func(_, data map[string]any) { data["count"] = "one" },
		"wrong nested known type":  func(_, data map[string]any) { data["nested"].(map[string]any)["name"] = 1 },
		"missing required field":   func(_, data map[string]any) { delete(data, "state") },
		"missing nested required":  func(_, data map[string]any) { delete(data["list"].([]any)[0].(map[string]any), "name") },
		"wrong map value type":     func(_, data map[string]any) { data["flags"].(map[string]any)["f"] = "yes" },
		"wrong typed map value":    func(_, data map[string]any) { data["by_name"].(map[string]any)["k"] = "leaf" },
		"array arity":              func(_, data map[string]any) { data["pair"] = data["pair"].([]any)[:1] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			instance := wireEnvelope(t, openFixtureV2Value())
			mutate(instance, instance["untrusted_data"].(map[string]any))
			if cached.Validate(instance) == nil {
				t.Fatal("violation accepted by the opened schema")
			}
		})
	}
}

// preFixClosedSchema is the frozen descriptor a server published before
// opening, for
// openFixtureV1's top level and its nested record: closed at every level. It
// is deliberately a literal, not computed, so no change to SchemaFor can
// rewrite what an already-connected client holds.
const preFixClosedSchema = `{
  "type": "object",
  "required": ["schema_version", "untrusted_data", "event_id"],
  "additionalProperties": false,
  "properties": {
    "schema_version": {"type": "integer", "const": 2},
    "event_id": {"type": "string"},
    "untrusted_data": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "inherited": {"type": "string"},
        "state": {"type": "string"},
        "count": {"type": "integer"},
        "nested": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {"name": {"type": "string"}}
        },
        "list": {"type": ["null", "array"]},
        "pair": {"type": "array"},
        "pointer": {"type": ["null", "object"]},
        "by_name": {"type": "object"},
        "groups": {"type": "object"},
        "flags": {"type": "object"},
        "optional": {"type": "string"}
      }
    }
  }
}`

// TestPreFixClosedSchemaStillRejectsAdditions is the negative migration test:
// opening the descriptor the server publishes does nothing for a schema a
// client cached before the fix. Such a session must re-list once. Never turn
// this into a passing case.
func TestPreFixClosedSchemaStillRejectsAdditions(t *testing.T) {
	frozen := cachedSchemaJSON(t, []byte(preFixClosedSchema))
	v1 := func() openFixtureV1 {
		leaf := openLeafV1{Name: "n"}
		return openFixtureV1{
			EventID: "signed-token", openEmbeddedV1: openEmbeddedV1{Inherited: "i"}, State: "ok",
			Nested: leaf, List: []openLeafV1{leaf}, Pointer: &leaf,
			ByName: map[string]openLeafV1{}, Groups: map[string][]openLeafV1{}, Flags: map[string]bool{},
		}
	}
	if err := frozen.Validate(wireEnvelope(t, v1())); err != nil {
		t.Fatalf("frozen fixture rejects its own era's output, so it proves nothing: %v", err)
	}
	for name, mutate := range map[string]func(data map[string]any){
		"top-level addition": func(data map[string]any) { data["top_added"] = 1 },
		"nested addition":    func(data map[string]any) { data["nested"].(map[string]any)["added"] = "x" },
	} {
		t.Run(name, func(t *testing.T) {
			instance := wireEnvelope(t, v1())
			mutate(instance["untrusted_data"].(map[string]any))
			if frozen.Validate(instance) == nil {
				t.Fatal("a pre-fix closed schema accepted an added field; the migration boundary is misdescribed")
			}
		})
	}
	if frozen.Validate(wireEnvelope(t, openFixtureV2Value())) == nil {
		t.Fatal("a pre-fix closed schema accepted the v2 result")
	}
}

func decodeJSON(t *testing.T, v any) any {
	t.Helper()
	var out any
	if err := json.Unmarshal([]byte(mustJSON(t, v)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// stripFalseAdditionalProperties deletes every "additionalProperties": false
// from a decoded schema, wherever it occurs.
func stripFalseAdditionalProperties(node any) {
	switch v := node.(type) {
	case map[string]any:
		if b, ok := v["additionalProperties"].(bool); ok && !b {
			delete(v, "additionalProperties")
		}
		for _, child := range v {
			stripFalseAdditionalProperties(child)
		}
	case []any:
		for _, child := range v {
			stripFalseAdditionalProperties(child)
		}
	}
}
