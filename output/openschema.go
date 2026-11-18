package output

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// Published output schemas are open below the envelope root.
//
// jsonschema.For closes every inferred struct with additionalProperties
// false. A client that validates structuredContent against the outputSchema
// it cached at tools/list then rejects any result carrying a field added
// after it connected, and with tools.listChanged=false nothing tells it to
// re-list: one additive release breaks every session that outlives the
// deploy, while the server logs the calls as completed.
//
// openPayload therefore removes additionalProperties false from every record
// object in the payload subtree, so an optional field added later validates
// against a schema cached earlier. It keeps everything else: types, enums,
// consts, required lists, descriptions, unrelated false schemas, and the
// value schema of a typed map (a map[string]Summary already admits new keys;
// its value schema is kept and opened recursively). The envelope root stays
// closed and schema_version stays const 2, because the root is the trust
// delimiter and changes there are deliberate contract versions. Unknown
// payload fields remain untrusted data, normalized and bounded by Wrap like
// every known one; opening the descriptor grants a handler nothing.
//
// Removing a closure only widens a schema where the closed object sits in a
// monotone position. Under not, in an if condition, in a oneOf branch or in
// contains, opening can make a previously valid result invalid (a not that
// matched nothing now matches, an if switches branch, two oneOf branches
// both match). The same positions also break additivity with no closure at
// all, when the predicate there sees the property set ({"if":
// {"minProperties":1},"then":false} rejects any object that gains a
// property). openPayload supports exactly the vocabulary the inference
// produces plus the monotone combinators, allows only property-insensitive
// predicates in non-monotone positions (objectSensitiveKeyword), checks the
// whole graph before it changes anything, and rejects anything else with an
// error naming the location. Supporting a new composition needs a reviewed
// transformation and semantic tests, not a wider walker.
//
// Opening a schema cannot reach a closed schema a client already cached:
// such a session needs one re-list after the release that opened it.

// payloadPointer is where the payload schema sits in the published envelope,
// and therefore the prefix every local $ref inside it must carry.
const payloadPointer = "#/properties/untrusted_data"

// childKind says how widening a child schema affects its parent.
type childKind int

const (
	// monotone: a wider child can only make the parent wider.
	monotone childKind = iota
	// definition: applied only where a $ref uses it.
	definition
	// nonMonotone: a wider child can make the parent narrower.
	nonMonotone
	// restricting: a keyword whose presence can reject an added property.
	restricting
)

type schemaChild struct {
	schema *jsonschema.Schema
	loc    string
	kind   childKind
}

// schemaChildren lists every schema-valued field of s with its kind.
// TestSchemaChildrenCoversEverySchemaValuedField fails when a library
// upgrade adds a field this table does not classify.
func schemaChildren(s *jsonschema.Schema) []schemaChild {
	var out []schemaChild
	one := func(child *jsonschema.Schema, loc string, kind childKind) {
		if child != nil {
			out = append(out, schemaChild{child, loc, kind})
		}
	}
	list := func(children []*jsonschema.Schema, loc string, kind childKind) {
		for i, child := range children {
			one(child, fmt.Sprintf("%s/%d", loc, i), kind)
		}
	}
	dict := func(children map[string]*jsonschema.Schema, loc string, kind childKind) {
		for _, name := range slices.Sorted(maps.Keys(children)) {
			one(children[name], loc+"/"+escapePointer(name), kind)
		}
	}

	dict(s.Properties, "properties", monotone)
	one(s.Items, "items", monotone)
	list(s.ItemsArray, "items", monotone)
	list(s.PrefixItems, "prefixItems", monotone)
	one(s.AdditionalItems, "additionalItems", monotone)
	one(s.UnevaluatedItems, "unevaluatedItems", monotone)
	list(s.AllOf, "allOf", monotone)
	list(s.AnyOf, "anyOf", monotone)
	one(s.Then, "then", monotone)
	one(s.Else, "else", monotone)
	one(s.ContentSchema, "contentSchema", monotone)
	if s.AdditionalProperties != nil && !isFalseSchema(s.AdditionalProperties) {
		// A typed map's value schema; on a record with named properties the
		// same keyword constrains every added property instead.
		kind := monotone
		if len(s.Properties) > 0 {
			kind = restricting
		}
		one(s.AdditionalProperties, "additionalProperties", kind)
	}
	dict(s.Defs, "$defs", definition)
	dict(s.Definitions, "definitions", definition)
	one(s.Not, "not", nonMonotone)
	one(s.If, "if", nonMonotone)
	list(s.OneOf, "oneOf", nonMonotone)
	one(s.Contains, "contains", nonMonotone)
	dict(s.PatternProperties, "patternProperties", restricting)
	one(s.PropertyNames, "propertyNames", restricting)
	one(s.UnevaluatedProperties, "unevaluatedProperties", restricting)
	dict(s.DependencySchemas, "dependencies", restricting)
	dict(s.DependentSchemas, "dependentSchemas", restricting)
	return out
}

// openPayload opens data, which the caller owns, in place. It checks the
// whole graph first and returns an error, leaving data unchanged, when a
// closure sits where removing it is not a pure widening or when a constraint
// other than additionalProperties false could reject an added property.
func openPayload(data *jsonschema.Schema) error {
	p := &preflight{root: data, seen: map[preflightKey]bool{}}
	if err := p.check(data, payloadPointer, ""); err != nil {
		return err
	}
	removeRecordClosure(data, map[*jsonschema.Schema]bool{})
	return nil
}

type preflightKey struct {
	node   *jsonschema.Schema
	unsafe bool
}

type preflight struct {
	root *jsonschema.Schema
	seen map[preflightKey]bool
}

// check visits node once per context: a node reached both in a monotone
// position and under a non-monotone keyword is checked in both, so a
// visited set cannot hide its unsafe use. unsafe names the nearest
// non-monotone keyword above node, or is empty.
func (p *preflight) check(node *jsonschema.Schema, path, unsafe string) error {
	key := preflightKey{node, unsafe != ""}
	if p.seen[key] {
		return nil
	}
	p.seen[key] = true

	if isFalseSchema(node.AdditionalProperties) && unsafe != "" {
		return fmt.Errorf("output schema %s: additionalProperties false under %s cannot be opened without changing which results validate", path, unsafe)
	}
	if unsafe != "" {
		if keyword := objectSensitiveKeyword(node); keyword != "" {
			return fmt.Errorf("output schema %s: %s under %s depends on which properties an object has, so an added property can change which results validate", path, keyword, unsafe)
		}
	}
	if keyword := objectValuedLiteral(node); keyword != "" {
		return fmt.Errorf("output schema %s: %s pins an object value, which rejects an added property", path, keyword)
	}
	if node.UniqueItems {
		// uniqueItems compares whole elements, object properties included:
		// adding a property to one of two equal elements changes the verdict,
		// in an ordinary position as much as under not.
		return fmt.Errorf("output schema %s: uniqueItems compares whole elements, so an added property can change which results validate", path)
	}
	switch {
	case node.MaxProperties != nil:
		return fmt.Errorf("output schema %s: maxProperties would reject added properties", path)
	case len(node.DependentRequired) > 0 || len(node.DependencyStrings) > 0:
		return fmt.Errorf("output schema %s: property dependencies can reject added properties", path)
	case node.DynamicRef != "" || node.ID != "" || node.Anchor != "" || node.DynamicAnchor != "":
		return fmt.Errorf("output schema %s: $id, anchors and $dynamicRef are not supported in output schemas", path)
	}
	if node.Ref != "" {
		target, err := p.resolve(node.Ref)
		if err != nil {
			return fmt.Errorf("output schema %s: %w", path, err)
		}
		if err := p.check(target, path+"/$ref", unsafe); err != nil {
			return err
		}
	}
	for _, child := range schemaChildren(node) {
		childPath, childUnsafe := path+"/"+child.loc, unsafe
		switch child.kind {
		case definition:
			childUnsafe = ""
		case nonMonotone:
			if childUnsafe == "" {
				childUnsafe, _, _ = strings.Cut(child.loc, "/")
			}
		case restricting:
			if !isTrueSchema(child.schema) {
				return fmt.Errorf("output schema %s: %s can reject added properties", childPath, child.loc)
			}
		}
		if err := p.check(child.schema, childPath, childUnsafe); err != nil {
			return err
		}
	}
	return nil
}

// objectSensitiveKeyword names the first keyword on s whose outcome can
// change when a property is added to an object instance, or returns "".
//
// Under a non-monotone keyword (the subschema of not, an if condition, a
// oneOf branch, contains) such a keyword makes the parent's verdict depend
// on the property set even with no closure in sight: {"if":
// {"minProperties":1},"then":false} rejects every object that gains a
// property. V1 does not analyse which of these are harmless; it allows only
// predicates built from keywords that cannot see an added property (type,
// const/enum on non-object values, string, number and array keywords,
// annotations, and nested schemas that obey the same rule) and refuses the
// rest.
func objectSensitiveKeyword(s *jsonschema.Schema) string {
	switch {
	case len(s.Required) > 0:
		return "required"
	case len(s.Properties) > 0:
		return "properties"
	case len(s.PatternProperties) > 0:
		return "patternProperties"
	case s.AdditionalProperties != nil:
		return "additionalProperties"
	case s.UnevaluatedProperties != nil:
		return "unevaluatedProperties"
	case s.MinProperties != nil:
		return "minProperties"
	case s.MaxProperties != nil:
		return "maxProperties"
	case s.PropertyNames != nil:
		return "propertyNames"
	case len(s.DependentRequired) > 0 || len(s.DependencyStrings) > 0 || len(s.DependencySchemas) > 0:
		return "dependencies"
	case len(s.DependentSchemas) > 0:
		return "dependentSchemas"
	}
	return ""
}

// objectValuedLiteral names const or enum when either pins a value that
// contains a JSON object: equality then fails as soon as that object gains a
// property, in any position.
func objectValuedLiteral(s *jsonschema.Schema) string {
	if s.Const != nil && containsJSONObject(*s.Const) {
		return "const"
	}
	for _, value := range s.Enum {
		if containsJSONObject(value) {
			return "enum"
		}
	}
	return ""
}

func containsJSONObject(value any) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return true
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return true
	}
	return hasObject(decoded)
}

func hasObject(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		return true
	case []any:
		for _, item := range v {
			if hasObject(item) {
				return true
			}
		}
	}
	return false
}

// resolve supports the one local reference form a hand-built payload schema
// needs: a definition at the payload root.
func (p *preflight) resolve(ref string) (*jsonschema.Schema, error) {
	rest, ok := strings.CutPrefix(ref, payloadPointer+"/")
	if !ok {
		return nil, fmt.Errorf("$ref %q is not a local definition under %s", ref, payloadPointer)
	}
	container, name, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(name, "/") || strings.Contains(name, "~") {
		return nil, fmt.Errorf("$ref %q is not a payload-root definition", ref)
	}
	var target *jsonschema.Schema
	switch container {
	case "$defs":
		target = p.root.Defs[name]
	case "definitions":
		target = p.root.Definitions[name]
	}
	if target == nil {
		return nil, fmt.Errorf("$ref %q does not resolve to a payload-root definition", ref)
	}
	return target, nil
}

// removeRecordClosure deletes every additionalProperties false reachable
// from s. It runs only after the preflight proved each one sits in a
// monotone position, and touches no other keyword.
func removeRecordClosure(s *jsonschema.Schema, visited map[*jsonschema.Schema]bool) {
	if visited[s] {
		return
	}
	visited[s] = true
	if isFalseSchema(s.AdditionalProperties) {
		s.AdditionalProperties = nil
	}
	for _, child := range schemaChildren(s) {
		removeRecordClosure(child.schema, visited)
	}
}

// isFalseSchema reports whether s is the schema that admits nothing. The
// library spells it {"not":{}} in Go and marshals it as the literal false.
func isFalseSchema(s *jsonschema.Schema) bool {
	return marshalsAs(s, "false")
}

// isTrueSchema reports whether s is the schema that admits everything.
func isTrueSchema(s *jsonschema.Schema) bool {
	return marshalsAs(s, "true")
}

func marshalsAs(s *jsonschema.Schema, literal string) bool {
	if s == nil {
		return false
	}
	raw, err := json.Marshal(s)
	return err == nil && string(raw) == literal
}

// ClosedRecordPaths reports every location below the root of schema where
// a constraint could reject a property added to an object, as
// JSON-pointer-like paths. It accepts a *jsonschema.Schema or the decoded
// JSON a client receives from tools/list, and inspects the marshalled form,
// so both the literal false and the {"not":{}} spelling are caught.
//
// Reported anywhere below the root: a false additionalProperties; a
// schema-valued additionalProperties beside named properties; any non-true
// unevaluatedProperties or propertyNames; maxProperties; patternProperties;
// dependentRequired, dependentSchemas and dependencies; const or enum
// pinning an object value; uniqueItems true, which compares whole elements;
// and $dynamicRef or a local $ref that does not
// resolve or a non-local one, whose target cannot be inspected. Inside the
// subschema of not, an if condition, a oneOf branch or contains (followed
// through local $refs), every object-sensitive keyword is reported too,
// because there it can make the parent reject an added property without any
// closure (objectSensitiveKeyword). The root itself is exempt: the schema-v2
// envelope root is closed on purpose. The result is sorted; nil means no
// object below the root can reject an added property.
func ClosedRecordPaths(schema any) ([]string, error) {
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("marshal schema: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode schema: %w", err)
	}
	w := &schemaWalk{doc: decoded, reported: map[string]bool{}, seenRefs: map[string]bool{}}
	w.walk(decoded, "", true, false)
	slices.Sort(w.paths)
	return w.paths, nil
}

// Schema-valued keywords of JSON Schema 2020-12, plus the draft-07
// definitions/dependencies/items-array forms the library also emits.
// nonMonotoneKeywords are the ones whose subschema is evaluated as a
// predicate rather than a constraint on the instance.
var (
	singleSchemaKeywords = []string{
		"additionalProperties", "unevaluatedProperties", "propertyNames",
		"items", "additionalItems", "contains", "unevaluatedItems",
		"not", "if", "then", "else", "contentSchema",
	}
	schemaListKeywords  = []string{"prefixItems", "items", "allOf", "anyOf", "oneOf"}
	schemaMapKeywords   = []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
	nonMonotoneKeywords = map[string]bool{"not": true, "if": true, "oneOf": true, "contains": true}
	// objectSensitiveJSONKeywords mirrors objectSensitiveKeyword for the
	// wire form.
	objectSensitiveJSONKeywords = []string{
		"required", "properties", "patternProperties", "additionalProperties",
		"unevaluatedProperties", "minProperties", "maxProperties", "propertyNames",
		"dependentRequired", "dependentSchemas", "dependencies",
	}
)

type schemaWalk struct {
	doc      any
	paths    []string
	reported map[string]bool
	seenRefs map[string]bool
}

func (w *schemaWalk) report(path string) {
	if !w.reported[path] {
		w.reported[path] = true
		w.paths = append(w.paths, path)
	}
}

func (w *schemaWalk) walk(node any, path string, root, unsafe bool) {
	obj, ok := node.(map[string]any)
	if !ok {
		// true/false schemas have no children; a false schema in a closing
		// keyword is reported by its parent below.
		return
	}
	if !root {
		if additional, present := obj["additionalProperties"]; present {
			_, named := obj["properties"].(map[string]any)
			if isFalseJSON(additional) || (named && additional != true && !isEmptyObject(additional)) {
				w.report(path + "/additionalProperties")
			}
		}
		for _, keyword := range []string{"unevaluatedProperties", "propertyNames"} {
			if value, present := obj[keyword]; present && value != true && !isEmptyObject(value) {
				w.report(path + "/" + keyword)
			}
		}
		for _, keyword := range []string{"maxProperties", "patternProperties", "dependentRequired", "dependentSchemas", "dependencies"} {
			if _, present := obj[keyword]; present {
				w.report(path + "/" + keyword)
			}
		}
		if value, present := obj["const"]; present && hasObject(value) {
			w.report(path + "/const")
		}
		if values, present := obj["enum"].([]any); present && hasObject(values) {
			w.report(path + "/enum")
		}
		if obj["uniqueItems"] == true {
			w.report(path + "/uniqueItems")
		}
		if unsafe {
			for _, keyword := range objectSensitiveJSONKeywords {
				if value, present := obj[keyword]; present && !isEmptyContainer(keyword, value) {
					w.report(path + "/" + keyword)
				}
			}
		}
	}
	if ref, present := obj["$ref"].(string); present {
		w.followRef(ref, path, unsafe)
	}
	if _, present := obj["$dynamicRef"]; present {
		w.report(path + "/$dynamicRef")
	}
	childUnsafe := func(keyword string) bool { return unsafe || nonMonotoneKeywords[keyword] }
	for _, keyword := range singleSchemaKeywords {
		if child, present := obj[keyword].(map[string]any); present {
			w.walk(child, path+"/"+keyword, false, childUnsafe(keyword))
		}
	}
	for _, keyword := range schemaListKeywords {
		if list, present := obj[keyword].([]any); present {
			for i, child := range list {
				w.walk(child, fmt.Sprintf("%s/%s/%d", path, keyword, i), false, childUnsafe(keyword))
			}
		}
	}
	for _, keyword := range schemaMapKeywords {
		if m, present := obj[keyword].(map[string]any); present {
			// Definitions apply only through a $ref, which carries its own
			// context; every other map keyword inherits this one.
			mapUnsafe := unsafe && keyword != "$defs" && keyword != "definitions"
			for name, child := range m {
				// dependencies may map to a string list (dependentRequired's
				// draft-07 spelling), which is not a schema.
				w.walk(child, path+"/"+keyword+"/"+escapePointer(name), false, mapUnsafe)
			}
		}
	}
}

// followRef reports a $ref whose target cannot be inspected, and walks a
// resolvable local target in the context of this use. Safe-context targets
// are inside the document and walked where they are defined.
func (w *schemaWalk) followRef(ref, path string, unsafe bool) {
	if !strings.HasPrefix(ref, "#") {
		w.report(path + "/$ref")
		return
	}
	target, ok := resolveJSONPointer(w.doc, strings.TrimPrefix(ref, "#"))
	if !ok {
		w.report(path + "/$ref")
		return
	}
	if !unsafe {
		return
	}
	key := ref
	if w.seenRefs[key] {
		return
	}
	w.seenRefs[key] = true
	w.walk(target, path+"/$ref", false, true)
}

func resolveJSONPointer(doc any, pointer string) (any, bool) {
	if pointer == "" {
		return doc, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	node := doc
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.NewReplacer("~1", "/", "~0", "~").Replace(token)
		switch v := node.(type) {
		case map[string]any:
			next, ok := v[token]
			if !ok {
				return nil, false
			}
			node = next
		case []any:
			var i int
			if _, err := fmt.Sscanf(token, "%d", &i); err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			node = v[i]
		default:
			return nil, false
		}
	}
	return node, true
}

// isEmptyContainer treats an empty required list or properties map as
// absent; neither can see an added property.
func isEmptyContainer(keyword string, value any) bool {
	switch v := value.(type) {
	case []any:
		return keyword == "required" && len(v) == 0
	case map[string]any:
		return (keyword == "properties" || keyword == "patternProperties" || keyword == "dependentSchemas" || keyword == "dependentRequired" || keyword == "dependencies") && len(v) == 0
	}
	return false
}

func isFalseJSON(value any) bool {
	if b, ok := value.(bool); ok {
		return !b
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != 1 {
		return false
	}
	switch not := obj["not"].(type) {
	case bool:
		return not
	case map[string]any:
		return len(not) == 0
	}
	return false
}

func isEmptyObject(value any) bool {
	obj, ok := value.(map[string]any)
	return ok && len(obj) == 0
}

func escapePointer(token string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}
