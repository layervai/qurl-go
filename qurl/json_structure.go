package qurl

import (
	"bytes"
	"encoding/json"
	"io"
)

// Negative limits disable that limit; the root value has depth zero.
type jsonStructurePolicy struct {
	requireObject     bool
	numbersAsText     bool
	maxContainerDepth int
	maxValueDepth     int
	rejectRootNull    bool
	allowedRootFields map[string]struct{}
}

type jsonStructureKind uint8

const (
	jsonStructureSyntax jsonStructureKind = iota
	jsonStructureNotObject
	jsonStructureKey
	jsonStructureUnknown
	jsonStructureDuplicate
	jsonStructureNull
	jsonStructureDepth
	jsonStructureObjectEnd
	jsonStructureArrayEnd
	jsonStructureDelimiter
	jsonStructureTrailing
)

type jsonStructureError struct {
	kind  jsonStructureKind
	key   string
	cause error
	more  bool
}

func (e *jsonStructureError) Error() string { return "invalid JSON structure" }
func (e *jsonStructureError) Unwrap() error { return e.cause }

type jsonStructureWalker struct {
	decoder *json.Decoder
	policy  jsonStructurePolicy
}

// walkJSONStructure owns token traversal only. Callers retain typed decoding,
// required-field checks, and their existing error vocabularies.
func walkJSONStructure(raw []byte, policy jsonStructurePolicy) (map[string]struct{}, *jsonStructureError) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if policy.numbersAsText {
		decoder.UseNumber()
	}
	walker := jsonStructureWalker{decoder: decoder, policy: policy}
	fields, err := walker.value(0, "")
	if err != nil {
		return nil, err
	}
	more := decoder.More()
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &jsonStructureError{kind: jsonStructureTrailing, more: more}
	}
	return fields, nil
}

func (w *jsonStructureWalker) value(depth int, key string) (map[string]struct{}, *jsonStructureError) {
	if w.policy.maxValueDepth >= 0 && depth > w.policy.maxValueDepth {
		return nil, &jsonStructureError{kind: jsonStructureDepth}
	}
	token, err := w.decoder.Token()
	if err != nil {
		return nil, &jsonStructureError{kind: jsonStructureSyntax, cause: err}
	}
	delimiter, container := token.(json.Delim)
	if depth == 0 && w.policy.requireObject && (!container || delimiter != '{') {
		return nil, &jsonStructureError{kind: jsonStructureNotObject}
	}
	if !container {
		if token == nil && depth == 1 && w.policy.rejectRootNull {
			return nil, &jsonStructureError{kind: jsonStructureNull, key: key}
		}
		return nil, nil
	}
	if w.policy.maxContainerDepth >= 0 && depth > w.policy.maxContainerDepth {
		return nil, &jsonStructureError{kind: jsonStructureDepth}
	}
	// Unbounded profiles drain nested values iteratively; recursion always has a limit.
	if depth > 0 && (delimiter == '{' || delimiter == '[') && w.policy.maxContainerDepth < 0 && w.policy.maxValueDepth < 0 {
		return nil, w.drainContainer()
	}
	switch delimiter {
	case '{':
		return w.object(depth)
	case '[':
		for w.decoder.More() {
			if _, err := w.value(depth+1, ""); err != nil {
				return nil, err
			}
		}
		end, err := w.decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, &jsonStructureError{kind: jsonStructureArrayEnd, cause: err}
		}
		return nil, nil
	default:
		return nil, &jsonStructureError{kind: jsonStructureDelimiter}
	}
}

func (w *jsonStructureWalker) object(depth int) (map[string]struct{}, *jsonStructureError) {
	seen := make(map[string]struct{})
	for w.decoder.More() {
		token, err := w.decoder.Token()
		if err != nil {
			return nil, &jsonStructureError{kind: jsonStructureSyntax, cause: err}
		}
		key, ok := token.(string)
		if !ok {
			return nil, &jsonStructureError{kind: jsonStructureKey}
		}
		if depth == 0 && w.policy.allowedRootFields != nil {
			if _, allowed := w.policy.allowedRootFields[key]; !allowed {
				return nil, &jsonStructureError{kind: jsonStructureUnknown, key: key}
			}
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, &jsonStructureError{kind: jsonStructureDuplicate, key: key}
		}
		seen[key] = struct{}{}
		if _, err := w.value(depth+1, key); err != nil {
			return nil, err
		}
	}
	end, err := w.decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, &jsonStructureError{kind: jsonStructureObjectEnd, cause: err}
	}
	return seen, nil
}

func (w *jsonStructureWalker) drainContainer() *jsonStructureError {
	depth := 1
	for depth > 0 {
		token, err := w.decoder.Token()
		if err != nil {
			return &jsonStructureError{kind: jsonStructureSyntax, cause: err}
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
		}
	}
	return nil
}
