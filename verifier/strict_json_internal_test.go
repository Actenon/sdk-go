package verifier

import "testing"

func TestRejectUnpairedSurrogateEscapes(t *testing.T) {
	accepted := []string{
		`{"a":"\ud83d\ude00"}`,
		`{"a":"\\ud800"}`,
		`{"a":"\u0041\""}`,
		`{"a":"plain"}`,
	}
	for _, raw := range accepted {
		if err := rejectUnpairedSurrogateEscapes([]byte(raw)); err != nil {
			t.Fatalf("%s: unexpected error %v", raw, err)
		}
	}
	refused := []string{
		`{"a":"\ud800"}`,
		`{"a":"\udc00"}`,
		`{"a":"\ud800\u0041"}`,
		`{"\ud800":1}`,
		`{"a":"x\ud83d"}`,
	}
	for _, raw := range refused {
		if err := rejectUnpairedSurrogateEscapes([]byte(raw)); err == nil {
			t.Fatalf("%s: expected refusal", raw)
		}
	}
}

func TestDecodeStrictJSONRefusesAmbiguousDocuments(t *testing.T) {
	type inner struct {
		Name string `json:"name"`
	}
	type document struct {
		Audience inner          `json:"audience"`
		Items    []string       `json:"items"`
		Extra    map[string]any `json:"extra"`
		Flag     bool           `json:"flag"`
		Label    string         `json:"label,omitempty"`
	}
	options := strictJSONOptions{rejectNullContainers: true, rejectEmptyOptionalStrings: true}
	var target document
	if err := decodeStrictJSON([]byte(`{"audience":{"name":"a"},"items":["x"],"extra":{"k":null},"flag":true,"label":"l","unknown":1}`), &target, options); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, raw := range []string{
		`{"audience":{"name":"a"},"audience":{"name":"b"}}`,
		`{"Audience":{"name":"a"}}`,
		`{"audience":{"NAME":"a"}}`,
		`{"items":null}`,
		`{"items":[null]}`,
		`{"extra":null}`,
		`{"flag":null}`,
		`{"audience":null}`,
		`{"label":""}`,
		`{"extra":{"k":1,"k":2}}`,
		`{} {}`,
		"{\"label\":\"\xff\"}",
	} {
		if err := decodeStrictJSON([]byte(raw), &target, options); err == nil {
			t.Fatalf("%s: expected refusal", raw)
		}
	}
}
