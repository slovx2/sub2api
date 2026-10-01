package modeltrace

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
)

func TestPythonParity(t *testing.T) {
	raw, err := os.ReadFile("parity_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Outputs    []Output    `json:"outputs"`
		Candidates []Candidate `json:"candidates"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for i, f := range fixtures {
		score, err := Analyze(f.Outputs)
		if err != nil {
			t.Fatal(err)
		}
		for j, c := range f.Candidates {
			actual := score.Candidates[j]
			if actual.Model != c.Model || math.Abs(actual.Probability-c.Probability) > 1e-8 {
				t.Fatalf("fixture=%d rank=%d Python=%+v Go=%+v", i, j, c, actual)
			}
		}
	}
}
func TestParsingAndMinimum(t *testing.T) {
	if got := Numbers("١ ２ 355 9999999999999999999999999999"); !reflect.DeepEqual(got, []int{1, 2, 355}) {
		t.Fatal(got)
	}
	if got := Numbers("1 2 abc 3 4 5 999 -7"); !reflect.DeepEqual(got, []int{3, 4, 5, 7}) {
		t.Fatal(got)
	}
	if got := Numbers("1 2 中 3 4"); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatal(got)
	}
	if _, err := Analyze([]Output{{Text: "拒绝回答"}}); err == nil {
		t.Fatal("拒答不应产生归因")
	}
	d := Inspect(Output{Expected: 301})
	if d.Minimum != 166 || d.Accepted {
		t.Fatal(d)
	}
	if len(Models()) != 13 {
		t.Fatal("统一库候选数量")
	}
}
