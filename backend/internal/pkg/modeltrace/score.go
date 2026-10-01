// Package modeltrace 实现 ModelTrace 的闭集指纹归因；算法来源及许可见 LICENSE。
package modeltrace

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode"
)

//go:embed unified_bank.json
var bankJSON []byte

type featureBank struct {
	Mean         []float64     `json:"feature_mean"`
	Scale        []float64     `json:"feature_scale"`
	Basis        [][]float64   `json:"nuisance_basis"`
	Centroids    [][]float64   `json:"centroids"`
	Environments [][][]float64 `json:"environment_centroids"`
	Weight       float64       `json:"weight"`
}
type fingerprintBank struct {
	Models []struct {
		ID string `json:"id"`
	} `json:"models"`
	Robust struct {
		Hellinger featureBank `json:"hellinger"`
		Ordered   featureBank `json:"ordered_blocks"`
	} `json:"robust"`
	Calibration map[string]struct {
		Beta float64 `json:"beta"`
	} `json:"calibration"`
}

var bank = func() fingerprintBank {
	var b fingerprintBank
	if err := json.Unmarshal(bankJSON, &b); err != nil {
		panic(err)
	}
	return b
}()

func Version() string { sum := sha256.Sum256(bankJSON); return hex.EncodeToString(sum[:]) }
func Models() []string {
	result := make([]string, len(bank.Models))
	for i, m := range bank.Models {
		result[i] = m.ID
	}
	return result
}

type Candidate struct {
	Model       string  `json:"model"`
	Probability float64 `json:"probability"`
}
type Output struct {
	Text     string `json:"text"`
	Expected int    `json:"expected_count"`
}
type Diagnostic struct {
	Count    int  `json:"parsed_numbers"`
	Minimum  int  `json:"minimum_numbers"`
	Accepted bool `json:"accepted"`
}
type Score struct {
	Model       string       `json:"model"`
	Probability float64      `json:"probability"`
	Candidates  []Candidate  `json:"candidates"`
	Diagnostics []Diagnostic `json:"diagnostics"`
	Used        int          `json:"used_outputs"`
}

var digits = regexp.MustCompile(`\p{Nd}+`)

// Numbers 与原 Python 实现一致：字母分隔切断数字段，取最长有效段。
// decimalNumber 对齐 Python 的 Unicode 十进制数字解析，并避免超长整数溢出。
func decimalNumber(text string) int {
	n := 0
	for _, r := range text {
		digit := int(r - '0')
		if r < '0' || r > '9' {
			for _, block := range unicode.Nd.R16 {
				if uint32(r) >= uint32(block.Lo) && uint32(r) <= uint32(block.Hi) {
					digit = int((uint32(r)-uint32(block.Lo))/uint32(block.Stride)) % 10
					break
				}
			}
			for _, block := range unicode.Nd.R32 {
				if uint32(r) >= block.Lo && uint32(r) <= block.Hi {
					digit = int((uint32(r)-block.Lo)/block.Stride) % 10
					break
				}
			}
		}
		n = n*10 + digit
		if n > 355 {
			return 356
		}
	}
	return n
}

func Numbers(text string) []int {
	var best, current []int
	end := 0
	for _, loc := range digits.FindAllStringIndex(text, -1) {
		split := false
		for _, r := range text[end:loc[0]] {
			if unicode.IsLetter(r) {
				split = true
				break
			}
		}
		if split && len(current) > 0 {
			if len(current) > len(best) {
				best = current
			}
			current = nil
		}
		n := decimalNumber(text[loc[0]:loc[1]])
		if n >= 1 && n <= 355 {
			current = append(current, n)
		}
		end = loc[1]
	}
	if len(current) > len(best) {
		best = current
	}
	return best
}
func Inspect(o Output) Diagnostic {
	minimum := 80
	if n := int(math.Ceil(float64(o.Expected) * .55)); n > minimum {
		minimum = n
	}
	count := len(Numbers(o.Text))
	return Diagnostic{count, minimum, count >= minimum}
}
func dot(a, b []float64) float64 {
	var s float64
	for i, v := range a {
		s += v * b[i]
	}
	return s
}
func standardize(a []float64) []float64 {
	var mean, variance float64
	for _, v := range a {
		mean += v
	}
	mean /= float64(len(a))
	for _, v := range a {
		variance += (v - mean) * (v - mean)
	}
	scale := math.Max(math.Sqrt(variance/float64(len(a))), 1e-12)
	out := make([]float64, len(a))
	for i, v := range a {
		out[i] = (v - mean) / scale
	}
	return out
}
func normalize(a []float64) []float64 {
	out := append([]float64(nil), a...)
	norm := math.Max(math.Sqrt(dot(a, a)), 1e-12)
	for i := range out {
		out[i] /= norm
	}
	return out
}
func project(a []float64, basis [][]float64) []float64 {
	out := append([]float64(nil), a...)
	for _, row := range basis {
		weight := dot(a, row)
		for i, v := range row {
			out[i] -= weight * v
		}
	}
	return out
}
func transform(feature []float64, b featureBank) []float64 {
	out := make([]float64, len(feature))
	for i, v := range feature {
		out[i] = (v - b.Mean[i]) / b.Scale[i]
	}
	return out
}
func similarities(feature []float64, centroids [][]float64) []float64 {
	out := make([]float64, len(centroids))
	for i, c := range centroids {
		out[i] = dot(feature, c)
	}
	return out
}
func hellinger(counts []float64) []float64 {
	total := float64(len(counts)) * .5
	for _, v := range counts {
		total += v
	}
	for i := range counts {
		counts[i] = math.Sqrt((counts[i] + .5) / total)
	}
	return counts
}
func features(numbers []int) ([]float64, []float64) {
	counts := make([]float64, 355)
	for _, n := range numbers {
		counts[n-1]++
	}
	ordered := make([]float64, 0, 74)
	offset := 0
	for block := 0; block < 4; block++ {
		size := len(numbers) / 4
		if block < len(numbers)%4 {
			size++
		}
		bins := make([]float64, 16)
		for _, n := range numbers[offset : offset+size] {
			bins[(n-1)*16/355]++
		}
		ordered = append(ordered, hellinger(bins)...)
		offset += size
	}
	last := make([]float64, 10)
	for _, n := range numbers {
		last[n%10]++
	}
	ordered = append(ordered, hellinger(last)...)
	return hellinger(counts), ordered
}
func scores(numbers []int) []float64 {
	h, o := features(numbers)
	hb, ob := bank.Robust.Hellinger, bank.Robust.Ordered
	marginal := standardize(standardize(similarities(normalize(project(transform(h, hb), hb.Basis)), hb.Centroids)))
	f := transform(o, ob)
	normalized := normalize(f)
	template := make([]float64, len(bank.Models))
	for i := range template {
		template[i] = math.Inf(-1)
	}
	for _, environment := range ob.Environments {
		for i, v := range similarities(normalized, environment) {
			template[i] = math.Max(template[i], v)
		}
	}
	template = standardize(template)
	nuisance := standardize(similarities(normalize(project(f, ob.Basis)), ob.Centroids))
	for i := range template {
		template[i] = .5*template[i] + .5*nuisance[i]
	}
	ordered := standardize(template)
	for i := range marginal {
		marginal[i] = (1-ob.Weight)*marginal[i] + ob.Weight*ordered[i]
	}
	return marginal
}
func Analyze(outputs []Output) (*Score, error) {
	result := &Score{}
	combined := make([]float64, len(bank.Models))
	for _, o := range outputs {
		d := Inspect(o)
		result.Diagnostics = append(result.Diagnostics, d)
		if !d.Accepted {
			continue
		}
		result.Used++
		for i, v := range scores(Numbers(o.Text)) {
			combined[i] += v
		}
	}
	if result.Used == 0 {
		return nil, fmt.Errorf("没有有效数字样本")
	}
	key := result.Used
	if key > 3 {
		key = 3
	}
	beta := bank.Calibration[strconv.Itoa(key)].Beta
	maximum := math.Inf(-1)
	for i := range combined {
		combined[i] *= beta / float64(result.Used)
		maximum = math.Max(maximum, combined[i])
	}
	total := 0.0
	for i := range combined {
		combined[i] = math.Exp(combined[i] - maximum)
		total += combined[i]
	}
	for i, m := range bank.Models {
		result.Candidates = append(result.Candidates, Candidate{m.ID, combined[i] / total})
	}
	sort.SliceStable(result.Candidates, func(i, j int) bool { return result.Candidates[i].Probability > result.Candidates[j].Probability })
	result.Model = result.Candidates[0].Model
	result.Probability = result.Candidates[0].Probability
	return result, nil
}
