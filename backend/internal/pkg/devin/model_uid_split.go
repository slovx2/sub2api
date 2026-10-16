package devin

import "strings"

// 以下 UID 拆分与展示名清理规则移植自 CPA cmd/fetch_devin_models，见 NOTICE。

// devinLevelOrder 是聚合后思考档位的排列顺序；fast/priority 是计费通道，不是档位。
var devinLevelOrder = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"}

var devinUpperEffortSuffixes = []struct{ suffix, effort string }{
	{"_NONE", "none"}, {"_MINIMAL", "minimal"}, {"_LOW", "low"}, {"_MEDIUM", "medium"},
	{"_HIGH", "high"}, {"_XHIGH", "xhigh"}, {"_MAX", "max"}, {"_THINKING", "high"},
}

var devinCompoundEffortSuffixes = []struct{ suffix, effort, readd string }{
	{"-low-fast", "low", ""}, {"-medium-fast", "medium", ""}, {"-high-fast", "high", ""},
	{"-xhigh-fast", "xhigh", ""}, {"-max-fast", "max", ""}, {"-none-fast", "none", ""},
	{"-low-priority", "low", ""}, {"-medium-priority", "medium", ""}, {"-high-priority", "high", ""},
	{"-xhigh-priority", "xhigh", ""}, {"-max-priority", "max", ""}, {"-none-priority", "none", ""},
	{"-thinking-1m", "", "-1m"}, {"-thinking", "", ""},
	{"-max-1m", "max", "-1m"}, {"-none-1m", "none", "-1m"},
}

var devinSimpleEffortSuffixes = []struct{ suffix, effort string }{
	{"-none", "none"}, {"-minimal", "minimal"}, {"-low", "low"}, {"-medium", "medium"},
	{"-high", "high"}, {"-xhigh", "xhigh"}, {"-max", "max"},
}

// splitDevinUID 把上游 UID 拆成基础模型和思考档位（无档位时为空）。
func splitDevinUID(uid string) (string, string) {
	switch uid {
	case "swe-1-6-slow":
		return uid, ""
	case "swe-1-6-fast":
		return "swe-1-6", ""
	}
	upper := strings.ToUpper(uid)
	for _, s := range devinUpperEffortSuffixes {
		if strings.HasSuffix(upper, s.suffix) {
			return uid[:len(uid)-len(s.suffix)], s.effort
		}
	}
	for _, s := range devinCompoundEffortSuffixes {
		if strings.HasSuffix(uid, s.suffix) {
			return uid[:len(uid)-len(s.suffix)] + s.readd, s.effort
		}
	}
	for _, s := range devinSimpleEffortSuffixes {
		if strings.HasSuffix(uid, s.suffix) {
			return uid[:len(uid)-len(s.suffix)], s.effort
		}
	}
	return uid, ""
}

var devinDisplayNameSuffixes = []string{
	" Low Fast", " Medium Fast", " High Fast", " XHigh Fast", " Max Fast",
	" Low Thinking Fast", " Medium Thinking Fast", " High Thinking Fast",
	" XHigh Thinking Fast", " Max Thinking Fast", " No Thinking Fast",
	" Low Thinking", " Medium Thinking", " High Thinking", " XHigh Thinking",
	" Max Thinking", " No Thinking",
	" Low", " Medium", " High", " XHigh", " Max", " None", " Minimal",
	" Thinking", " Fast",
}

func cleanDevinDisplayName(label string) string {
	trimmed := strings.TrimSpace(label)
	for changed := true; changed; {
		changed = false
		for _, s := range devinDisplayNameSuffixes {
			if strings.HasSuffix(strings.ToLower(trimmed), strings.ToLower(s)) {
				trimmed = strings.TrimSpace(trimmed[:len(trimmed)-len(s)])
				changed = true
				break
			}
		}
	}
	return trimmed
}
