package service

import (
	"testing"

	pluginv1 "github.com/Wei-Shaw/sub2api/pkg/pluginapi/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluatePluginCompatibility(t *testing.T) {
	manifest := testPluginManifest(nil)
	host := PluginHostInfo{Version: "0.1.179", BuildType: "release"}

	result := EvaluatePluginCompatibility(manifest, host)
	require.True(t, result.Compatible)
	assert.True(t, result.Tested)
	assert.Equal(t, "compatible", result.Status)

	manifest.Requires.TestedSub2APIVersions = []string{"0.1.178"}
	result = EvaluatePluginCompatibility(manifest, host)
	require.True(t, result.Compatible)
	assert.False(t, result.Tested)
	assert.Equal(t, "untested", result.Status)

	manifest.Requires.Sub2API = ">=0.2.0 <0.3.0"
	result = EvaluatePluginCompatibility(manifest, host)
	assert.False(t, result.Compatible)
	assert.Equal(t, "incompatible", result.Status)
}

func TestEvaluatePluginCompatibilityRejectsProtocolMismatch(t *testing.T) {
	manifest := testPluginManifest(nil)
	manifest.Requires.PluginProtocol = pluginv1.ProtocolVersion + 1

	result := EvaluatePluginCompatibility(manifest, PluginHostInfo{Version: "0.1.179"})

	assert.False(t, result.Compatible)
	assert.Equal(t, "incompatible", result.Status)
}

func TestMatchesSemverRange(t *testing.T) {
	assert.True(t, matchesSemverRange("0.1.179", ">=0.1.170, <0.2.0"))
	assert.True(t, matchesSemverRange("v1.2.3", "=1.2.3"))
	assert.False(t, matchesSemverRange("0.1.169", ">=0.1.170 <0.2.0"))
	assert.False(t, matchesSemverRange("dev", ">=0.1.0"))
	assert.False(t, matchesSemverRange("0.1.179", "^0.1.0"))
}

func TestPluginCompatibilityForkHostVersion(t *testing.T) {
	manifest := testPluginManifest(nil)
	manifest.Requires.Sub2API = ">=0.2.7 <0.3.0"
	manifest.Requires.TestedSub2APIVersions = []string{"0.2.7"}
	for _, version := range []string{"0.2.7.1", "v0.2.7.2", "0.2.7.10"} {
		t.Run(version, func(t *testing.T) {
			result := EvaluatePluginCompatibility(manifest, PluginHostInfo{Version: version})
			require.True(t, result.Compatible)
			// 上游已测试不等于分支已测试，仍保留管理员确认。
			require.False(t, result.Tested)
			require.Equal(t, version, result.CurrentSub2API)
		})
	}
	for _, version := range []string{"0.2.6.99", "0.3.0.1", "0.2.7.bad", "0.2.7.1.2", "0.2.7.01"} {
		t.Run(version, func(t *testing.T) {
			require.False(t, EvaluatePluginCompatibility(manifest, PluginHostInfo{Version: version}).Compatible)
		})
	}
	// 插件自己的 version 仍必须符合标准 semver，不放宽签名清单规范。
	require.Empty(t, normalizeSemver("0.2.7.1"))
}
