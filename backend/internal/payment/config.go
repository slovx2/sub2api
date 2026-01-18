package payment

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	defaultMinAmount            int64  = 5
	defaultMaxAmount            int64  = 5000
	defaultStepAmount           int64  = 1
	defaultTimestampSkewSeconds int64  = 180
	defaultPluginsWorldAPIBase  string = "https://pay.plugins-world.cn"
)

type Config struct {
	Enabled              bool               `mapstructure:"enabled"`
	PublicBaseURL        string             `mapstructure:"public_base_url"`
	MinAmount            int64              `mapstructure:"min_amount"`
	MaxAmount            int64              `mapstructure:"max_amount"`
	Step                 int64              `mapstructure:"step"`
	TimestampSkewSeconds int64              `mapstructure:"timestamp_skew_seconds"`
	PluginsWorld         PluginsWorldConfig `mapstructure:"plugins_world"`
}

type PluginsWorldConfig struct {
	APIBaseURL         string `mapstructure:"api_base_url"`
	MerchantID         int64  `mapstructure:"merchant_id"`
	MerchantPrivateKey string `mapstructure:"merchant_private_key"`
	PlatformPublicKey  string `mapstructure:"platform_public_key"`
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:              true,
		MinAmount:            defaultMinAmount,
		MaxAmount:            defaultMaxAmount,
		Step:                 defaultStepAmount,
		TimestampSkewSeconds: defaultTimestampSkewSeconds,
		PluginsWorld: PluginsWorldConfig{
			APIBaseURL: defaultPluginsWorldAPIBase,
		},
	}
}

func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()
	if value, ok, err := readBoolEnv("PAYMENT_ENABLED"); err != nil {
		return cfg, err
	} else if ok {
		cfg.Enabled = value
	}
	if value, ok, err := readInt64Env("PAYMENT_MIN_AMOUNT"); err != nil {
		return cfg, err
	} else if ok {
		cfg.MinAmount = value
	}
	if value, ok, err := readInt64Env("PAYMENT_MAX_AMOUNT"); err != nil {
		return cfg, err
	} else if ok {
		cfg.MaxAmount = value
	}
	if value, ok, err := readInt64Env("PAYMENT_STEP"); err != nil {
		return cfg, err
	} else if ok {
		cfg.Step = value
	}
	if value, ok, err := readInt64Env("PAYMENT_TIMESTAMP_SKEW_SECONDS"); err != nil {
		return cfg, err
	} else if ok {
		cfg.TimestampSkewSeconds = value
	}
	if value, ok := readStringEnv("PAYMENT_PUBLIC_BASE_URL"); ok {
		cfg.PublicBaseURL = value
	}
	if value, ok, err := readInt64Env("PAYMENT_PLUGINS_WORLD_MERCHANT_ID"); err != nil {
		return cfg, err
	} else if ok {
		cfg.PluginsWorld.MerchantID = value
	}
	if value, ok := readStringEnv("PAYMENT_PLUGINS_WORLD_MERCHANT_PRIVATE_KEY"); ok {
		cfg.PluginsWorld.MerchantPrivateKey = normalizeKey(value)
	}
	if value, ok := readStringEnv("PAYMENT_PLUGINS_WORLD_PLATFORM_PUBLIC_KEY"); ok {
		cfg.PluginsWorld.PlatformPublicKey = normalizeKey(value)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("payment config is nil")
	}
	if c.MinAmount <= 0 || c.MaxAmount <= 0 || c.Step <= 0 {
		return errors.New("payment amount range is invalid")
	}
	if c.MinAmount > c.MaxAmount {
		return errors.New("payment amount range is invalid")
	}
	if c.TimestampSkewSeconds <= 0 {
		return errors.New("payment timestamp skew is invalid")
	}
	if !c.Enabled {
		return nil
	}
	if err := validateURL("public_base_url", c.PublicBaseURL); err != nil {
		return err
	}
	if err := validateURL("plugins_world.api_base_url", c.PluginsWorld.APIBaseURL); err != nil {
		return err
	}
	if c.PluginsWorld.MerchantID <= 0 {
		return errors.New("plugins_world.merchant_id is required")
	}
	if strings.TrimSpace(c.PluginsWorld.MerchantPrivateKey) == "" {
		return errors.New("plugins_world.merchant_private_key is required")
	}
	if strings.TrimSpace(c.PluginsWorld.PlatformPublicKey) == "" {
		return errors.New("plugins_world.platform_public_key is required")
	}
	return nil
}

func (c *Config) PublicConfig() PublicConfig {
	if c == nil {
		return PublicConfig{
			Enabled:   false,
			MinAmount: defaultMinAmount,
			MaxAmount: defaultMaxAmount,
			Step:      defaultStepAmount,
		}
	}
	return PublicConfig{
		Enabled:   c.Enabled,
		MinAmount: c.MinAmount,
		MaxAmount: c.MaxAmount,
		Step:      c.Step,
	}
}

func validateURL(name, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s is required", name)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func readStringEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

func readInt64Env(key string) (int64, bool, error) {
	raw, ok := readStringEnv(key)
	if !ok {
		return 0, false, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("%s is invalid", key)
	}
	return value, true, nil
}

func readBoolEnv(key string) (bool, bool, error) {
	raw, ok := readStringEnv(key)
	if !ok {
		return false, false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, true, fmt.Errorf("%s is invalid", key)
	}
	return value, true, nil
}

func normalizeKey(value string) string {
	if value == "" {
		return value
	}
	return strings.ReplaceAll(value, "\\n", "\n")
}
