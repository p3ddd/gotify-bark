package main

import (
	"testing"

	"github.com/gotify/plugin-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPICompatibility(t *testing.T) {
	assert.Implements(t, (*plugin.Plugin)(nil), new(BarkForwardPlugin))
	assert.Implements(t, (*plugin.Configurer)(nil), new(BarkForwardPlugin))
	assert.Implements(t, (*plugin.Displayer)(nil), new(BarkForwardPlugin))
}

func TestDefaultConfig(t *testing.T) {
	p := &BarkForwardPlugin{}
	cfg := p.DefaultConfig().(*Config)

	assert.Equal(t, "ws://localhost:80", cfg.GotifyHost)
	assert.Equal(t, "", cfg.GotifyClientToken)
	assert.Equal(t, "", cfg.BarkDeviceKey)
	assert.Equal(t, "https://api.day.app/push", cfg.BarkURL)
	assert.Equal(t, 10, cfg.ReconnectDelay)
}

func TestValidateAndSetConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name:    "empty GotifyHost",
			config:  &Config{GotifyHost: "", GotifyClientToken: "token", BarkDeviceKey: "key", BarkURL: "url"},
			wantErr: "GotifyHost cannot be empty",
		},
		{
			name:    "empty GotifyClientToken",
			config:  &Config{GotifyHost: "ws://localhost", GotifyClientToken: "", BarkDeviceKey: "key", BarkURL: "url"},
			wantErr: "GotifyClientToken cannot be empty",
		},
		{
			name:    "empty BarkDeviceKey",
			config:  &Config{GotifyHost: "ws://localhost", GotifyClientToken: "token", BarkDeviceKey: "", BarkURL: "url"},
			wantErr: "BarkDeviceKey key cannot be empty",
		},
		{
			name:    "empty BarkURL",
			config:  &Config{GotifyHost: "ws://localhost", GotifyClientToken: "token", BarkDeviceKey: "key", BarkURL: ""},
			wantErr: "BarkURL cannot be empty",
		},
		{
			name:    "valid config",
			config:  &Config{GotifyHost: "ws://localhost", GotifyClientToken: "token", BarkDeviceKey: "key", BarkURL: "url", ReconnectDelay: 5},
			wantErr: "",
		},
		{
			name:    "zero ReconnectDelay defaults to 10",
			config:  &Config{GotifyHost: "ws://localhost", GotifyClientToken: "token", BarkDeviceKey: "key", BarkURL: "url", ReconnectDelay: 0},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BarkForwardPlugin{}
			err := p.ValidateAndSetConfig(tt.config)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, p.config)
			}
		})
	}
}

func TestReconnectDelayDefault(t *testing.T) {
	p := &BarkForwardPlugin{}
	cfg := &Config{
		GotifyHost:        "ws://localhost",
		GotifyClientToken: "token",
		BarkDeviceKey:     "key",
		BarkURL:           "url",
		ReconnectDelay:    0,
	}

	err := p.ValidateAndSetConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, 10, p.config.ReconnectDelay)
}

func TestEnableWithoutConfig(t *testing.T) {
	p := &BarkForwardPlugin{}
	err := p.Enable()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}
