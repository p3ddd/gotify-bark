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

func TestEncryptAESCBC(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		iv        string
		plaintext string
		wantErr   string
	}{
		{
			name:      "valid AES-128",
			key:       "1234567890123456", // 16 bytes
			iv:        "1234567890123456", // 16 bytes
			plaintext: `{"title":"test","body":"hello"}`,
			wantErr:   "",
		},
		{
			name:      "valid AES-256",
			key:       "12345678901234567890123456789012", // 32 bytes
			iv:        "1234567890123456",                 // 16 bytes
			plaintext: `{"title":"test","body":"hello"}`,
			wantErr:   "",
		},
		{
			name:      "invalid key length",
			key:       "shortkey", // 8 bytes - invalid
			iv:        "1234567890123456",
			plaintext: `{"title":"test"}`,
			wantErr:   "encryption key must be 16 or 32 bytes",
		},
		{
			name:      "invalid IV length",
			key:       "1234567890123456",
			iv:        "short", // 5 bytes - invalid
			plaintext: `{"title":"test"}`,
			wantErr:   "encryption IV must be 16 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BarkForwardPlugin{
				config: &Config{
					EncryptionKey: tt.key,
					EncryptionIV:  tt.iv,
				},
			}

			result, err := p.encryptAESCBC([]byte(tt.plaintext))

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
				// Result should be valid base64
				assert.Regexp(t, `^[A-Za-z0-9+/]+=*$`, result)
			}
		})
	}
}

func TestEncryptionDisabledByDefault(t *testing.T) {
	p := &BarkForwardPlugin{}
	cfg := p.DefaultConfig().(*Config)

	assert.Empty(t, cfg.EncryptionKey)
	assert.Empty(t, cfg.EncryptionIV)
}
