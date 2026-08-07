package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Role mirrors handshake/transport's network role (Fase 1 §1), spelled out
// as a string in config.yaml.
type Role string

const (
	RoleHub  Role = "hub"
	RolePeer Role = "peer"
)

// Config is what config.yaml deserializes into (Fase 4 §1: "Carga de
// Configuración"). Every field has a workable zero-config default except
// HubLeafNodeURL, which only makes sense for a Peer and has no sane
// default — Load rejects Role: peer without it.
type Config struct {
	MachineID string `yaml:"machine_id"`
	Role      Role   `yaml:"role"`

	IdentityPath          string `yaml:"identity_path"`
	AuthorizedClientsPath string `yaml:"authorized_clients_path"`
	PrekeysPath           string `yaml:"prekeys_path"`
	OneTimePreKeyCount    int    `yaml:"one_time_prekey_count"`

	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	LeafNodePort   int    `yaml:"leaf_node_port"`
	HubLeafNodeURL string `yaml:"hub_leaf_node_url"`

	JetStreamStoreDir string `yaml:"jetstream_store_dir"`
	MaxPayloadBytes   int64  `yaml:"max_payload_bytes"`
	AllowedDestPath   string `yaml:"allowed_dest_path"`

	Debug bool `yaml:"debug"`
}

// configDir is where every default path below lives: a single, predictable
// subdirectory for everything the daemon owns (identity, prekeys, the
// authorized-clients list, JetStream's own storage) — never a bare
// filename in the current directory. internal/ignore.DefaultPatterns
// excludes ".fileshare/" unconditionally, so if these defaults are ever
// left inside a directory that also happens to be a `share`/`watch` root,
// the private key material in identity.json/prekeys.json doesn't get
// transferred to a peer just because it was sitting nearby — see the
// project CLAUDE.md for why this convention exists.
const configDir = ".fileshare"

func defaults() Config {
	return Config{
		Role:                  RoleHub,
		IdentityPath:          configDir + "/identity.json",
		AuthorizedClientsPath: configDir + "/authorized_clients",
		PrekeysPath:           configDir + "/prekeys.json",
		OneTimePreKeyCount:    10,
		Host:                  "127.0.0.1",
		Port:                  4222,
		LeafNodePort:          7422,
		JetStreamStoreDir:     configDir + "/data/jetstream",
		MaxPayloadBytes:       1 << 20,
	}
}

// Load reads path and overlays it onto sane defaults. A missing file is
// not an error — it just means "run with defaults" (Role: hub, listening
// locally), which is enough to boot a first Daemon with zero configuration.
// A malformed file, or Role: peer without HubLeafNodeURL, is an error.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if verr := cfg.validate(); verr != nil {
				return nil, verr
			}
			return &cfg, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	switch c.Role {
	case RoleHub:
		// Nothing extra required.
	case RolePeer:
		if c.HubLeafNodeURL == "" {
			return fmt.Errorf("config: role %q requires hub_leaf_node_url", RolePeer)
		}
	default:
		return fmt.Errorf("config: unknown role %q (want %q or %q)", c.Role, RoleHub, RolePeer)
	}
	return nil
}
