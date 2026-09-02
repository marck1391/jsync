package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Role mirrors handshake/transport's network role (Fase 1 §1), spelled out
// as a string in config.yaml.
type Role string

const (
	RoleHub  Role = "hub"
	RolePeer Role = "peer"
)

// StringList is a []string that also accepts a single scalar in YAML, so
// both `allowed_dest_paths: /one` and the block-sequence form parse. An
// empty or absent value yields a nil slice.
type StringList []string

// UnmarshalYAML accepts a scalar, a sequence, or null.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var one string
		if err := node.Decode(&one); err != nil {
			return err
		}
		if one == "" || one == "~" {
			*s = nil
			return nil
		}
		*s = StringList{one}
		return nil
	case yaml.SequenceNode:
		var many []string
		if err := node.Decode(&many); err != nil {
			return err
		}
		*s = StringList(many)
		return nil
	default:
		return fmt.Errorf("config: expected a string or list of strings, got yaml node kind %d", node.Kind)
	}
}

// Config is what the config file deserializes into (Fase 4 §1: "Carga de
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

	// Nodes maps a friendly alias to a peer's machine_id, so
	// `jsync share ./x vm-01:/dest` works instead of pasting a raw
	// machine_id. Only affects how the local CLI addresses a target — it is
	// not exchanged with anyone and does not grant trust (that stays in
	// authorized_clients). `jsync node add/rm/ls` edit this key in place.
	Nodes map[string]string `yaml:"nodes"`

	JetStreamStoreDir string `yaml:"jetstream_store_dir"`
	MaxPayloadBytes   int64  `yaml:"max_payload_bytes"`

	// AllowedDestPaths restricts where a peer may ask this daemon to write
	// (Fase 1 handshake): a handshake is rejected unless its
	// requested_dest_path is one of these roots or nested under one.
	// Accepts a single path or a YAML list; empty means no restriction.
	// `allowed_dest_path` (singular) is a deprecated alias, folded in on
	// Load. `jsync allow` / `jsync remove` edit this key in place.
	AllowedDestPaths StringList `yaml:"allowed_dest_paths"`

	// AuditLog records the file mutations a `watch` session applies or
	// publishes (Fase 6 / internal/auditlog). Defaults on; set
	// `audit_log: false` to disable. AuditLogDir is where the per-root
	// JSONL logs live — under configDir like every other daemon-owned
	// path, so internal/ignore.DefaultPatterns keeps it out of any synced
	// tree automatically.
	AuditLog    bool   `yaml:"audit_log"`
	AuditLogDir string `yaml:"audit_log_dir"`

	Debug bool `yaml:"debug"`

	// Path is the config file Load read (or would have read, for a missing
	// file). Not from YAML — set by Load so `jsync allow` knows which file
	// to rewrite. Empty only for a Config built straight from defaults().
	Path string `yaml:"-"`
}

// aliasEnvelope catches the deprecated singular key without disturbing the
// StringList unmarshal on the plural one.
type aliasEnvelope struct {
	Legacy string `yaml:"allowed_dest_path"`
}

// configDir is where every default path below lives: a single, predictable
// subdirectory for everything the daemon owns (identity, prekeys, the
// authorized-clients list, JetStream's own storage) — never a bare
// filename in the current directory. internal/ignore.DefaultPatterns
// excludes ".jsync/" unconditionally, so if these defaults are ever
// left inside a directory that also happens to be a `share`/`watch` root,
// the private key material in identity.json/prekeys.json doesn't get
// transferred to a peer just because it was sitting nearby — see the
// project CLAUDE.md for why this convention exists.
const configDir = ".jsync"

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
		AuditLog:              true,
		AuditLogDir:           configDir + "/audit",
	}
}

// Resolve picks the config file path to use, in order of precedence:
//
//  1. explicit (the --config flag), if non-empty;
//  2. $JSYNC_CONFIG, if set;
//  3. ./jsync.yaml, if it exists in the working directory;
//  4. $XDG_CONFIG_HOME/jsync/config.yaml (falling back to
//     ~/.config/jsync/config.yaml) — the canonical home, returned whether
//     or not it exists yet so a first run and `jsync allow` agree on where
//     it lives.
//
// The returned path is always safe to hand to Load (a missing file there is
// not an error). found reports whether the path actually exists.
func Resolve(explicit string) (path string, found bool) {
	switch {
	case explicit != "":
		path = explicit
	case os.Getenv("JSYNC_CONFIG") != "":
		path = os.Getenv("JSYNC_CONFIG")
	default:
		if local := "jsync.yaml"; fileExists(local) {
			path = local
		} else {
			base := os.Getenv("XDG_CONFIG_HOME")
			if base == "" {
				if home, err := os.UserHomeDir(); err == nil {
					base = filepath.Join(home, ".config")
				}
			}
			path = filepath.Join(base, "jsync", "config.yaml")
		}
	}
	return path, fileExists(path)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Load reads path and overlays it onto sane defaults. A missing file is not
// an error — it just means "run with defaults" (Role: hub, listening
// locally), which is enough to boot a first daemon with zero configuration.
// A malformed file, or Role: peer without HubLeafNodeURL, is an error.
//
// Relative internal paths (identity_path, prekeys_path, …) are resolved
// against path's directory, not the process working directory, so `.jsync/`
// lives next to the config file wherever it is. See Resolve for how the
// default path is chosen when none is given on the command line.
func Load(path string) (*Config, error) {
	cfg := defaults()
	cfg.Path = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.resolvePaths(path)
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

	var alias aliasEnvelope
	if err := yaml.Unmarshal(data, &alias); err == nil && alias.Legacy != "" {
		cfg.AllowedDestPaths = append(cfg.AllowedDestPaths, alias.Legacy)
	}

	cfg.resolvePaths(path)

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// resolvePaths rewrites each relative internal path to sit under the config
// file's directory. AllowedDestPaths is left untouched — those are absolute
// targets on the receiver, unrelated to where the config lives.
func (c *Config) resolvePaths(configPath string) {
	base := filepath.Dir(configPath)
	for _, p := range []*string{&c.IdentityPath, &c.AuthorizedClientsPath, &c.PrekeysPath, &c.JetStreamStoreDir, &c.AuditLogDir} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
}

// ResolveNode returns the machine_id for a target: the alias's mapping if
// name is a known node alias, otherwise name unchanged (so raw machine_ids
// keep working).
func (c *Config) ResolveNode(name string) string {
	if id, ok := c.Nodes[name]; ok && id != "" {
		return id
	}
	return name
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
