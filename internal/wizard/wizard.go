// Package wizard is the interactive setup REPL shared by `jsync configure`
// and `jsyncd install`. It walks the operator through role/network/dirs/
// aliases with charmbracelet/huh, writes the jsync config file in place
// (comments and key order preserved, via internal/yamledit), and
// materialises this node's Ed25519 identity and X3DH prekeys so the node is
// ready to hand its public key to a peer the moment the form closes.
//
// It is the only package that imports huh — the two commands stay thin
// wrappers that add what is specific to each (watch-mode launch for the
// CLI, service registration for the daemon).
package wizard

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	xterm "github.com/charmbracelet/x/term"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/crypto/x3dh"
	"github.com/marck1391/jsync/internal/identity"
	"github.com/marck1391/jsync/internal/yamledit"
)

// Dir is one directory the operator chose to expose: LocalPath is added to
// allowed_dest_paths (so the daemon accepts writes there); Target, if set,
// is the "<node|machine-id>:<dest-path>" a follow-up `jsync watch`/`share`
// would use.
type Dir struct {
	LocalPath string
	Target    string
}

// Result is what Run produces once the form closes and the config +
// identity are on disk.
type Result struct {
	ConfigPath string
	Role       config.Role
	Peer       bool
	Dirs       []Dir
	MachineID  string
	PublicKey  ed25519.PublicKey
}

// inputs is the raw form state, split out from Run so writeConfig and the
// tests never touch huh.
type inputs struct {
	ConfigPath     string
	Role           string
	Host           string
	Port           int
	LeafNodePort   int
	HubLeafNodeURL string
	Dirs           []Dir
	Aliases        map[string]string
}

// ErrNotInteractive is returned by Run when stdin/stdout is not a terminal,
// so a caller in a pipe or CI gets a clear message instead of a huh panic.
var ErrNotInteractive = errors.New("this command needs an interactive terminal; edit jsync.yaml directly, or use `jsync allow` / `jsync node`")

// Run drives the setup form and returns the finished Result. defaultCfgPath
// pre-fills the "config file" prompt.
func Run(defaultCfgPath string) (*Result, error) {
	if !interactive() {
		return nil, ErrNotInteractive
	}

	d := config.Defaults()
	in := inputs{
		ConfigPath:   defaultCfgPath,
		Role:         string(d.Role),
		Host:         d.Host,
		Port:         d.Port,
		LeafNodePort: d.LeafNodePort,
		Aliases:      map[string]string{},
	}

	portStr := strconv.Itoa(in.Port)
	leafStr := strconv.Itoa(in.LeafNodePort)
	var role config.Role = d.Role

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("jsync setup").
				Description("Builds jsync.yaml and this node's identity. Existing keys and comments are kept."),
			huh.NewInput().
				Title("Config file").
				Description("Where to write jsync.yaml.").
				Value(&in.ConfigPath).
				Validate(nonEmpty("config file path")),
			huh.NewSelect[config.Role]().
				Title("Role").
				Description("hub runs the NATS broker; peer is a leaf node that dials a hub.").
				Options(
					huh.NewOption("hub", config.RoleHub),
					huh.NewOption("peer", config.RolePeer),
				).
				Value(&role),
		),
		huh.NewGroup(
			huh.NewInput().Title("Listen host").Value(&in.Host).Validate(nonEmpty("host")),
			huh.NewInput().Title("Client port").Value(&portStr).Validate(validPort),
		),
		huh.NewGroup(
			huh.NewInput().Title("Leaf-node port").Value(&leafStr).Validate(validPort),
		).WithHideFunc(func() bool { return role != config.RoleHub }),
		huh.NewGroup(
			huh.NewInput().
				Title("Hub leaf-node URL").
				Description("nats://host:7422 of the hub this peer connects to.").
				Value(&in.HubLeafNodeURL).
				Validate(validHubURL),
		).WithHideFunc(func() bool { return role != config.RolePeer }),
	)
	if err := form.Run(); err != nil {
		return nil, formErr(err)
	}
	in.Role = string(role)
	in.Port, _ = strconv.Atoi(strings.TrimSpace(portStr))
	in.LeafNodePort, _ = strconv.Atoi(strings.TrimSpace(leafStr))
	in.HubLeafNodeURL = strings.TrimSpace(in.HubLeafNodeURL)
	in.ConfigPath = strings.TrimSpace(in.ConfigPath)

	dirs, err := askDirs()
	if err != nil {
		return nil, err
	}
	in.Dirs = dirs

	if err := askAliases(in.Aliases); err != nil {
		return nil, err
	}

	machineID, err := writeConfig(in)
	if err != nil {
		return nil, err
	}

	pub, err := materialiseIdentity(in.ConfigPath, machineID)
	if err != nil {
		return nil, err
	}

	return &Result{
		ConfigPath: in.ConfigPath,
		Role:       config.Role(in.Role),
		Peer:       config.Role(in.Role) == config.RolePeer,
		Dirs:       in.Dirs,
		MachineID:  machineID,
		PublicKey:  pub,
	}, nil
}

// askDirs runs the "which directories" step: a quick "just this one",
// an add-as-many-as-you-want loop, or nothing.
func askDirs() ([]Dir, error) {
	cwd, _ := os.Getwd()

	const (
		modeCwd    = "cwd"
		modeChoose = "choose"
		modeNone   = "none"
	)
	mode := modeCwd
	if err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Directories to share / sync").
			Options(
				huh.NewOption("Just this directory ("+cwd+")", modeCwd),
				huh.NewOption("Choose directories…", modeChoose),
				huh.NewOption("None for now", modeNone),
			).
			Value(&mode),
	)).Run(); err != nil {
		return nil, formErr(err)
	}

	switch mode {
	case modeNone:
		return nil, nil
	case modeCwd:
		target, err := askTarget(cwd)
		if err != nil {
			return nil, err
		}
		return []Dir{{LocalPath: cwd, Target: target}}, nil
	}

	var dirs []Dir
	for {
		var path string
		if err := huh.NewForm(huh.NewGroup(
			huh.NewInput().
				Title("Directory path").
				Value(&path).
				Validate(validDir),
		)).Run(); err != nil {
			return nil, formErr(err)
		}
		abs, err := filepath.Abs(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", path, err)
		}
		target, err := askTarget(abs)
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, Dir{LocalPath: abs, Target: target})

		more := false
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title("Add another directory?").Value(&more),
		)).Run(); err != nil {
			return nil, formErr(err)
		}
		if !more {
			return dirs, nil
		}
	}
}

// askTarget asks for the sync target of one directory. Blank is allowed —
// it means "add to allowed_dest_paths but don't wire a watch/share".
func askTarget(localPath string) (string, error) {
	var target string
	if err := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Sync target for " + localPath).
			Description("<node|machine-id>:<dest-path> — leave blank to only permit writes here.").
			Value(&target).
			Validate(validTarget),
	)).Run(); err != nil {
		return "", formErr(err)
	}
	return strings.TrimSpace(target), nil
}

// askAliases optionally collects node aliases into out.
func askAliases(out map[string]string) error {
	add := false
	if err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title("Add node aliases?").
			Description("Friendly names for peer machine-ids, so `jsync share ./x vm-01:/dest` works.").
			Value(&add),
	)).Run(); err != nil {
		return formErr(err)
	}
	for add {
		var alias, machineID string
		if err := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Alias").Value(&alias).Validate(func(s string) error {
				return config.ValidNodeAlias(strings.TrimSpace(s))
			}),
			huh.NewInput().Title("machine-id").Value(&machineID).Validate(nonEmpty("machine-id")),
		)).Run(); err != nil {
			return formErr(err)
		}
		out[strings.TrimSpace(alias)] = strings.TrimSpace(machineID)

		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title("Add another alias?").Value(&add),
		)).Run(); err != nil {
			return formErr(err)
		}
	}
	return nil
}

// writeConfig merges in onto whatever config file already exists at
// in.ConfigPath and writes it back atomically. It returns the node's
// machine_id — the one already in the file, or a freshly generated one it
// just wrote (so the CLI and a service launched later agree on identity).
func writeConfig(in inputs) (string, error) {
	doc, err := yamledit.Load(in.ConfigPath)
	if err != nil {
		return "", err
	}
	root := yamledit.DocumentRoot(&doc)

	machineID := ""
	if mid := yamledit.Get(root, "machine_id"); mid != nil && mid.Value != "" {
		machineID = mid.Value
	} else {
		machineID, err = identity.NewMachineID()
		if err != nil {
			return "", fmt.Errorf("generate machine id: %w", err)
		}
		yamledit.SetString(root, "machine_id", machineID)
	}

	yamledit.SetString(root, "role", in.Role)
	yamledit.SetString(root, "host", in.Host)
	yamledit.SetInt(root, "port", in.Port)
	// Write only the key the chosen role uses, and drop the other one so a
	// peer->hub (or hub->peer) switch doesn't leave a stale sibling behind.
	if config.Role(in.Role) == config.RolePeer {
		yamledit.SetString(root, "hub_leaf_node_url", in.HubLeafNodeURL)
		yamledit.Delete(root, "leaf_node_port")
	} else {
		yamledit.SetInt(root, "leaf_node_port", in.LeafNodePort)
		yamledit.Delete(root, "hub_leaf_node_url")
	}

	if len(in.Dirs) > 0 {
		seq, err := yamledit.EnsureSequence(root, "allowed_dest_paths")
		if err != nil {
			return "", err
		}
		for _, d := range in.Dirs {
			yamledit.AppendUnique(seq, d.LocalPath)
		}
	}

	if len(in.Aliases) > 0 {
		nodes, err := yamledit.EnsureMapping(root, "nodes")
		if err != nil {
			return "", err
		}
		for alias, mid := range in.Aliases {
			yamledit.SetString(nodes, alias, mid)
		}
	}

	buf, err := yamledit.Marshal(&doc)
	if err != nil {
		return "", err
	}
	if err := yamledit.AtomicWrite(in.ConfigPath, buf, 0o600); err != nil {
		return "", err
	}
	return machineID, nil
}

// materialiseIdentity loads (creating on first use) this node's Ed25519
// identity and X3DH prekey store, using the paths the just-written config
// resolves to, and returns the public key.
func materialiseIdentity(cfgPath, machineID string) (ed25519.PublicKey, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("reload config: %w", err)
	}
	id, err := identity.Load(cfg.IdentityPath, machineID)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if _, err := x3dh.LoadStore(cfg.PrekeysPath, id.PublicKey, id.PrivateKey, cfg.OneTimePreKeyCount); err != nil {
		return nil, fmt.Errorf("load prekeys: %w", err)
	}
	return id.PublicKey, nil
}

// WatchCommands renders the `jsync watch` invocation for each Dir that has a
// target — what `jsync configure` prints when it will not launch watch mode
// itself (more than one directory, or the operator declined).
func WatchCommands(cfgPath string, dirs []Dir) []string {
	var out []string
	for _, d := range dirs {
		if d.Target == "" {
			continue
		}
		cmd := "jsync watch"
		if cfgPath != "" {
			cmd += " --config " + maybeQuote(cfgPath)
		}
		out = append(out, cmd+" "+maybeQuote(d.LocalPath)+" "+d.Target)
	}
	return out
}

func maybeQuote(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return strconv.Quote(s)
	}
	return s
}

// --- validators ---------------------------------------------------------

func nonEmpty(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s must not be empty", what)
		}
		return nil
	}
}

func validPort(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	return nil
}

func validHubURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("a peer needs the hub's leaf-node URL")
	}
	if !strings.HasPrefix(s, "nats://") && !strings.HasPrefix(s, "tls://") {
		return fmt.Errorf("expected a nats:// or tls:// URL")
	}
	return nil
}

func validDir(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("directory path must not be empty")
	}
	info, err := os.Stat(s)
	if err != nil {
		return fmt.Errorf("%s: %w", s, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", s)
	}
	return nil
}

func validTarget(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	name, dest, ok := strings.Cut(s, ":")
	if !ok || name == "" || dest == "" {
		return fmt.Errorf("expected <node|machine-id>:<dest-path>")
	}
	return nil
}

// formErr normalises a user Ctrl+C / ESC out of a huh form into a plain
// "aborted" error rather than leaking huh's sentinel.
func formErr(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return errors.New("setup aborted")
	}
	return err
}

func interactive() bool {
	return xterm.IsTerminal(os.Stdin.Fd()) && xterm.IsTerminal(os.Stdout.Fd())
}
