package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/huh"
	"github.com/kardianos/service"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/wizard"
)

// cmdInstall runs the shared interactive setup (internal/wizard — the same
// REPL `jsync configure` uses) and then registers jsyncd with the OS
// service manager, pointing it at the config file the wizard just wrote.
//
// The config path is resolved to an absolute path and baked into the
// service's Arguments: a service does not run in the directory `jsyncd
// install` was invoked from, so a relative path (or a bare ./jsync.yaml
// discovery) would not find it.
func cmdInstall(svc service.Service, svcCfg *service.Config, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file for the service (default: the system location)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	def := *cfgPath
	if def == "" {
		def = config.SystemConfigPath()
	}

	res, err := wizard.Run(def)
	if err != nil {
		return err
	}

	abs, err := filepath.Abs(res.ConfigPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", res.ConfigPath, err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate the jsyncd binary: %w", err)
	}
	svcCfg.Executable = exe
	svcCfg.Arguments = []string{"--config", abs}

	if err := svc.Install(); err != nil {
		return fmt.Errorf("register the service (run as root / Administrator?): %w", err)
	}

	fmt.Println()
	fmt.Println("installed service:", serviceName)
	fmt.Printf("  exec: %s --config %s\n", exe, abs)
	fmt.Println("  machine_id:", res.MachineID)
	fmt.Println("  public_key:", base64.StdEncoding.EncodeToString(res.PublicKey))

	start := false
	if err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title("Start the service now?").Value(&start),
	)).Run(); err != nil {
		return err
	}
	if start {
		if err := svc.Start(); err != nil {
			return fmt.Errorf("start the service: %w", err)
		}
		fmt.Println("started — check it with `jsyncd status`")
	} else {
		fmt.Println("start it later with `jsyncd start`")
	}
	return nil
}

// controlAndReport runs one service.Control action and prints a one-line
// result. uninstall stops the service first so it does not fail on a
// running one.
func controlAndReport(svc service.Service, action string) error {
	if action == "uninstall" {
		_ = svc.Stop()
	}
	if err := service.Control(svc, action); err != nil {
		return fmt.Errorf("%s the service (run as root / Administrator?): %w", action, err)
	}
	fmt.Printf("%s ok: %s\n", action, serviceName)
	return nil
}

// reportStatus prints the installed service's state (or "not installed").
func reportStatus(svc service.Service) error {
	st, err := svc.Status()
	if err != nil {
		if errors.Is(err, service.ErrNotInstalled) {
			fmt.Println("not installed")
			return nil
		}
		return err
	}
	switch st {
	case service.StatusRunning:
		fmt.Println("running")
	case service.StatusStopped:
		fmt.Println("stopped")
	default:
		fmt.Println("unknown")
	}
	return nil
}
