// Vault-User-Token Utility
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Luzifer/rconfig/v2"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
)

const (
	tokenRenewValidity  = 900 // Seconds
	tokenRenewEarly     = 30 * time.Second
	vaultTokenFilePerms = 0o600

	modeGroupReadable = 0o020
	modeGroupWritable = 0o040
	modeOtherReadable = 0o002
	modeOtherWritable = 0o004
)

var (
	cfg = struct {
		LogLevel string `flag:"log-level" default:"info" description:"Log level (debug, info, warning, error)"`

		UseFullHostname bool `flag:"full-hostname" default:"true" description:"Use the full reported hostname (true) or only the first part (false)"`

		VaultAddress string `flag:"vault-addr" env:"VAULT_ADDR" default:"https://127.0.0.1:8200" description:"Vault API address"`
		VaultRoleID  string `flag:"vault-role-id" env:"VAULT_ROLE_ID" default:"" description:"ID of the role to use"`

		VersionAndExit bool `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	version = "dev"

	client *api.Client
)

func initApp() (err error) {
	rconfig.AutoEnv(true)
	if err = rconfig.Parse(&cfg); err != nil {
		return fmt.Errorf("parsing CLI options: %w", err)
	}

	if cfg.VersionAndExit {
		// main will exit shortly after
		return nil
	}

	if cfg.VaultRoleID == "" {
		return fmt.Errorf("vault-role-id missing")
	}

	logLevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("parsing log-level: %w", err)
	}
	log.SetLevel(logLevel)

	return nil
}

func main() {
	var err error
	if err = initApp(); err != nil {
		log.WithError(err).Fatal("initializing app")
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-user-token %s\n", version) //nolint:forbidigo // printing to stdout is not expected to err
		os.Exit(0)
	}

	roleSecret, err := getVaultRoleSecret()
	if err != nil {
		log.WithError(err).Fatal("getting vault role secret")
	}

	client, err = api.NewClient(&api.Config{
		Address: cfg.VaultAddress,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to create new vault client")
	}

	for {
		if err = authenticateVault(roleSecret); err != nil {
			log.WithError(err).Fatal("Unable to authenticate vault")
		}

		if err = keepRenewingToken(); err != nil {
			log.WithError(err).Error("Unale to renew token")
		}
	}
}

func getVaultRoleSecret() (string, error) {
	var secret string

	secretOverrideFile, err := homedir.Expand("~/.config/vault-user-token.secret")
	if err != nil {
		return "", fmt.Errorf("expanding location of secret override: %w", err)
	}

	sofInfo, err := os.Stat(secretOverrideFile)
	if err == nil {
		if hasInsecurePermission(sofInfo.Mode()) {
			return "", errors.New("secret override file has insecure permissions")
		}

		//#nosec:G304 // File is only read as string, not sec-relevant
		if secretOverride, err := os.ReadFile(secretOverrideFile); err == nil {
			return strings.TrimSpace(string(secretOverride)), nil
		}
	}

	if secret, err = os.Hostname(); err != nil {
		return "", fmt.Errorf("resolving hostname: %w", err)
	}

	if parts := strings.Split(secret, "."); !cfg.UseFullHostname && len(parts) > 1 {
		secret = parts[0]
	}

	return secret, nil
}

func hasInsecurePermission(filePerm os.FileMode) bool {
	for _, insecMode := range []os.FileMode{modeGroupWritable, modeGroupReadable, modeOtherWritable, modeOtherReadable} {
		if filePerm&insecMode == insecMode {
			return true
		}
	}
	return false
}

func keepRenewingToken() error {
	for {
		var (
			lease *api.Secret
			err   error
		)
		if lease, err = client.Auth().Token().RenewSelf(tokenRenewValidity); err != nil {
			return fmt.Errorf("renewing token: %w", err)
		}

		log.Debugf("Token renewed for another %d seconds.", lease.Auth.LeaseDuration)

		<-time.After(time.Duration(lease.Auth.LeaseDuration)*time.Second - tokenRenewEarly)
	}
}

func authenticateVault(roleSecret string) error {
	data := map[string]any{
		"role_id":   cfg.VaultRoleID,
		"secret_id": roleSecret,
	}

	loginSecret, err := client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("logging in using approle: %w", err)
	}

	if loginSecret.Auth == nil {
		return fmt.Errorf("no loginsecret-auth returned")
	}

	client.SetToken(loginSecret.Auth.ClientToken)

	tokenFile, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return fmt.Errorf("expanding token file path: %w", err)
	}

	if err = os.WriteFile(tokenFile, []byte(loginSecret.Auth.ClientToken), vaultTokenFilePerms); err != nil {
		return fmt.Errorf("writing vault token file: %w", err)
	}

	return nil
}
