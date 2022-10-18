package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/Luzifer/rconfig/v2"
)

const (
	tokenRenewValidity  = 900 // Seconds
	tokenRenewEarly     = 30 * time.Second
	vaultTokenFilePerms = 0o600
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

func init() {
	rconfig.AutoEnv(true)
	if err := rconfig.Parse(&cfg); err != nil {
		log.WithError(err).Fatal("Unable to parse commandline options")
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-user-token %s\n", version) //revive:disable:unhandled-error // printing to stdout is not expected to err
		os.Exit(0)
	}

	if cfg.VaultRoleID == "" {
		log.Fatal("You need to supply a role id for this to work")
	}

	if logLevel, err := log.ParseLevel(cfg.LogLevel); err == nil {
		log.SetLevel(logLevel)
	} else {
		log.WithError(err).Fatal("Unable to parse log level")
	}
}

func main() {
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
		return "", errors.Wrap(err, "expanding location of secret override")
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
		return "", errors.Wrap(err, "resolving hostname")
	}

	if parts := strings.Split(secret, "."); !cfg.UseFullHostname && len(parts) > 1 {
		secret = parts[0]
	}

	return secret, nil
}

func hasInsecurePermission(filePerm os.FileMode) bool {
	for _, insecMode := range []os.FileMode{0o040, 0o020, 0o004, 0o002} {
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
			return errors.Wrap(err, "renewing token")
		}

		log.Debugf("Token renewed for another %d seconds.", lease.Auth.LeaseDuration)

		<-time.After(time.Duration(lease.Auth.LeaseDuration)*time.Second - tokenRenewEarly)
	}
}

func authenticateVault(roleSecret string) error {
	data := map[string]interface{}{
		"role_id":   cfg.VaultRoleID,
		"secret_id": roleSecret,
	}

	loginSecret, lserr := client.Logical().Write("auth/approle/login", data)
	if lserr != nil || loginSecret.Auth == nil {
		return errors.Wrap(lserr, "logging in using approle")
	}

	client.SetToken(loginSecret.Auth.ClientToken)

	tokenFile, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return errors.Wrap(err, "expanding token file path")
	}

	return errors.Wrap(
		os.WriteFile(tokenFile, []byte(loginSecret.Auth.ClientToken), vaultTokenFilePerms),
		"writing vault token file",
	)
}
