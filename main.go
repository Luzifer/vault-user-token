package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/Luzifer/rconfig"
	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
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

	hostname string
	client   *api.Client
)

func init() {
	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-user-token %s\n", version)
		os.Exit(0)
	}

	if cfg.VaultRoleID == "" {
		log.Fatalf("You need to supply a role id for this to work")
	}

	if logLevel, err := log.ParseLevel(cfg.LogLevel); err == nil {
		log.SetLevel(logLevel)
	} else {
		log.Fatalf("Unable to parse log level: %s", err)
	}

	var err error
	if hostname, err = os.Hostname(); err != nil {
		log.Fatalf("Could not resolve hostname: %s", err)
	}

	if parts := strings.Split(hostname, "."); !cfg.UseFullHostname && len(parts) > 1 {
		hostname = parts[0]
	}
}

func main() {
	var err error
	client, err = api.NewClient(&api.Config{
		Address: cfg.VaultAddress,
	})

	if err != nil {
		log.Fatalf("Unable to create new vault client: %s", err)
	}

	for {
		if err := authenticateVault(); err != nil {
			log.Fatalf("Unable to authenticate vault: %s", err)
		}

		keepRenewingToken()
	}
}

func keepRenewingToken() error {
	for {
		var (
			lease *api.Secret
			err   error
		)
		if lease, err = client.Auth().Token().RenewSelf(900); err != nil {
			log.Errorf("Could not renew token: %s", err)
			return err
		}

		log.Debugf("Token renewed for another %d seconds.", lease.Auth.LeaseDuration)

		<-time.After((time.Duration(lease.Auth.LeaseDuration) - 30) * time.Second)
	}
}

func authenticateVault() error {
	data := map[string]interface{}{
		"role_id":   cfg.VaultRoleID,
		"secret_id": hostname,
	}

	loginSecret, lserr := client.Logical().Write("auth/approle/login", data)
	if lserr != nil || loginSecret.Auth == nil {
		return lserr
	}

	client.SetToken(loginSecret.Auth.ClientToken)

	tokenFile, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(tokenFile, []byte(loginSecret.Auth.ClientToken), 0600)
}
