package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/cli"
)

func mintFactory() (cli.Command, error) {
	return &mintCommand{
		ui: ui(),
	}, nil
}

type mintCommand struct {
	ui cli.Ui

	flags *flag.FlagSet

	privKeyFile string
	ttl         time.Duration
	typ         string
	nodeName    string
	server      bool
}

func (c *mintCommand) Help() string {
	return `Create a new intro token.`
}

func (c *mintCommand) Synopsis() string {
	return `Create a new intro token.`
}

func (c *mintCommand) Run(args []string) int {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.StringVar(&c.privKeyFile, "priv-key", "secint-priv-key.pem", "private key file in PEM format")
	c.flags.DurationVar(&c.ttl, "ttl", 30*time.Second, "duration the generated token is valid for")
	c.flags.BoolVar(&c.server, "server", false, "whether this token is for a server.")
	c.flags.StringVar(&c.nodeName, "node", "", "the name of the node")

	if err := c.flags.Parse(args); err != nil {
		return 1
	}

	if c.nodeName == "" {
		c.ui.Error("ERROR: node name must be set")
		return 1
	}
	if c.ttl > 24*time.Hour {
		c.ui.Error("ERROR: duration can't be more than 1 hour")
		return 1
	}
	if c.ttl < time.Second {
		c.ui.Error("ERROR: duration can't be less than 1 second")
		return 1
	}

	// Load the private key
	pk, err := privKeyFromFile(c.privKeyFile)
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to read private key file: %s", err))
		return 1
	}

	now := time.Now()

	claims := jws.Claims{}
	claims.SetExpiration(now.Add(c.ttl))
	claims.SetSubject(c.nodeName)
	id, err := uuid.GenerateUUID()
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to generate UUID: %s", err))
		return 1
	}
	claims.SetJWTID(id)
	if c.server {
		claims.Set("server", true)
	}

	jwt := jws.NewJWT(claims, crypto.SigningMethodES256)

	b, err := jwt.Serialize(pk)
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to create token: %s", err))
		return 1
	}

	c.ui.Output(string(b))

	return 0
}

func privKeyFromFile(fileName string) (*ecdsa.PrivateKey, error) {
	bs, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return crypto.ParseECPrivateKeyFromPEM(bs)
}
