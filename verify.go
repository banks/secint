package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/mitchellh/cli"
)

func verifyFactory() (cli.Command, error) {
	return &verifyCommand{
		ui: ui(),
	}, nil
}

type verifyCommand struct {
	ui cli.Ui

	flags *flag.FlagSet

	pubKeyFile string
	nodeName   string
	server     bool
}

func (c *verifyCommand) Help() string {
	return `Verify an intro token from stdin.`
}

func (c *verifyCommand) Synopsis() string {
	return `Verify an intro token from stdin.`
}

func (c *verifyCommand) Run(args []string) int {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.StringVar(&c.pubKeyFile, "pub-key", "secint-pub-key.pem", "public key file in PEM format")
	c.flags.BoolVar(&c.server, "server", false, "whether this token is expected to be for a server.")
	c.flags.StringVar(&c.nodeName, "node", "", "the name of the node expected.")

	if err := c.flags.Parse(args); err != nil {
		return 1
	}

	// Load the public key
	key, err := pubKeyFromFile(c.pubKeyFile)
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to read private key file: %s", err))
		return 1
	}

	tokenBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to read token from stdin: %s", err))
		return 1
	}

	jwt, err := jws.ParseJWT(tokenBytes)
	if err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to parse JWT: %s", err))
		return 1
	}

	// Verify token
	if err := jwt.Validate(key, crypto.SigningMethodES256); err != nil {
		c.ui.Error(fmt.Sprintf("ERROR: failed to verify token: %s", err))
		return 1
	}

	claims := jwt.Claims()

	id, ok := claims.JWTID()
	if !ok {
		c.ui.Error(fmt.Sprintf("ERROR: no ID in token"))
		return 1
	}

	sub, ok := claims.Subject()
	if !ok {
		c.ui.Error(fmt.Sprintf("ERROR: no subject in token"))
		return 1
	}
	if c.nodeName != "" && c.nodeName != sub {
		c.ui.Error(fmt.Sprintf("ERROR: token doesn't match expected node name.\n"+
			"Got %q expect %q", sub, c.nodeName))
		return 1
	}

	server, ok := claims.Get("server").(bool)
	isServer := "NO"
	if ok && server {
		isServer = "YES"
	} else {
		// Not a server token
		if c.server {
			c.ui.Error("ERROR: token is not a server token but one is expected.")
			return 1
		}
		c.ui.Output("Server Allowed:     NO")
	}

	c.ui.Output(fmt.Sprintf("JWT ID            : %s", id))
	c.ui.Output(fmt.Sprintf("Verified Node Name: %s", sub))
	c.ui.Output(fmt.Sprintf("Server Token      : %s", isServer))
	c.ui.Output("VALID")

	return 0
}

func pubKeyFromFile(fileName string) (*ecdsa.PublicKey, error) {
	bs, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return crypto.ParseECPublicKeyFromPEM(bs)
}
