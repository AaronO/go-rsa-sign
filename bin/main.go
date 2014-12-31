package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/codegangsta/cli"

	"github.com/AaronO/go-rsa-sign"
)

func main() {
	app := cli.NewApp()

	// Global app config
	app.Name = "rsa-sign"
	app.Usage = "Sign and verify documents/payload using RSA keys"
	app.Version = "0.0.0"
	app.Email = "aaron.omullan@gmail.com"
	app.EnableBashCompletion = true

	keyFlag := cli.StringFlag{
		Name:  "key, k",
		Usage: "Public or private key to use",
	}
	fileFlag := cli.StringFlag{
		Name:  "file, f",
		Usage: "File to sign or verify",
	}
	sigFlag := cli.StringFlag{
		Name:  "signature, s",
		Usage: "Signature to verify",
	}

	app.Commands = []cli.Command{
		{
			Name:      "sign",
			ShortName: "s",
			Usage:     "Sign a file or message",
			Action: func(c *cli.Context) {
				keyfile := c.String("key")
				filename := c.String("file")

				key := fileOrMessage(keyfile)
				data := fileOrMessage(filename)

				sig, err := sign.SignBase64(key, data)
				if err != nil {
					log.Fatal(err)
					return
				}
				fmt.Println(sig)
			},
			Flags: []cli.Flag{
				keyFlag,
				fileFlag,
			},
		},
		{
			Name:      "verify",
			ShortName: "v",
			Usage:     "Verify a file or message",
			Action: func(c *cli.Context) {
				keyfile := c.String("key")
				filename := c.String("file")
				sigfile := c.String("signature")

				key := fileOrMessage(keyfile)
				data := fileOrMessage(filename)
				sig := fileOrMessage(sigfile)

				err := sign.VerifyBase64(key, data, string(sig))
				fmt.Println(err == nil)
			},
			Flags: []cli.Flag{
				keyFlag,
				fileFlag,
				sigFlag,
			},
		},
	}

	app.Run(os.Args)
}

func fileOrMessage(filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err == nil {
		return data
	}
	return []byte(filename)
}
