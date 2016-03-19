package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ArtemKulyabin/cryptostack"
	"github.com/bgentry/speakeasy"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "jsign"
	app.Usage = ""
	app.Version = "0.0.1"

	app.Commands = []cli.Command{
		{
			Name:   "generate",
			Usage:  "generate keys",
			Action: generate,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "no-password",
				},
			},
		},
		{
			Name:   "sign",
			Usage:  "sign file",
			Action: sign,
		},
		{
			Name:   "verify",
			Usage:  "verify file",
			Action: verify,
		},
	}
	app.Run(os.Args)
}

func generate(c *cli.Context) {
	skey, err := cryptostack.GenerateKey()
	if err != nil {
		log.Fatalln(err)
	}
	if !c.Bool("no-password") {
		password, err := speakeasy.Ask("Please enter a password: ")
		if err != nil {
			log.Fatalln(err)
		}
		skey.Encrypt([]byte(password))
	}
	bc, err := json.MarshalIndent(skey, "", " ")
	if err != nil {
		log.Fatalln(err)
	}

	skeyFile := c.Args().First()
	if skeyFile != "" {
		err = ioutil.WriteFile(skeyFile+".jkey", bc, 0400)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		fmt.Print(string(bc))
	}

	pkeyFile := c.Args().Get(1)
	if pkeyFile != "" {
		bc, err = json.MarshalIndent(skey.GetPkey(), "", " ")
		if err != nil {
			log.Fatalln(err)
		}
		err = ioutil.WriteFile(pkeyFile+".jkey", bc, 0400)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func sign(c *cli.Context) {
	skeyFile := c.Args().First()
	skeyBuf, err := ioutil.ReadFile(skeyFile + ".jkey")
	if err != nil {
		log.Fatalln(err)
	}
	skey := cryptostack.Skey{}
	err = json.Unmarshal(skeyBuf, &skey)
	if err != nil {
		log.Fatalln(err)
	}

	if !c.Bool("no-password") {
		password, err := speakeasy.Ask("Please enter a password: ")
		if err != nil {
			log.Fatalln(err)
		}
		skey.Decrypt([]byte(password))
	}

	sig := cryptostack.NewSignature(skey.GetPkey())

	file := c.Args().Get(1)

	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}

	err = sig.Sign(&skey, f)
	if err != nil {
		log.Fatalln(err)
	}

	sigBuf, err := json.MarshalIndent(sig, "", " ")
	err = ioutil.WriteFile(strings.Join([]string{file, "jsig"}, "."), sigBuf, 0644)
	if err != nil {
		log.Fatalln(err)
	}
}

func verify(c *cli.Context) {
	pkeyFile := c.Args().First()
	pkeyBuf, err := ioutil.ReadFile(pkeyFile + ".jkey")
	if err != nil {
		log.Fatalln(err)
	}
	pkey := cryptostack.Pkey{}
	err = json.Unmarshal(pkeyBuf, &pkey)
	if err != nil {
		log.Fatalln(err)
	}

	file := c.Args().Get(1)

	sigFile := strings.Join([]string{file, "jsig"}, ".")
	sigBuf, err := ioutil.ReadFile(sigFile)
	if err != nil {
		log.Fatalln(err)
	}
	sig := cryptostack.Signature{}
	err = json.Unmarshal(sigBuf, &sig)
	if err != nil {
		log.Fatalln(err)
	}

	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}

	err = sig.Verify(f)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Ok")
}
