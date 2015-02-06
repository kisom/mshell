// mshelld is the process that runs on the target remote machine.
// It connects to the server and accepts incoming messages with
// shell commands.
package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/gokyle/goconfig"
	"github.com/kisom/die"
	"github.com/kisom/go-schannel/schannel"
)

type ident struct {
	PrivateFile string
	Private     *[schannel.IdentityPrivateSize]byte
	PublicFile  string
	Public      *[schannel.IdentityPublicSize]byte
}

var server, self ident

var configOpts struct {
	// Address of mshell-server.
	Address string
}

func readFile(path string, data []byte) {
	file, err := os.Open(path)
	die.If(err)
	defer file.Close()

	_, err = io.ReadFull(file, data)
	die.If(err)
}

func writeTempFile(contents []byte) (string, error) {
	tf, err := ioutil.TempFile("", "mshell-")
	if err != nil {
		return "", err
	}
	tfname := tf.Name()
	defer tf.Close()

	_, err = tf.Write(contents)
	return tfname, err
}

func loadIdentities() {
	server.Public = new([schannel.IdentityPublicSize]byte)
	readFile(server.PublicFile, server.Public[:])

	self.Private = new([schannel.IdentityPrivateSize]byte)
	readFile(self.PrivateFile, self.Private[:])
}

func parseConfig(configFile string) {
	cfg, err := goconfig.ParseFile(configFile)
	die.If(err)

	var ok bool
	server.PublicFile, ok = cfg.GetValue("identity", "server")
	if !ok {
		die.With("no server key specified")
	}

	self.PrivateFile, ok = cfg.GetValue("identity", "private")
	if !ok {
		die.With("no identity key specified")
	}

	loadIdentities()

	configOpts.Address, ok = cfg.GetValue("mshelld", "address")
	if !ok {
		die.With("no server address specific")
	}
}

func logErr(err error) {
	log.Printf("%v", err)
}

func session() {
	conn, err := net.Dial("tcp", configOpts.Address)
	if err != nil {
		logErr(err)
		return
	}

	_, err = conn.Write([]byte("t"))
	if err != nil {
		conn.Close()
		logErr(err)
	}

	sch, ok := schannel.Dial(conn, self.Private, server.Public)
	if !ok {
		log.Printf("secure channel failed")
		conn.Close()
		return
	}
	defer func() {
		sch.Close()
		conn.Close()
	}()
	log.Printf("secure channel established")

	for {
		m, ok := sch.Receive()
		if !ok {
			log.Print("failed to receive message")
			return
		}

		switch m.Type {
		case schannel.ShutdownMessage:
			log.Printf("peer is closing connection")
			return
		case schannel.KEXMessage:
			log.Printf("peer rotated keys")
			continue
		case schannel.NormalMessage:
			tfname, err := writeTempFile(m.Contents)
			if err != nil {
				log.Printf("failed to write temp file: %v", err)
				os.Remove(tfname)
				return
			}
			log.Printf("PATH: %s", os.Getenv("PATH"))
			cmd := exec.Command("sh", tfname)
			log.Printf("command line: %s", m.Contents)
			out, err := cmd.CombinedOutput()
			os.Remove(tfname)
			if err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					log.Printf("failed to execute command")
					logErr(err)
					break
				}
			}

			if len(out) == 0 {
				out = []byte("<no output>")
			}
			ok = sch.Send(out)
			if !ok {
				log.Printf("failed to send message")
				return
			}
			break
		}
	}
}

func main() {
	configFile := flag.String("f", "/etc/mshell/mshelld.conf",
		"path to config file")
	flag.Parse()

	parseConfig(*configFile)

	for {
		session()
		<-time.After(10 * time.Second)
	}
}
