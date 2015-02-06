// mshell connects to an mshell server and sends it a command line. The
// server passes the command line onto the target, which executes it and
// returns the result to the peer via the server.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/gokyle/goconfig"
	"github.com/kisom/die"
	"github.com/kisom/go-schannel/schannel"
)

var (
	private   [schannel.IdentityPrivateSize]byte
	serverPub [schannel.IdentityPublicSize]byte
)

func readFile(path string, data []byte) {
	file, err := os.Open(path)
	die.If(err)
	defer file.Close()

	_, err = io.ReadFull(file, data)
	die.If(err)
}

func loadIdentities(pubFile, privFile string) {
	readFile(pubFile, serverPub[:])
	readFile(privFile, private[:])
}

func parseConfig(configFile string) {
	cfg, err := goconfig.ParseFile(configFile)
	die.If(err)

	pubFile, ok := cfg.GetValue("identity", "server")
	if !ok {
		die.With("no server key specified")
	}

	privFile, ok := cfg.GetValue("identity", "private")
	if !ok {
		die.With("no identity key specified")
	}

	loadIdentities(pubFile, privFile)

	configOpts.Address, ok = cfg.GetValue("mshell", "address")
	if !ok {
		die.With("no server address specific")
	}
}

var configOpts struct {
	Address string
}

// readLine reads a line of input from the user.
func readLine(prompt string) (line string, err error) {
	fmt.Printf(prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err = rd.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	return
}

func main() {
	configFile := flag.String("f", "/etc/mshell/mshell.conf",
		"path to config file")
	flag.Parse()

	parseConfig(*configFile)
	conn, err := net.Dial("tcp", configOpts.Address)
	die.If(err)

	_, err = conn.Write([]byte("c"))
	die.If(err)

	sch, ok := schannel.Dial(conn, &private, &serverPub)
	if !ok {
		conn.Close()
		die.With("failed to set up secure session")
	}

	defer func() {
		sch.Close()
		conn.Close()
	}()

	for {
		cmdLine, err := readLine("> ")
		die.If(err)

		if cmdLine == "exit" || cmdLine == "quit" {
			fmt.Println("Byte.")
			return
		}

		if !sch.Send([]byte(cmdLine)) {
			die.With("failed to send command")
		}

		m, ok := sch.Receive()
		if !ok {
			die.With("failed to receve message")
		}

		switch m.Type {
		case schannel.ShutdownMessage:
			fmt.Println("[*] server is shutting down channel")
			return
		case schannel.KEXMessage:
			fmt.Println("[*] server has rotated keys")
			return
		case schannel.NormalMessage:
			fmt.Printf("output:\n------\n%s\n", m.Contents)
		}

	}
}
