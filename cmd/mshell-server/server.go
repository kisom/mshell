// mshell-server is the middle layer that accepts connections from
// peers and the target machine. It relays commands from peers to
// the target machine.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"

	"github.com/kisom/die"
	"github.com/kisom/go-schannel/schannel"
)

var serverKey [schannel.IdentityPrivateSize]byte
var peerPub, targetPub [schannel.IdentityPublicSize]byte

func readFile(path string, data []byte) {
	file, err := os.Open(path)
	die.If(err)
	defer file.Close()

	_, err = io.ReadFull(file, data)
	die.If(err)
}

func logErr(err error) {
	log.Printf("%v", err)
}

func peerListener(conn net.Conn, targetChan chan command) {
	sch, ok := schannel.Listen(conn, &serverKey, &peerPub)
	if !ok {
		log.Printf("failed to set up secure channel with target")
		conn.Close()
		return
	}

	defer func() {
		sch.Close()
		conn.Close()
	}()
	log.Println("secure channel established")

	for {
		log.Printf("waiting to receive message")
		m, ok := sch.Receive()
		if !ok {
			log.Printf("failed to receive message from target")
			return
		}

		switch m.Type {
		case schannel.ShutdownMessage:
			log.Printf("peer is shutting down the channel")
			return
		case schannel.KEXMessage:
			log.Printf("peer has rotated keys")
			break
		case schannel.NormalMessage:
			log.Printf("received command line: %s", m.Contents)
			command := command{
				CmdLine: m.Contents,
				Respond: make(chan []byte),
			}
			targetChan <- command

			out, ok := <-command.Respond
			if !ok {
				return
			}
			if !sch.Send(out) {
				log.Printf("failed to send response")
				return
			}
			close(command.Respond)
		}

	}
}

type command struct {
	CmdLine []byte
	Respond chan []byte
}

func targetListener(conn net.Conn, targetChan chan command) {
	sch, ok := schannel.Listen(conn, &serverKey, &targetPub)
	if !ok {
		log.Printf("failed to set up secure channel with target")
		conn.Close()
		return
	}

	defer func() {
		sch.Close()
		log.Printf("secure channel with target shut down")
		conn.Close()
	}()
	log.Printf("secure channel established with target")

	for {
		command, ok := <-targetChan
		if !ok {
			log.Printf("target channel closed")
			return
		}
		log.Printf("command received")

		if !sch.Send(command.CmdLine) {
			log.Printf("failed to send command line")
			close(command.Respond)
			return
		}

		for {
			m, ok := sch.Receive()
			if !ok {
				log.Printf("failed to receive message from target")
				close(command.Respond)
				return
			}

			switch m.Type {
			case schannel.ShutdownMessage:
				close(command.Respond)
				log.Printf("target is shutting down the channel")
				return
			case schannel.KEXMessage:
				log.Printf("target has rotated keys")
				continue
			case schannel.NormalMessage:
				command.Respond <- m.Contents
				log.Printf("command output forwarded")
				break
			}
			break
		}
	}
}

func main() {
	addr := flag.String("a", ":6000", "address to listen on")
	serverFile := flag.String("k", "/etc/mshell/server.key", "server identity private key")
	peerFile := flag.String("p", "/etc/mshell/peer.pub", "peer identity public key")
	targetFile := flag.String("t", "/etc/mshell/client.pub", "target identity public key")
	flag.Parse()

	readFile(*peerFile, peerPub[:])
	readFile(*targetFile, targetPub[:])
	readFile(*serverFile, serverKey[:])

	targetChan := make(chan command, 4)

	ln, err := net.Listen("tcp", *addr)
	die.If(err)

	log.Printf("listening on %s", *addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logErr(err)
			continue
		}

		var from = make([]byte, 1)
		_, err = conn.Read(from)
		if err != nil {
			logErr(err)
			continue
		}

		switch from[0] {
		case 't':
			log.Printf("target connected")
			go targetListener(conn, targetChan)
		case 'c':
			log.Printf("client connected")
			go peerListener(conn, targetChan)
		default:
			log.Printf("unknown peer: %v", from)
		}
	}
}
