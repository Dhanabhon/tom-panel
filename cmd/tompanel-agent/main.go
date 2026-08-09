package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/Dhanabhon/tom-panel/internal/agent"
)

const (
	runtimeDirectory = "/run/tompanel"
	socketPath       = runtimeDirectory + "/agent.sock"
)

func main() {
	serviceUser, err := user.Lookup("tompanel")
	if err != nil {
		log.Fatal(err)
	}
	uid, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	gid, err := strconv.Atoi(serviceUser.Gid)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(runtimeDirectory, 0o750); err != nil {
		log.Fatal(err)
	}
	if err := os.Chown(runtimeDirectory, 0, gid); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(runtimeDirectory, 0o750); err != nil {
		log.Fatal(err)
	}
	if err := removeStaleSocket(socketPath); err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chown(socketPath, 0, gid); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf("tompanel-agent listening on %s", socketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept agent connection: %v", err)
			continue
		}
		go func() {
			defer conn.Close()
			if err := agent.NewServer(conn, uint32(uid)).ServeOne(ctx); err != nil {
				log.Printf("serve agent request: %v", err)
			}
		}()
	}
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("agent socket path exists and is not a socket")
	}
	return os.Remove(path)
}
