package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agent"
	"golang.org/x/sys/unix"
)

const (
	runtimeDirectory = "/run/tompanel"
	socketPath       = runtimeDirectory + "/agent.sock"
	lockPath         = runtimeDirectory + "/agent.lock"
)

var errAgentAlreadyRunning = errors.New("tompanel-agent is already running")

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
	listener, instanceLock, ownedSocket, err := listenAgentSocket(socketPath, lockPath)
	if err != nil {
		log.Fatal(err)
	}
	defer instanceLock.Close()
	defer func() {
		if err := removeOwnedSocket(socketPath, ownedSocket); err != nil {
			log.Printf("remove agent socket: %v", err)
		}
		_ = listener.Close()
	}()
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
		_ = listener.SetDeadline(time.Now())
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

func listenAgentSocket(socketPath, lockPath string) (*net.UnixListener, *os.File, os.FileInfo, error) {
	instanceLock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := unix.Flock(int(instanceLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = instanceLock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, nil, errAgentAlreadyRunning
		}
		return nil, nil, nil, fmt.Errorf("lock agent instance: %w", err)
	}
	if err := instanceLock.Chmod(0o600); err != nil {
		_ = instanceLock.Close()
		return nil, nil, nil, err
	}
	if err := removeStaleSocket(socketPath); err != nil {
		_ = instanceLock.Close()
		return nil, nil, nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		_ = instanceLock.Close()
		return nil, nil, nil, err
	}
	listener.SetUnlinkOnClose(false)
	ownedSocket, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		_ = instanceLock.Close()
		return nil, nil, nil, err
	}
	return listener, instanceLock, ownedSocket, nil
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
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("agent socket is already in use")
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("check existing agent socket: %w", err)
	}
	return os.Remove(path)
}

func removeOwnedSocket(path string, owned os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(owned, current) {
		return nil
	}
	return os.Remove(path)
}
