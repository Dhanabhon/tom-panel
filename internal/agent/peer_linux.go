//go:build linux

package agent

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func init() {
	defaultPeerCredentials = linuxPeerCredentials
}

func linuxPeerCredentials(conn net.Conn) (PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerCredentials{}, fmt.Errorf("peer connection is %T, not *net.UnixConn", conn)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return PeerCredentials{}, err
	}

	var credentials PeerCredentials
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		credentials = PeerCredentials{PID: peer.Pid, UID: peer.Uid, GID: peer.Gid}
	}); err != nil {
		return PeerCredentials{}, err
	}
	if socketErr != nil {
		return PeerCredentials{}, socketErr
	}
	return credentials, nil
}
