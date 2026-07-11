// seaweedfs-launcher keeps every SeaweedFS control/data-plane listener on
// loopback and exposes only the authenticated S3 listener to the container
// network. The accepted argument vector is intentionally exact so Compose
// cannot accidentally override the isolation contract.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const (
	publicAddress  = "0.0.0.0:9000"
	privateAddress = "127.0.0.1:8333"
	shutdownGrace  = 10 * time.Second
)

var publicArguments = []string{
	"mini",
	"-dir=/data",
	"-s3.port=9000",
	"-bucket=hallu-backups,hallu-primary,hallu-backup-replica",
}

var privateArguments = []string{
	"mini",
	"-dir=/data",
	"-ip=127.0.0.1",
	"-ip.bind=127.0.0.1",
	"-s3.port=8333",
	"-s3.port.iceberg=0",
	"-s3.iam=false",
	"-bucket=hallu-backups,hallu-primary,hallu-backup-replica",
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	if !equalArguments(arguments, publicArguments) {
		fmt.Fprintln(os.Stderr, "seaweedfs-launcher: unsupported argument vector")
		return 2
	}

	listener, err := net.Listen("tcp4", publicAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seaweedfs-launcher: public S3 listener failed")
		return 1
	}

	command := exec.Command("/usr/local/bin/weed", privateArguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, "seaweedfs-launcher: SeaweedFS failed to start")
		return 1
	}

	go serve(listener)
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-waited:
		_ = listener.Close()
		return childExitCode(err)
	case received := <-signals:
		_ = listener.Close()
		_ = command.Process.Signal(received)
		select {
		case err := <-waited:
			return childExitCode(err)
		case <-time.After(shutdownGrace):
			_ = command.Process.Kill()
			return childExitCode(<-waited)
		}
	}
}

func serve(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go proxy(connection)
	}
}

func proxy(client net.Conn) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp4", privateAddress, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	completed := make(chan struct{}, 2)
	go copyHalf(upstream, client, completed)
	go copyHalf(client, upstream, completed)
	<-completed
	_ = client.Close()
	_ = upstream.Close()
	<-completed
}

func copyHalf(destination net.Conn, source net.Conn, completed chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	if tcp, ok := destination.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	completed <- struct{}{}
}

func equalArguments(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return 1
}
