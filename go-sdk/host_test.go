/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2027. All rights reserved.
 */

package sdk

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// Use a real SSH channel so the probe and the forwarding reader share the
// actual channel buffering and close behavior.
func relayChannelPair(t *testing.T) (context.Context, *ssh.Channel, *ssh.Channel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer listener.Close()
	clientConn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	serverConn, err := listener.Accept()
	if err != nil {
		cancel()
		_ = clientConn.Close()
		t.Fatal(err)
	}
	client := ssh.NewClientSession(ssh.NewNoSecurityConfig())
	server := ssh.NewServerSession(ssh.NewNoSecurityConfig())
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		_ = serverConn.Close()
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()
	connected := make(chan error, 1)
	go func() { connected <- server.Connect(ctx, serverConn) }()
	if err := client.Connect(ctx, clientConn); err != nil {
		t.Fatal(err)
	}
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	sender, err := server.OpenChannelWithType(ctx, relayChannelType)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := client.AcceptChannel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, sender, receiver
}

func TestReadPortNotificationPreservesNonNotificationBytes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		payload []byte
	}{
		{"banner", []byte("SSH-2.0-RelayClient\r\n")},
		{"banner and buffered tail", append([]byte("SSH-2.0-RelayClient\r\n"), bytes.Repeat([]byte{0x01}, 5000)...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := tt.payload
			ctx, sender, receiver := relayChannelPair(t)
			if err := sender.Send(ctx, payload); err != nil {
				t.Fatal(err)
			}
			stream, ports, isNotification := readPortNotification(receiver)
			if isNotification || stream == nil || len(ports) != 0 {
				t.Fatal("SSH data was classified as a port notification")
			}
			if err := sender.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("forwarded %d bytes, want all %d bytes including the SSH banner", len(got), len(payload))
			}
		})
	}
}

func TestReadPortNotificationConsumesNotification(t *testing.T) {
	ctx, sender, receiver := relayChannelPair(t)
	if err := sender.Send(ctx, []byte(`{"@type":"RelayRequest","ports":[8080,9090]}`)); err != nil {
		t.Fatal(err)
	}
	stream, ports, isNotification := readPortNotification(receiver)
	if !isNotification || stream != nil || len(ports) != 2 || ports[0] != 8080 || ports[1] != 9090 {
		t.Fatalf("notification not consumed: stream=%v ports=%v isNotification=%v", stream, ports, isNotification)
	}
	if !receiver.IsClosed() {
		t.Fatal("notification channel was left open")
	}
}

func TestRelayWithoutNotificationCompletesInnerSSHHandshake(t *testing.T) {
	ctx, sender, receiver := relayChannelPair(t)
	if err := ensureHostKey(); err != nil {
		t.Fatal(err)
	}
	d := &Devbridge{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	hostStream := make(chan io.ReadWriteCloser, 1)
	go func() {
		stream, _, isNotification := readPortNotification(receiver)
		if isNotification {
			hostStream <- nil
			return
		}
		d.handleRelayChannel(ctx, receiver, stream, nil)
		hostStream <- stream
	}()
	innerClient := ssh.NewClientSession(ssh.NewNoSecurityConfig())
	t.Cleanup(func() { _ = innerClient.Close() })
	if err := innerClient.Connect(ctx, ssh.NewStream(sender)); err != nil {
		t.Fatalf("inner SSH handshake after notification probe: %v", err)
	}
	// Opening a channel proves the inner server finished the handshake too,
	// including its writes through the replay wrapper.
	channel, err := innerClient.OpenChannel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	select {
	case stream := <-hostStream:
		if stream == nil {
			t.Fatal("SSH handshake was classified as a notification")
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if !receiver.IsClosed() {
			t.Fatal("closing the replay stream did not close the relay channel")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
