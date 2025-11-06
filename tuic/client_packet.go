package tuic

import (
	"io"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

func (c *Client) loopMessages(conn *clientQUICConnection) {
	for {
		message, err := conn.quicConn.ReceiveDatagram(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "receive message"))
			return
		}
		go func() {
			hErr := c.handleMessage(conn, message)
			if hErr != nil {
				conn.closeWithError(E.Cause(hErr, "handle message"))
			}
		}()
	}
}

func (c *Client) handleMessage(conn *clientQUICConnection, data []byte) error {
	if len(data) < 2 {
		return E.New("invalid message")
	}
	if data[0] != Version {
		return E.New("unknown version ", data[0])
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:])
		if err != nil {
			message.release()
			return E.Cause(err, "decode UDP message")
		}
		conn.handleUDPMessage(message)
	default:
		if c.logger != nil {
			c.logger.Warn("unknown command ", data[1])
		}
	}
	return nil
}

func (c *Client) loopUniStreams(conn *clientQUICConnection) {
	for {
		stream, err := conn.quicConn.AcceptUniStream(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "handle uni stream"))
			return
		}
		go func() {
			hErr := c.handleUniStream(conn, stream)
			if hErr != nil {
				conn.closeWithError(hErr)
			}
		}()
	}
}

func (c *Client) handleUniStream(conn *clientQUICConnection, stream quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	buffer := buf.NewPacket()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return err
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", version)
	}
	command, _ := buffer.ReadByte()
	switch command {
	case CommandPacket:
		reader := io.MultiReader(bufio.NewCachedReader(stream, buffer), stream)
		message := allocMessage()
		err = readUDPMessage(message, reader)
		if err != nil {
			message.release()
			return err
		}
		conn.handleUDPMessage(message)
	default:
		if c.logger != nil {
			c.logger.Warn("unknown command ", command)
		}
	}
	return nil
}

func (c *clientQUICConnection) handleUDPMessage(message *udpMessage) {
	c.udpAccess.RLock()
	udpConn, loaded := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if !loaded {
		message.releaseMessage()
		return
	}
	select {
	case <-udpConn.ctx.Done():
		message.releaseMessage()
		return
	default:
	}
	udpConn.inputPacket(message)
}
