package hysteria2

import (
	"io"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (c *udpPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return options.NeedHeadroom()
}

func (c *udpPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		destination = M.ParseSocksaddr(p.destination)
		if c.readWaitOptions.NeedHeadroom() {
			buffer = c.readWaitOptions.NewPacketBuffer()
			_, err = buffer.Write(p.data.Bytes())
			if err != nil {
				buffer.Release()
				return nil, M.Socksaddr{}, err
			}
			p.releaseMessage()
			c.readWaitOptions.PostReturn(buffer)
		} else {
			buffer = p.data
			p.release()
		}
		return
	case <-c.ctx.Done():
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	}
}
