package ppe

import (
	"bytes"
	"net"
)

type UDPConn struct {
	*net.UDPConn
	*net.UDPAddr
	readBuffer int
	buf        *bytes.Buffer
}

func NewUDPConn(conn *net.UDPConn, readbuf int) *UDPConn {
	return &UDPConn{conn, nil, readbuf, new(bytes.Buffer)}
}

func (u *UDPConn) Read(p []byte) (n int, err error) {
	if u.buf.Len() != 0 {
		n, err = u.buf.Read(p)
		return
	}
	b := make([]byte, u.readBuffer)
	n, u.UDPAddr, err = u.ReadFromUDP(b)
	if err != nil {
		return
	}
	_, err = u.buf.Write(b[:n])
	if err != nil {
		return
	}
	return u.Read(p)
}

func (u *UDPConn) Write(p []byte) (n int, err error) {
	if u.UDPAddr == nil {
		n, err = u.UDPConn.Write(p)
	} else {
		n, err = u.WriteToUDP(p, u.UDPAddr)
	}
	return
}
