package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/http"
)

type OpCode int
type DataType byte
type Framing byte

const (
	Ping OpCode = iota
	Close
	Text
	G
)

const (
	Continuation byte = iota
	Utf8
	Byte
)

const (
	Fin byte = 1 << 7
)

type WebSocket struct {
	Inbox    chan []byte
	Closed   chan bool
	rw       *bufio.ReadWriter
	conn     net.Conn
	DataType byte
}

func (ws *WebSocket) Worker() {

	for {

		select {
		case <-ws.Closed:
			return
		case message := <-ws.Inbox:
			ws.writeFrame(message)
		}
	}

}

func (ws *WebSocket) Write(b []byte) {
	//prolly good place to highwatermark + close
	ws.Inbox <- b
}

func (ws *WebSocket) WriteS(s string) {
	ws.Write([]byte(s))
}

func (ws *WebSocket) Close() error {
	return ws.conn.Close()
}

func (ws *WebSocket) Read() (string, OpCode, error) {
	return readFrame(ws.rw.Reader)
}

func readFrame(reader *bufio.Reader) (string, OpCode, error) {
	// | isfinal? | x x x | opcode(4) |
	// | ismask? | length(7) |
	// | mask (32) |
	header := make([]byte, 2)

	_, err := reader.Read(header)

	if err != nil {
		return "", G, err
	}

	var opcode = header[0] & 15
	var length = int(header[1] & 127)

	if opcode == 8 {
		return "", Close, nil
	}

	mask := make([]byte, 4)
	_, _ = reader.Read(mask)

	body := make([]byte, length)

	_, _ = reader.Read(body)

	for i := 0; i < length; i++ {
		body[i] = body[i] ^ mask[i%4]
	}

	s := string(body[:length])
	//fmt.Printf("string : %s \n", s)
	return s, Text, nil

}

func (ws *WebSocket) writeFrame(b []byte) (n int, err error) {

	rw := ws.rw
	length := len(b)
	max16 := 65535

	blen := (length >> 16) & 255
	llen := (length >> 8) & 255
	rlen := length & 255

	header := []byte{Fin | ws.DataType}

	if length > max16 {
		header = append(header, 127, 0, 0, 0, 0, 0, byte(blen))
	} else if length >= 126 {
		header = append(header, 126, byte(llen), byte(rlen))
	} else {
		header = append(header, byte(length))
	}
	rw.Write(header)

	rw.Write(b)
	rw.Flush()

	return length, nil

}

func Upgrade(w http.ResponseWriter, req *http.Request) *WebSocket {

	var guid = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	key := req.Header.Get("Sec-WebSocket-Key")

	hash := sha1.New()
	hash.Write([]byte(key))
	hash.Write(guid)

	shaed := hash.Sum(nil)
	var challengeresponse = base64.StdEncoding.EncodeToString(shaed)

	h, _ := w.(http.Hijacker)
	conn, rw, _ := h.Hijack()

	buf := make([]byte, 0, 4096)

	buf = append(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	buf = append(buf, challengeresponse...)
	buf = append(buf, "\r\n"...)
	buf = append(buf, "\r\n"...)

	rw.Write(buf)
	rw.Flush()

	ws := &WebSocket{
		rw:       rw,
		conn:     conn,
		Closed:   make(chan bool),
		Inbox:    make(chan []byte, 256),
		DataType: Utf8,
	}

	go ws.Worker()

	return ws

}
