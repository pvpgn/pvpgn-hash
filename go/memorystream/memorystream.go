package memorystream

import (
	"errors"
	"io"
)

type MemoryStream struct {
	buf    []byte
	offset int
}

const (
	Start = iota
	Current
	End
)

func NewCapacity(cap int) *MemoryStream {
	return &MemoryStream{buf: make([]byte, 0, cap), offset: 0}
}

func NewBytes(data []byte) *MemoryStream {
	return &MemoryStream{buf: data, offset: 0}
}

func (m *MemoryStream) Read(p []byte) (n int, err error) {
	n = copy(p, m.buf[m.offset:len(m.buf)])
	m.offset += n

	if m.offset == len(m.buf) {
		return n, io.EOF
	}

	return n, nil
}

func (m *MemoryStream) Write(p []byte) (n int, err error) {
	if available := cap(m.buf) - m.offset; available < len(p) {
		return n, errors.New("Write data length over than array size.")
	}

	n = copy(m.buf[m.offset:cap(m.buf)], p)
	m.offset += n
	if len(m.buf) < m.offset {
		m.buf = m.buf[:m.offset]
	}

	return n, nil
}

func (m *MemoryStream) Seek(offset int64, whence int) (int64, error) {
	newOffset := m.offset
	switch whence {
	case Start:
		newOffset = int(offset)
	case Current:
		newOffset += int(offset)
	case End:
		newOffset = len(m.buf) - int(offset)
	}

	if newOffset < 0 {
		return int64(m.offset), errors.New("Unable to seek to a location <0")
	}

	if newOffset > len(m.buf) {
		newOffset = len(m.buf)
	}

	m.offset = newOffset

	return int64(m.offset), nil
}

func (m *MemoryStream) Bytes() []byte {
	b := make([]byte, len(m.buf))
	copy(b, m.buf)
	return b
}
