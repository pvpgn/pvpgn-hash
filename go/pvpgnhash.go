package pvpgnhash

import (
	"encoding/binary"
	"encoding/hex"
	"pvpgnhash/memorystream"
	"strings"
)

func GetHash(pass string) string {
	result := calculateHash(pass)
	return asHex(result)
}

func calculateHash(data string) []byte {
	input := []byte(strings.ToLower(data))

	if len(input) > 1024 {
		panic("The input size must be less than 1024 bytes.")
	}

	return safeHash(input)
}

func safeHash(input []byte) []byte {
	var buf [1024]byte

	copy(buf[:], input)
	mem := memorystream.NewBytes(buf[:])

	var expr_ldata_i, expr_ldata_i_2, expr_ldata_i_8, expr_ldata_i_13 uint32
	for i := 0; i < 64; i++ {
		mem.Seek(int64(i*4), memorystream.Start)
		binary.Read(mem, binary.LittleEndian, &expr_ldata_i)
		mem.Seek(int64(1*4), memorystream.Current)
		binary.Read(mem, binary.LittleEndian, &expr_ldata_i_2)
		mem.Seek(int64(5*4), memorystream.Current)
		binary.Read(mem, binary.LittleEndian, &expr_ldata_i_8)
		mem.Seek(int64(4*4), memorystream.Current)
		binary.Read(mem, binary.LittleEndian, &expr_ldata_i_13)
		shiftVal := int((expr_ldata_i ^ expr_ldata_i_8 ^ expr_ldata_i_2 ^
			expr_ldata_i_13) & 0x1f)
		mem.Seek(int64(2*4), memorystream.Current)
		val := uint32(rol(1, shiftVal))
		binary.Write(mem, binary.LittleEndian, val)
	}

	var a, b, c, d, e, g uint32
	a = 0x67452301
	b = 0xefcdab89
	c = 0x98badcfe
	d = 0x10325476
	e = 0xc3d2e1f0
	g = 0

	mem.Seek(0, memorystream.Start)

	var temp uint32
	for i := 0; i < 20; i++ {
		binary.Read(mem, binary.LittleEndian, &temp)
		g = temp + rol(a, 5) + e + ((b & c) | (^b & d)) + 0x5A827999
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = g
	}

	for i := 0; i < 20; i++ {
		binary.Read(mem, binary.LittleEndian, &temp)
		g = (d ^ c ^ b) + e + rol(g, 5) + temp + 0x6ed9eba1
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = g
	}

	for i := 0; i < 20; i++ {
		binary.Read(mem, binary.LittleEndian, &temp)
		g = temp + rol(g, 5) + e + ((c & b) | (d & c) | (d & b)) - 0x70E44324
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = g
	}

	for i := 0; i < 20; i++ {
		binary.Read(mem, binary.LittleEndian, &temp)
		g = (d ^ c ^ b) + e + rol(g, 5) + temp - 0x359d3e2a
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = g
	}

	var result [20]byte
	mem = memorystream.NewBytes(result[:])
	binary.Write(mem, binary.BigEndian, 0x67452301+a)
	binary.Write(mem, binary.BigEndian, 0xefcdab89+b)
	binary.Write(mem, binary.BigEndian, 0x98badcfe+c)
	binary.Write(mem, binary.BigEndian, 0x10325476+d)
	binary.Write(mem, binary.BigEndian, 0xc3d2e1f0+e)

	return mem.Bytes()
}

func rol(val uint32, shift int) uint32 {
	shift &= 0x1f
	val = (val >> (0x20 - shift)) | (val << shift)
	return val
}

func asHex(buf []byte) string {
	return hex.EncodeToString(buf)
}
