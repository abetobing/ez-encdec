package ezcrypt

import (
	"fmt"
	"io"
	"math/bits"
	"os"
)

const BUFFERSIZE = 1024

type cryptFunc func([]byte, int) []byte

func readBytesThen(file, target *os.File, fn cryptFunc) (err error) {
	file.Seek(0, io.SeekStart)
	n := io.SeekStart
	for {
		buf := make([]byte, BUFFERSIZE)
		n, err = file.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Printf("end of file. %v\n", err)
			return
		}
		if n == 0 {
			break
		}
		newbuf := fn(buf, n)
		target.Write(newbuf[:n])
	}
	return
}

func Decrypt(file, target *os.File) {
	readBytesThen(file, target, decryptBytes)
}
func Encrypt(file, target *os.File) {
	readBytesThen(file, target, encryptBytes)
}

// encryptButes read each byte then inverse each bits, then add two
func encryptBytes(b []byte, off int) []byte {
	var result []byte
	for _, b := range b[:off] {
		xb := bits.Reverse8(b)
		xb = xb + 2
		result = append(result, xb)
	}
	return result
}

// decryptBytes read each byte then substract by two then inverse the bits
func decryptBytes(b []byte, off int) []byte {
	var result []byte
	for _, b := range b[:off] {
		xb := b - 2
		xb = bits.Reverse8(xb)
		result = append(result, xb)
	}
	return result
}
