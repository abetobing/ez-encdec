package ezcrypt

import (
	"io"
	"math/bits"
	"os"
)

const BUFFERSIZE = 1024

type cryptFunc func([]byte, int) []byte

// Encrypt read file, then write encrypted to target
func Encrypt(file, target *os.File) error {
	return readBytesThen(file, target, encryptBytes)
}

// Decrypt read file, then write decrypted to target
func Decrypt(file, target *os.File) error {
	return readBytesThen(file, target, decryptBytes)
}

// readBytesThen read each bytes on file, then apply fn function on the bytes
// then write the resulting bytes to target file
func readBytesThen(file, target *os.File, fn cryptFunc) (err error) {
	file.Seek(0, io.SeekStart)
	n := io.SeekStart
	for {
		buf := make([]byte, BUFFERSIZE)
		n, err = file.Read(buf)
		if err != nil && err != io.EOF {
			// end of file
			return
		}
		if n == 0 {
			// no bytes left to read
			break
		}
		newbuf := fn(buf, n)
		_, err = target.Write(newbuf[:n])
		if err != nil {
			return
		}
	}
	return
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
