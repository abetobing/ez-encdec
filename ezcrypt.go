package ezcrypt

import (
	"io"
	"math/bits"
	"math/rand"
	"os"
	"time"
)

type cryptFunc func([]byte, int) []byte // the signature func to process the bytes

var (
	key uint8 // the cipher key that should be prepended as first byte of the encrypted file/bytes
)

const (
	BufferSize       = 1024      // global buffer sise for reading file
	MinUint8   uint8 = 0         // minimum range of uint8
	MaxUint8         = ^MinUint8 // maximum range of uint8
)

// Encrypt read file, then write encrypted to target
func Encrypt(file, target *os.File) error {
	// 1. generate key
	// 2. write key to the first byte of target file
	// 3. reset the file seeker to 0 index
	// 4. execute readFileThen, apply encryption
	key = generateKey()
	_, err := target.Write([]byte{key})
	if err != nil {
		return err
	}
	file.Seek(0, io.SeekStart)
	return readFileThen(file, target, encryptBytes)
}

// Decrypt read file, then write decrypted to target
func Decrypt(file, target *os.File) error {
	// 1. read the first byte from source file
	// 2. get the key from the first byte
	// 3. reset the seeker to first index
	// 4. execute readFileThen, apply decryption
	buf := make([]byte, BufferSize)
	_, err := file.Read(buf)
	if err != nil {
		return err
	}
	key = readKey(buf)
	file.Seek(1, io.SeekStart)
	target.Seek(0, io.SeekStart)
	return readFileThen(file, target, decryptBytes)
}

// EncryptBytes accept bytes then returns encrypted bytes
func EncryptBytes(src []byte) []byte {
	key = generateKey()
	println("key:", key)
	res := encryptBytes(src, len(src))
	res = append([]byte{key}, res...)
	return res
}

// DecryptBytes accept bytes then returns encrypted bytes
func DecryptBytes(src []byte) []byte {
	key = readKey(src)
	println("key:", key)
	return decryptBytes(src[1:], len(src[1:]))
}

// readFileThen read each bytes on file, then apply fn function on the bytes
// then write the resulting bytes to target file
func readFileThen(file, target *os.File, fn cryptFunc) (err error) {

	defer func(file, target *os.File) {
		// reset the file cursor to start
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			panic(err)
		}
		_, err = target.Seek(0, io.SeekStart)
		if err != nil {
			panic(err)
		}
	}(file, target)

	n := io.SeekStart
	for {
		buf := make([]byte, BufferSize)
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

// encryptButes read each byte then inverse each bits, then add by key
func encryptBytes(b []byte, off int) []byte {
	var result []byte
	for _, b := range b[:off] {
		xb := bits.Reverse8(b)
		xb = xb + key
		result = append(result, xb)
	}
	return result
}

// decryptBytes read each byte then substract by key then inverse the bits
func decryptBytes(b []byte, off int) []byte {
	var result []byte
	for _, b := range b[:off] {
		xb := b - key
		xb = bits.Reverse8(xb)
		result = append(result, xb)
	}
	return result
}

// generateKey will generate random key in range of uint8 (1-255)
// this key should be prepended on the first bytes of the target
func generateKey() byte {
	rand.Seed(time.Now().Unix())
	return uint8(rand.Intn(int(MaxUint8 - MinUint8)))
}

// readKey will return the first byte of the encrypted bytes data
// this key should be removed at the decrypted bytes
func readKey(b []byte) byte {
	if len(b) <= 0 {
		panic("empty bytes")
	}
	return b[0]
}
