# ezcrypt

A very basic file encryption/decryption.

## Example

```go
package main

import (
	"github.com/abetobing/ezcrypt"
	"os"
)

func main() {
	file, err := os.Open("test.txt")
	if err != nil {
		return
	}
	encfile, err := os.Create("encrypt.txt")
	if err != nil {
		return
	}
	decfile, err := os.Create("decrypt.txt")
	if err != nil {
		return
	}
	ezcrypt.Encrypt(file, encfile) // encrypt file
	ezcrypt.Decrypt(encfile, decfile) // decrypt file
}

```