package main

import (
	"fmt"
	"crypto/rc4"
)

func main() {	
  // insert the shellcode
	shellcode := []byte("")
	key := []byte("\x44\xe6\x89\xe7\xbf\xcd\x3e\xcb\x68\x85\x8e\xbc\xda\x61\xe7\xf7")

	EncryptShellcode(shellcode, key)

}

func EncryptShellcode(shellcode []byte, key []byte) ([]byte, error) {
    encrypted := make([]byte, len(shellcode))
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("error creating RC4 cipher: %v", err)
    }
    cipher.XORKeyStream(encrypted, shellcode)

    output := ""
    for _, b := range encrypted {
        output += fmt.Sprintf("\\x%02x", b)
    }

    fmt.Printf("Encrypted shellcode: %s\n", output)

    return encrypted, nil
}








