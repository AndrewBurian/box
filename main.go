package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
)

func main() {

	open := flag.Bool("open", false, "Open a locked box")
	seal := flag.Bool("seal", false, "Create and seal a box")
	file := flag.String("f", "", "File to be sealed/opened")
	inPlace := flag.Bool("i", false, "Write the result to the source file")
	outfile := flag.String("o", "", "File to write output to instead of stdout")
	help := flag.Bool("h", false, "Print usage")
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *open && *seal {
		fmt.Println("Cannot both open and seal a box")
		os.Exit(1)
	}

	if !(*open) && !(*seal) {
		fmt.Println("Must choose an operation")
		os.Exit(1)
	}

	if *inPlace && *outfile != "" {
		fmt.Println("Cannot specify an output file and inplace")
		os.Exit(1)
	}

	if *file == "" {
		fmt.Println("Must specify a file")
		os.Exit(1)
	}

	var err error
	if *open {
		err = OpenBox(*file, *outfile, *inPlace)

	} else if *seal {
		err = SealBox(*file, *outfile, *inPlace)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func getPassword() ([]byte, error) {
	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(0)
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}

	return bytePassword, nil
}

func OpenBox(src, dst string, inPlace bool) error {
	// start with the secret to be decrypted
	file, err := os.OpenFile(src, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	secretData, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	password, err := getPassword()
	if err != nil {
		return err
	}

	salt := secretData[:8]
	secretData = secretData[8:]

	key := pbkdf2.Key(password, salt, 1000000, 32, sha256.New)

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcmBox, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	nonce := secretData[:gcmBox.NonceSize()]
	secretData = secretData[gcmBox.NonceSize():]

	result, err := gcmBox.Open(secretData[:0], nonce, secretData, nil)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(result)

	return Write(file, buf, dst, inPlace)
}

func SealBox(src, dst string, inPlace bool) error {

	// start with the secret to be encrypted
	file, err := os.OpenFile(src, os.O_RDWR, 660)
	if err != nil {
		return err
	}
	defer file.Close()

	secretData, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	password, err := getPassword()
	if err != nil {
		return err
	}

	// Salt for PBKD2 to stop rainbow table attacks against the password
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// key based on lots of SHA256 operations
	key := pbkdf2.Key(password, salt, 1000000, 32, sha256.New)

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Gaussian Counter Mode for Authenticated Encryption
	gcmBox, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	// Random nonce to ensure multiple uses of the key aren't compromised
	nonce := make([]byte, gcmBox.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	result := gcmBox.Seal(secretData[:0], nonce, secretData, nil)

	// salt and nonce aren't secrets
	buf := bytes.NewBuffer(salt)
	buf.Write(nonce)
	buf.Write(result)

	return Write(file, buf, dst, inPlace)

}

func Write(file *os.File, buf io.Reader, dst string, inPlace bool) error {
	if inPlace {
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := io.Copy(file, buf); err != nil {
			return err
		}
		return nil
	}

	if dst == "" {
		io.Copy(os.Stdout, buf)
		return nil
	}

	outFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, buf)
	return err
}
