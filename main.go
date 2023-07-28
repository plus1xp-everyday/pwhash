package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const KeyPhrase string = "User generated password"

func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decode(s string) ([]byte, error) {
	cipheredText, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return cipheredText, nil
}

func mdHashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:])
}

func generateAESBlock(keyPhrase string) (cipher.Block, error) {
	aesBlock, err := aes.NewCipher([]byte(mdHashing(keyPhrase)))
	if err != nil {
		return nil, err
	}
	return aesBlock, nil
}

func generateGCMInstance(keyPhrase string) (cipher.AEAD, error) {
	aesBlock, err := generateAESBlock(keyPhrase)
	if err != nil {
		return nil, err
	}
	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	return gcmInstance, nil
}

func Encrypt(textToEncrypt, keyPhrase string) (string, error) {
	gcmInstance, err := generateGCMInstance(keyPhrase)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcmInstance.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	cipheredText := gcmInstance.Seal(nonce, nonce, []byte(textToEncrypt), nil)
	return encode(cipheredText), nil
}

func Decrypt(encryptedText, keyPhrase string) (string, error) {
	gcmInstance, err := generateGCMInstance(keyPhrase)
	if err != nil {
		return "", err
	}
	nonceSize := gcmInstance.NonceSize()
	cipheredText, err := decode(encryptedText)
	if err != nil {
		return "", err
	}
	nonce, cipheredText := cipheredText[:nonceSize], cipheredText[nonceSize:]
	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		return "", err
	}
	return string(originalText), nil
}

func main() {
	textToEncrypt := "Encrypting this string"

	encryptedText, err := Encrypt(textToEncrypt, KeyPhrase)
	if err != nil {
		fmt.Println("error encrypting your classified text: ", err)
	}
	fmt.Println(encryptedText)

	decryptedText, err := Decrypt(encryptedText, KeyPhrase)
	if err != nil {
		fmt.Println("error decrypting your encrypted text: ", err)
	}
	fmt.Println(decryptedText)
}
