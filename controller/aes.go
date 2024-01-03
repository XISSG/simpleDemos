package controller

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

type AesAlgorithm struct {
	AppAlg     *AlgrithomManager
	EncryptKey string
	PlainText  string
	CipherText string
}

type AesAlgorithmOption func(ase *AesAlgorithm)

func NewAesAlgorithm(options ...AesAlgorithmOption) *AesAlgorithm {
	aseAlg := &AesAlgorithm{
		AppAlg:     new(AlgrithomManager),
		EncryptKey: "",
		PlainText:  "",
		CipherText: "",
	}
	for _, option := range options {
		option(aseAlg)
	}
	return aseAlg
}

func WithEncryptKey(key string) AesAlgorithmOption {
	return func(aes *AesAlgorithm) {
		aes.EncryptKey = key
	}
}

func WithPlaintextContent(plainContent string) AesAlgorithmOption {
	return func(aes *AesAlgorithm) {
		aes.PlainText = plainContent
	}
}

func WithCiphertextContent(cipherContent string) AesAlgorithmOption {
	return func(aes *AesAlgorithm) {
		aes.CipherText = cipherContent
	}
}

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padtext...)
}

func (aalg *AesAlgorithm) Encrypt() {
	tmpKeys := []byte(aalg.EncryptKey)
	tmpPlaintext := aalg.PlainText
	block, err := aes.NewCipher(tmpKeys)
	if err != nil {
		fmt.Println("aes加密失败,原因:" + err.Error())
		return
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding([]byte(tmpPlaintext), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, tmpKeys[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	aalg.CipherText = hex.EncodeToString(crypted)
}
func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (aalg *AesAlgorithm) Decrypt() {
	tmpKeys := []byte(aalg.EncryptKey)
	cryptedByte, _ := hex.DecodeString(aalg.CipherText)
	block, err := aes.NewCipher(tmpKeys)
	if err != nil {
		fmt.Println("aes解密失败,原因:" + err.Error())
		return
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, tmpKeys[:blockSize])
	origin := make([]byte, len(cryptedByte))
	blockMode.CryptBlocks(origin, cryptedByte)
	decryptStrings := pkcs5UnPadding(origin)
	aalg.PlainText = string(decryptStrings)
}
