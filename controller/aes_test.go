package controller

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

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
