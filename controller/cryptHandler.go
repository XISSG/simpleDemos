package controller

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"data_crypt/model"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// ctype 用来指定是加密还是解密
func AES(rawText string, key []byte, ctype string) (string, error) {
	switch len(key) {
	case 16, 24, 32:
		//生成加密器
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		//选定是加密还是解密
		if ctype == model.ModeEncrypt || ctype == "" {
			//文本处理
			paddedText := PKCS5Padding([]byte(rawText), block.BlockSize()) //文本填充
			ciphertext := make([]byte, len(paddedText))                    //分配密文内存大小
			//进行加密
			mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()]) //选取加密模式
			mode.CryptBlocks(ciphertext, paddedText)                       //进行加密
			result := hex.EncodeToString(ciphertext)                       //对结果进行编码成十六进制
			return result, nil
		} else if ctype == model.ModeDecrypt {
			//处理文本
			ciphertext, _ := hex.DecodeString(rawText)     //从十六进制将文本解码
			tempPlainText := make([]byte, len(ciphertext)) //分配空间
			//解密
			mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()]) //选取解密模式
			mode.CryptBlocks(tempPlainText, ciphertext)                    //解密
			plaintext, err := PKCS5UnPadding(tempPlainText)                //去填充
			if err != nil {
				return "", err
			}
			return string(plaintext), nil
		} else {
			return "", errors.New("Invalid cipher type")
		}

	}
	return "", errors.New("Key length error,require 16 24 32 bytes")
}

func DES(rawText string, key []byte, ctype string) (string, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	iv := make([]byte, des.BlockSize) // DES固定块大小为8字节

	if ctype == model.ModeEncrypt || ctype == "" {
		paddedText := PKCS5Padding([]byte(rawText), des.BlockSize) // 使用PKCS5填充
		ciphertext := make([]byte, len(paddedText))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, paddedText)
		return hex.EncodeToString(ciphertext), nil
	} else if ctype == model.ModeDecrypt {
		ciphertext, _ := hex.DecodeString(rawText)
		if len(ciphertext)%des.BlockSize != 0 {
			return "", errors.New("Ciphertext is not a multiple of the block size")
		}
		plaintext := make([]byte, len(ciphertext))
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, ciphertext)
		plaintext, err := PKCS5UnPadding(plaintext) // 去除填充
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	} else {
		return "", errors.New("Invalid cipher type")
	}
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func PKCS5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, errors.New("Invalid padding")
	}
	return src[:(length - unpadding)], nil
}

func MD5(plainText string) string {
	data := []byte(plainText)
	CipherText := fmt.Sprintf("%x", md5.Sum(data))
	return CipherText
}

func SHA1(plainText string) string {
	data := []byte(plainText)
	CipherText := fmt.Sprintf("%x", sha1.Sum(data))
	return CipherText
}

func Base64(rawText string, ctype string) string {
	var TargetText string
	if ctype == model.ModeEncrypt {
		TargetText = base64.StdEncoding.EncodeToString([]byte(rawText))
	} else if ctype == model.ModeDecrypt {
		data, _ := base64.StdEncoding.DecodeString(rawText)
		TargetText = string(data)
	}
	return TargetText

}
