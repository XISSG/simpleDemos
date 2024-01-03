package main

import (
	"data_crypt/controller"
	"data_crypt/middleware"
	"data_crypt/model"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	CryptTypeAES    = "AES"
	CryptTypeDES    = "DES"
	CryptTypeMD5    = "MD5"
	CryptTypeSHA1   = "SHA1"
	CryptTypeBase64 = "Base64"
	CryptTypeURL    = "URL"
)

func main() {
	r := mux.NewRouter()
	r.Use(middleware.CorsMiddleware)
	r.HandleFunc("/api", GetData)
	http.ListenAndServe(":8081", r)
}

func GetData(w http.ResponseWriter, r *http.Request) {
	////解析表单
	//err := r.ParseForm()
	//if err != nil {
	//	fmt.Println(err)
	//}
	//KeyLen, _ := strconv.ParseInt(r.Form.Get("KeyLen"), 10, 32)

	//KeyCrypt := &model.KeyCrypt{
	//	RawText:   r.Form.Get("RawText"),
	//	CryptType: r.Form.Get("CryptType"),
	//	KeyLen:    KeyLen,
	//	Key:       []byte(r.Form.Get("Key")),
	//	Ctype:     r.Form.Get("Ctype"),
	//}

	//json反序列化
	var KeyCrypt model.KeyCrypt
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &KeyCrypt)
	var err error

	var TargetText string //接收加密结果
	//根据CryptType来选择加解密方式
	switch KeyCrypt.CryptType {
	//分组加密
	case CryptTypeAES:
		if KeyCrypt.Ctype == model.ModeEncrypt {
			data, _ := strconv.Atoi(strings.TrimSpace(KeyCrypt.KeyLen))
			KeyCrypt.Key = string(KeyGenerator(data))
		}
		TargetText, err = controller.AES(KeyCrypt.RawText, []byte(strings.TrimSpace(KeyCrypt.Key)), KeyCrypt.Ctype)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error in AES %v", err), http.StatusInternalServerError)
		}
	case CryptTypeDES:
		if KeyCrypt.Ctype == model.ModeEncrypt {
			data, _ := strconv.Atoi(strings.TrimSpace(KeyCrypt.KeyLen))
			KeyCrypt.Key = string(KeyGenerator(data))
		}
		TargetText, err = controller.DES(KeyCrypt.RawText, []byte(strings.TrimSpace(KeyCrypt.Key)), KeyCrypt.Ctype)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error in DES %v", err), http.StatusInternalServerError)
		}
		//hash
	case CryptTypeMD5:
		TargetText = controller.MD5(KeyCrypt.RawText)
	case CryptTypeSHA1:
		TargetText = controller.SHA1(KeyCrypt.RawText)

		//编码
	case CryptTypeBase64:
		TargetText = controller.Base64(KeyCrypt.RawText, KeyCrypt.Ctype)
		fmt.Println(TargetText)
	case CryptTypeURL:
		if KeyCrypt.Ctype == model.ModeEncrypt {
			TargetText = url.QueryEscape(KeyCrypt.RawText)
		} else if KeyCrypt.Ctype == model.ModeDecrypt {
			TargetText, _ = url.QueryUnescape(KeyCrypt.RawText)
		}
	default:
		http.Error(w, "not found this crypt selection", http.StatusBadRequest)
	}
	//将结果写回响应中
	w.Header().Set("Content-Type", "application/json")
	if KeyCrypt.CryptType == CryptTypeAES || KeyCrypt.CryptType == CryptTypeDES {
		data, _ := json.MarshalIndent(&model.Json{CryptType: KeyCrypt.CryptType, TargetText: TargetText, Key: KeyCrypt.Key}, "", "    ")
		w.Write(data)
	} else {
		data, _ := json.MarshalIndent(&model.Json1{CryptType: KeyCrypt.CryptType, TargetText: TargetText}, "", "    ")
		w.Write(data)
	}
}

// Key生成器
func KeyGenerator(KeyLen int) []byte {
	if KeyLen == 0 { //默认生成密钥长度为8字节
		KeyLen = 8
	}
	key := make([]byte, KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("Key Generate error")
		return nil
	}
	key = []byte(hex.EncodeToString(key))
	return key[:KeyLen]
}
