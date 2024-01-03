package model

type KeyCrypt struct {
	CryptType string `json:"cryptType"` //指明是何种加密类型 AES, DES, MD5, SHA1, Base64
	RawText   string `json:"rawText"`   //原文
	Ctype     string `json:"ctype"`     //是加密还是解密
	KeyLen    string `json:"keyLen"`    //指定字节大小用于生成aes、des密钥
	Key       string `json:"key"`       //存储需要的加密方式的Key
}
