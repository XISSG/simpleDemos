# Data Encrypt/Decrypt
This project is a simple data encrytion and decrytion demo, which include DES, AES encryption/decrption, MD5, SHA1 Hash, Base64 and URL encoding/decoding .
## Useage
### request method 
``POST``
### request Content-Type
Content-Type:application/json
### Request Parameters
``cryptType``to indicate the encryption type AES|DES|MD5|SHA1|Base64 encoding/decoding|URL encoding/decoding
``rawText``plain text or cipher text you give 
``ctype``to indicate encrypt or decrypt
``key`` if it is decrypt mode you need to offer a Key to decrypt
### Response Parameters
``cryptType`` this is the encryption type you request
``targetText`` this is your result
``key`` AES|DES encrypt mode return a generated key by giving KeyLen
### Response Contnent-Type
application/json
Response Data Format is Json:
 {
"cryptType": "AES",
"targetText": "crypted text ...",
"key":"Key generatoed"
}
type Json1 struct {
json:"cryptType": "AES",
json:"targetText":"cipher text"
}

### AES/DES
cryptType
rawText
keyLen (AES 16 24 32 bytes |DES 8 bytes) encrypt mode
key     decrypt mode
ctype
### Base64/URL
cryptType
rawText
ctype
### MD5/SHA1
cryptType
rawText
