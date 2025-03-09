package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"gitee.com/frankyu365/gocrypto/errors"
	"gitee.com/frankyu365/gocrypto/util"
	"runtime"
)

// AES 加解密
// plainText：明文
// iv： 初始化向量
// key：密钥
// 返回密文/明文，以及错误
func AesEncrypt(plainText, iv,key []byte) ([]byte,error) {
	block, err :=aes.NewCipher(key)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,errors.AesKeyError)
	}
	if len(iv) != block.BlockSize(){
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,errors.AesIvError)
	}
	// create a CTR interface
	stream := cipher.NewCTR(block,iv)
	cipherText := make([]byte,len(plainText))
	// encrypt or decrypt
	stream.XORKeyStream(cipherText,plainText)
	return cipherText,nil
}
var AesDecrypt func(cipherText,iv, key []byte) ([]byte,error) = AesEncrypt
