package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"gitee.com/frankyu365/gocrypto/errors"
	"gitee.com/frankyu365/gocrypto/util"
	"os"
	"runtime"
)
// 生成RSA密钥对
// keySize 密钥大小
// dirPath 密钥对文件路径
// 返回错误
func GenerateRsaKey(keySize int, dirPath string) error {
	privateKey,err := rsa.GenerateKey(rand.Reader,keySize)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	// x509
	derText :=x509.MarshalPKCS1PrivateKey(privateKey)
	// pem Block
	block := &pem.Block{
		Type:"rsa private key",
		Bytes:derText,
	}
	// just joint, caller must let dirPath right
	file,err := os.Create(dirPath+"private.pem")
	defer file.Close()
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	err = pem.Encode(file,block)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	// get PublicKey from privateKey
	publicKey := privateKey.PublicKey
	derStream,err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	block = &pem.Block{
		Type:"rsa public key",
		Bytes:derStream,
	}
	file,err = os.Create(dirPath+"public.pem")
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	err = pem.Encode(file, block)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	return nil
}
// Rsa加密
// plainText 明文
// filePath 公钥文件路径
// 返回加密后的结果 错误
func RsaEncrypt(plainText []byte,filePath string) ([]byte, error) {
	// get pem.Block
	block,err := util.GetKey(filePath)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	// X509
	publicInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	publicKey,flag := publicInterface.(*rsa.PublicKey)
	if flag == false{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,errors.RsatransError)
	}
	// encrypt
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	return cipherText,nil
}
// Rsa解密
// cipherText 密文
// filePath 私钥文件路径
// 返回解密后的结果 错误
func RsaDecrypt(cipherText []byte,filePath string) (plainText []byte,err error) {
	// get pem.Block
	block,err := util.GetKey(filePath)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	// get privateKey
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	// no need recover, you can add it when you call these function
	//defer func() {
	//	if err2 := recover();err2 != nil{
	//		_, file, line, _ := runtime.Caller(0)
	//		err = util.Error(file,line,errors.RsaNilError)
	//	}
	//}()
	// get plainText use privateKey
	plainText, err3 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err3 != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err3.Error())
	}
	return plainText,err
}
// Rsa签名
// plainText 明文
// filePath 私钥文件路径
// 返回签名后的数据 错误
func RsaSign(plainText []byte, priFilePath string) ([]byte,error) {
	// get pem.Block
	block,err := util.GetKey(priFilePath)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	priKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	// calculate hash value
	hashText := sha512.Sum512(plainText)
	// Sign with hashText
	signText, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA512, hashText[:])
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return nil,util.Error(file,line+1,err.Error())
	}
	return signText,nil
}
// Rsa签名验证
// plainText 明文
// filePath 公钥文件路径
// 返回签名后的数据 错误
func RsaVerify(plainText []byte, pubFilePath string,signText []byte) error {
	// get pem.Block
	block,err := util.GetKey(pubFilePath)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	// x509
	pubInter,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	pubKey := pubInter.(*rsa.PublicKey)
	// hashText to verify
	hashText := sha512.Sum512(plainText)
	err = rsa.VerifyPKCS1v15(pubKey,crypto.SHA512,hashText[:],signText)
	if err != nil{
		_, file, line, _ := runtime.Caller(0)
		return util.Error(file,line+1,err.Error())
	}
	return nil
}