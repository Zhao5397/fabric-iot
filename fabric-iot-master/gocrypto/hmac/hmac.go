package hmac
import (
	"crypto/hmac"
	"crypto/sha1"
)

// 生成消息认证码
// plainText 明文
// key 密钥
// 返回 消息认证码
func GenerateMAC(plainText,key []byte) []byte {
	hash := hmac.New(sha1.New,key)
	hash.Write(plainText)
	hashText := hash.Sum(nil)
	return hashText
}

// 消息认证
// plainText 明文
// key 密钥
// hashText 消息认证码
// 返回 是否是原消息
func VerifyMAC(plainText,key,hashText []byte) bool {
	hash := hmac.New(sha1.New,key)
	hash.Write(plainText)
	return hmac.Equal(hashText,hash.Sum(nil))
}
