package hmac

import (
	"fmt"
	"testing"
)

func TestHmac(t *testing.T)  {
	plainText := []byte("消息")
	key := []byte("私钥")
	hashText := GenerateMAC(plainText,key)
	ok := VerifyMAC(plainText,key,hashText)
	if ok{
		fmt.Printf("%s 是原消息\n",plainText)
	}
	fakeText := []byte("假消息")
	ok = VerifyMAC(plainText,key,fakeText)
	if !ok{
		fmt.Printf("%s 是假消息\n",fakeText)
	}
}
