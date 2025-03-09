package rsa

import (
	"fmt"
	"os"
	"testing"
)

func TestRsa(t *testing.T) {
	// 生成密钥对
	err := GenerateRsaKey(1024, "./")
	if err!=nil{
		fmt.Println(err)
	}
	// 测试加密
	plainText := []byte("hi, I'm lady_killer9")
	cipherText,err := RsaEncrypt(plainText,"./public.pem")
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("加密后为:%s\n",cipherText)
	// 测试解密
	plainText,err = RsaDecrypt(cipherText,"./private.pem")
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("解密后为:%s\n",plainText)
}

func TestGenerateRsaKey(t *testing.T) {
	// 测试keysize错误
	err := GenerateRsaKey(10, "./")
	if err!=nil{
		fmt.Println(err)
	}
	// 测试目录错误
	err = GenerateRsaKey(1024, ".//sc?")
	if err!=nil{
		fmt.Println(err)
	}
}

func TestRsaEncrypt(t *testing.T) {
	// 测试使用私钥加密
	plainText := []byte("hi, I'm lady_killer9")
	cipherText,err := RsaEncrypt(plainText,"./private.pem")
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("加密后为:%s\n",cipherText)
}

func TestRsaDecrypt(t *testing.T) {
	plainText := []byte("hi, I'm lady_killer9")
	cipherText,err := RsaEncrypt(plainText,"./public.pem")
	if err!=nil{
		fmt.Println(err)
	}
	// 测试使用公钥解密
	plainText,err = RsaDecrypt(cipherText,"./public.pem") // 居然发现空指针异常
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("解密后为:%s\n",plainText)
}

func TestSignVerify(t *testing.T) {
	plainText := []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来")
	signText,err := RsaSign(plainText,"./private.pem")
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("%s\n",signText)
	err = RsaVerify(plainText,"./public.pem",signText)
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("验证成功")
	plainText = []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来！")
	err = RsaVerify(plainText,"./public.pem",signText)
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
}

func TestRsaSign(t *testing.T) {
	// 测试公钥签名
	plainText := []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来")
	signText,err := RsaSign(plainText,"./public.pem")
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("%s\n",signText)
}

func TestRsaVerify(t *testing.T) {
	// 测试私钥验证
	plainText := []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来")
	signText,err := RsaSign(plainText,"./private.pem")
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("%s\n",signText)
	err = RsaVerify(plainText,"./private.pem",signText)
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("验证成功")
	plainText = []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来！")
	err = RsaVerify(plainText,"./public.pem",signText)
	if err != nil{
		fmt.Println(err)
		os.Exit(0)
	}
}