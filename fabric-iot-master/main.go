package main

import (
	//"fmt"
    "html/template"
    "net/http"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"	
	"crypto/x509"
	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"	
	"strings"
	"math/big"
	//"gitee.com/frankyu365/gocrypto/util"
	"github.com/ethereum/go-ethereum/crypto/ecies"	
)

type PageData struct {
			PrivateKeyStr string
			PublicKeyStr	string
			Ticket	string
			UserTicket	string
			CipherText	string
		}

var data  PageData

// 生成公私钥
func GenKeyPair() (privateKey string, publicKey string, e error) {
	// GenerateKey生成公私钥对。
	// priKey --- priv.PublicKey.X, priv.PublicKey.Y
	priKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", "", e
	}
	// 将一个EC私钥转换为SEC 1, ASN.1 DER格式。
	ecPrivateKey, e := x509.MarshalECPrivateKey(priKey)
	if e != nil {
		return "", "", e
	}
	// 私钥
	privateKey = base64.StdEncoding.EncodeToString(ecPrivateKey)

	X := priKey.X
	Y := priKey.Y
	xStr, e := X.MarshalText()
	if e != nil {
		return "", "", e
	}
	yStr, e := Y.MarshalText()
	if e != nil {
		return "", "", e
	}
	public := string(xStr) + "+" + string(yStr)
	// 公钥 x+y
	publicKey = base64.StdEncoding.EncodeToString([]byte(public))
	return
}

// 解析私钥
func BuildPrivateKey(privateKeyStr string) (priKey *ecdsa.PrivateKey, e error) {
	bytes, e := base64.StdEncoding.DecodeString(privateKeyStr)
	if e != nil {
		return nil, e
	}
	// ParseECPrivateKey解析SEC 1, ASN.1 DER形式的EC私钥。
	priKey, e = x509.ParseECPrivateKey(bytes)
	if e != nil {
		return nil, e
	}
	return
}

// 解析公钥
func BuildPublicKey(publicKeyStr string) (pubKey *ecdsa.PublicKey, e error) {
	bytes, e := base64.StdEncoding.DecodeString(publicKeyStr)
	if e != nil {
		return nil, e
	}
	split := strings.Split(string(bytes), "+")
	xStr := split[0]
	yStr := split[1]
	x := new(big.Int)
	y := new(big.Int)
	e = x.UnmarshalText([]byte(xStr))
	if e != nil {
		return nil, e
	}
	e = y.UnmarshalText([]byte(yStr))
	if e != nil {
		return nil, e
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pubKey = &pub
	return
}

// 签名
func Sign(content string, privateKeyStr string) (signature string, e error) {
	priKey, e := BuildPrivateKey(privateKeyStr)
	if e != nil {
		return "", e
	}

	// 随机数，用户私钥，hash签署消息
	r, s, e := ecdsa.Sign(rand.Reader, priKey, []byte(hash(content)))
	if e != nil {
		return "", e
	}

	rt, e := r.MarshalText()
	st, e := s.MarshalText()
	// r+s
	signStr := string(rt) + "+" + string(st)
	signature = hex.EncodeToString([]byte(signStr))

	return
}

// Hash算法，这里是sha256，可以根据需要自定义
func hash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func pubEcdsaToEcies(pub *ecdsa.PublicKey) *ecies.PublicKey {
	return &ecies.PublicKey{
		X:      pub.X,
		Y:      pub.Y,
		Curve:  pub.Curve,
		Params: ecies.ParamsFromCurve(pub.Curve),
	}
}

func formHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/index.html"))
	
    if r.Method == http.MethodPost {
        name := r.FormValue("name")
		
		data := struct {
			Message string
		}{

			Message: name,
		}		
		
		tmpl.Execute(w, data)
		return
    }

    
    tmpl.Execute(w, nil)
}

func handlerKey(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/index.html"))
	
	if r.Method == http.MethodPost {
		privateKey, publicKey, err := GenKeyPair()
		if err != nil {
			panic(err)
		}

		data.PrivateKeyStr=privateKey
		data.PublicKeyStr=publicKey	

		tmpl.Execute(w, data)
		return		
		
	}
    
    tmpl.Execute(w, nil)
}

func handlerSign(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/index.html"))
	
	if r.Method == http.MethodPost {			
		prikey_master := r.FormValue("devicePrivateKey")
		deviceid := r.FormValue("slaveDeviceId")
		domainid := r.FormValue("domainId")
	
		//info := string(deviceid) + string(domainid)
		info := deviceid + domainid
		ticket, err := Sign(info, prikey_master)
		if err != nil {
			panic(err)
		}
		
		data.Ticket=ticket
		
		tmpl.Execute(w, data)
		return		
		
	}
    
    tmpl.Execute(w, nil)
}

func handlerUser(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/index.html"))
	
	if r.Method == http.MethodPost {
			
		prikey_master := r.FormValue("devicePrivateKey")
		userid := r.FormValue("userid")
		role := r.FormValue("role")
		group := r.FormValue("group")
	
		//info := string(userid) + string(role) + string(group)
		info := userid + role + group
		ticket, err := Sign(info, prikey_master)
		if err != nil {
			panic(err)
		}
		
		data.UserTicket=ticket

		tmpl.Execute(w, data)
		return		
		
	}
    
    tmpl.Execute(w, nil)
}

func handlerEncrypt(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/index.html"))
	
	if r.Method == http.MethodPost {			
		url := r.FormValue("url")
		pubKey := r.FormValue("pubKey")
	
		publicKey, _ := BuildPublicKey(pubKey)
		cipherText, _ := ecies.Encrypt(rand.Reader, pubEcdsaToEcies(publicKey), []byte(url), nil, nil)
		encodeString := base64.StdEncoding.EncodeToString(cipherText)
		//decodeBytes, _ := base64.StdEncoding.DecodeString(encodeString)	
		
		data.CipherText=encodeString
	
		tmpl.Execute(w, data)
		return		
		
	}
    
    tmpl.Execute(w, nil)
}

func main() {
    http.HandleFunc("/", formHandler)
	http.HandleFunc("/key", handlerKey)
	http.HandleFunc("/sign", handlerSign)
	http.HandleFunc("/user", handlerUser)
	http.HandleFunc("/encrypt", handlerEncrypt)
    http.ListenAndServe(":8080", nil)
}
