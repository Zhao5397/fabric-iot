# gocrypto

#### 介绍

对标准库crypto相关包进行简单的包装，使加解密更简单。

#### 更新

v1.0.7-alpha 添加ecc加解密与签名

v1.0.6-stable 添加hmac进行消息认证

v1.0.6-alpha 添加hmac进行消息认证

v1.0.5-stable 添加rsa签名（去除了recover，应在您调用时recover）

v1.0.5-beta 添加rsa 签名

v1.0.5-alpha 添加rsa加解密（测试使用公钥进行解密时发现空指针错误，目前是recover了）

v1.0.4 添加aes，将des和aes的iv拿出函数作为参数

v1.0.3 添加des

#### 软件架构
软件架构说明


#### 安装教程

1.  go get "gitee.com/frankyu365/gocrypto"

#### 使用说明

1.  `import "gitee.com/frankyu365/gocrypto/package"`
![输入图片说明](https://img-blog.csdnimg.cn/20210608212718423.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2xhZHlfa2lsbGVyOQ==,size_16,color_FFFFFF,t_70 "在这里输入图片标题")

其他的函数使用请查看注释和的对应包下的xxx_test.go文件

#### 个人博客

https://blog.csdn.net/lady_killer9/category_11124949.html