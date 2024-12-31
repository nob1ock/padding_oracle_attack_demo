# padding_oracle_attack_demo

Padding Oracle Attack and Shiro 721 Exp Demo

用于Padding Oracle Attack演示，以及在Shiro 721中的利用

关于漏洞原理和代码说明可见：[Padding-Oracle-Attack](https://nob1ock.github.io/posts/Padding-Oracle-Attack/)

使用的加解密库为 pycryptodome



文件结构：

```txt
padding_oracle_attack_demo/
├── README.md
├── aes_algorithm.py	# AES加解密
├── decrypt_by_poa.py	# 通过Paddding Oracle Attack解密密文
├── forge_plain.py		# 通过Paddding Oracle Attack加密密文
└── shiro_721_exp.py	# 利用Paddding Oracle Attack攻击Shiro 721漏洞
```



搭建Shiro 721环境

```shell
git clone https://github.com/apache/shiro.git
// 切换至1.4.1版本
git checkout tags/shiro-root-1.4.1
```

该版本的Shiro演示环境就有Spring Boot，开箱即用。加载一下shiro-1.4.1\samples\spring-boot-web\pom.xml，然后启动项在`src/master/java/org/apache/shiro/samples/WebApp.java`，直接启动即可

![Pasted image 20241126114056.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241126114056.png)

