#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# @Author  :    nob1ock
# @Date    :    2024-11-26
# @Description: AES加解密算法

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'0123456789abcdef'
iv = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])


# 加密函数
def aes_encrypt(plaintext: str, key=key, iv=iv) -> bytes:
    # 将明文数据转换为字节
    plaintext_bytes = plaintext.encode('utf-8')
    # 使用CBC模式
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))

    return ciphertext


# 解密函数
def aes_decrypt(ciphertext: bytes, key=key, iv=iv) -> bytes:
    # 使用CBC模式进行解密并去除填充
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return decrypted

