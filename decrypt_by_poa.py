#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# @Author  :    nob1ock
# @Date    :    2024-12-02
# @Description: 通过Padding Oracle Attack解密数据

from Crypto.Cipher import AES
from aes_algorithm import aes_decrypt, aes_encrypt

# 块长
BLOCK_SIZE = AES.block_size


def split_blocks(text, is_plaintext=False) -> list:
    # 按照块长切分明/密文块，每一块为字节数组，一个元素代表一个字节
    if type(text) is str:
        text = text.encode('utf-8')
    block_size = BLOCK_SIZE
    block_num = int(((len(text) + block_size) / block_size))
    blocks = []
    for i in range(block_num):
        start = i * block_size
        end = (i + 1) * block_size
        end = end if end < len(text) else len(text)
        if start == end:
            break
        blocks.append(list(text[start:end]))

    if is_plaintext:
        # 明文块需要填充
        padding_num = block_size - len(blocks[-1])
        if padding_num == 0:
            blocks.append(bytes([block_size] * block_size))
        else:
            blocks[-1] += bytes([padding_num] * padding_num)

    return blocks


def poa_decrypt(cipher_block: list, intermediary_value: list, index=1, decrypt_func=None):
    """
    核心函数，通过变换传入的上一个密文块/初始向量，根据解密系统返回的差异，爆破密文块对应的中间值
    :param cipher_block: 密文块
    :param intermediary_value: 中间值块，用于接收爆破出来的中间值
    :param index: 当前爆破的中间值块下标，倒序
    :param decrypt_func: 解密函数，通过穿入解密回调函数可以自定义解密逻辑
    :return:
    """
    if decrypt_func is None:
        decrypt_func = aes_decrypt
    tmp_last_cipher_block = [0] * BLOCK_SIZE
    if len(intermediary_value) > 0:
        for i in range(-1, -1 - len(intermediary_value), -1):
            tmp_last_cipher_block[i] = intermediary_value[i] ^ index
    # 要爆破的字节位下标
    crack_index = -index
    _bytes_cipher = bytes(cipher_block)
    for i in range(256):
        tmp_last_cipher_block[crack_index] = i
        _bytes_block = bytes(tmp_last_cipher_block)

        try:
            decrypt_func(_bytes_cipher, iv=_bytes_block)
            intermediary_value.insert(0, i ^ index)
            index += 1
            if index > 16:
                break
            poa_decrypt(cipher_block, intermediary_value, index, decrypt_func=decrypt_func)
        except ValueError as e:
            pass


def get_plain_block(cipher_block: list, last_cipher_block: list, is_last_block: bool):
    # 根据中间值获取明文
    intermediary_value = []
    poa_decrypt(cipher_block, intermediary_value)
    plain_block = []
    for i in range(len(last_cipher_block)):
        plain_block.append(intermediary_value[i] ^ last_cipher_block[i])

    if is_last_block:
        end = len(plain_block) - plain_block[-1]
        plain_block = plain_block[0:end]

    return bytes(plain_block)


def crack_plaintext(ciphertext, iv) -> bytes:
    """
    逐字节爆破中间值，再逐块解密数据
    :param ciphertext: 密文
    :param iv: 初始向量
    :return: 明文，字节形式
    """
    blocks = split_blocks(ciphertext)
    blocks.insert(0, list(iv))
    plaintext = b''
    for i in range(len(blocks) - 1):
        if i + 1 == len(blocks) - 1:
            plaintext += get_plain_block(blocks[i + 1], blocks[i], True)
        else:
            plaintext += get_plain_block(blocks[i + 1], blocks[i], False)

    return plaintext


if __name__ == '__main__':
    # 示例
    cipher = b'\xee\xe7\'s\xae7(f\xbc\xfb\xce\x8e@\xa7d\xb3\xe9v\x18|w\xddxQr\xbf"\xf1\xa6p\xa9E\x03\xce\x85\xea\xb2\xee~\xea@7<P\xa7A\tX\xaeO\xc1\x94\xd9r\x9e\xee\xa3\xcd\xef\x98\x14\x1cQC\x13\xcak+\x9c\xba\x07\xc0\xbe\x1d\xda9\xb4Ei\x07\xaa\x04\x95\x8a!@\x88\xe7\xda\x9a.]h\x9fd0S\xdd\x05\xed\x94,\x85\xde7\x82R\xa3,\x0fG\x05\xda\xa2\xe1\x93\t"\x81\xefX\xca\x80\xf9,\x98\xa7\xff\xa7\x0edO\xd5\xbf\xb0t\xaf\xdbm\xf1\xdby,=aWJB\xaec\x0f\xab\x95\xb7G\xb2\xc8{\xf6v\x1c m\xb2\x99\x0e\xf0I\xa5\xeb\xc3\x87\xe1ch\x80"\x1b=ryr\x9cB\x86Q\xb3\x0f\xc9\x93\xa2\xf9A\nJ\xb6"O\x9d\xa9\x7f\xf9\x154\xdet\xae\x9b:\xc3\x9e\xd9\x1a\xa0\xc8\'\xcd\xb6\x15\x87\xb2\xab\xa7\xf8%\x97\xc6\xb2\xc9\x9d\xbd\xcc(\xe7\xf1\xed\x9c\xf3\xe3\x03cj\x80@\xfd\xcb\xff\xb1:\x13g6\x13]\x9f\x12\xbcr\xb4\xf0\x14\xf4\xbd\x89sCO?\x12\xaa\xcf\xf8\xbfEG\xfev\xf8\xa7e\xc7\xdfhd1\xc2\xf7\xfd\xab\xa3\x86d\\\xad\xb1\x9cA\xa5Y\xbf*;\xbcv\xe6\x94>W\x15%^\x97\xf9\xb6P\x89e\xdb\xbb\xc7\x1d\x18\x8e7\x19\xa5\x14\xbf\xdfE\xb6\xe5G\xc0\x8f1\xfd\x0e\xdd\xa1By#\xad\xbbT\x0e\xee\x10\x9d\x02,\xb8\x89\x18\x9a9W\xab\xaf\xdeA\x9d\x9f{\xb4\xcc\x1ej\xcc\xb6\t\x97\x85\x91U9\x03\x9c\x90\xdb\x11C\xa7\x00_|j\xe4\x12j\xf3\xc1\x86\x1c\x9fn5\xf1K\xd4\x8e\xa4\xb2"O\x97Lk\x87\xa39\x95h\xa8\x89\xe6\x1d\xff\xb2,z=_8\x92\xea\xa5\xc7\x8e\x81\xca\x11\xa4dq\xf4\x88\xdc\x9d-}\x8b\xfdA\xcd\xc59[:4V\x14\xceR\xdc\x99^\x1c!g\x9a^\xc1z\xc2rk=\xf6\x8dn\x83HX\xb4s,\xd0\xaf\xe7\x1c\xae\x82\x1bh\xb1\x9a\xc8)s\xad\xe7j\xa4\xae\x93\xe2h!p0C\xaejf7\x1fWG\xe6E'
    iv = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    print('明文: ' + crack_plaintext(cipher, iv).decode('utf-8'))