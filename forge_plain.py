#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# @Author  :    nob1ock
# @Date    :    2024-12-02
# @Description: 通过Padding Oracle Attack加密任意数据

from aes_algorithm import aes_decrypt, aes_encrypt
from decrypt_by_poa import poa_decrypt, split_blocks

def xor_list(*args):
    # 对列表元素进行异或计算
    result = []
    for i in range(len(args[0])):
        xor_result = args[0][i]
        for lst in args[1:]:
            xor_result ^= lst[i]
        result.append(xor_result)

    return result


def calc_penultimate_cipher_block(forge_plain_block, last_intermediary_value):
    # 计算倒数第二块密文
    # C'[n-1]=P'[n]^P[n]^C[n-1]=P'[n]^D(C[n]) n为明文块的块数
    return xor_list(forge_plain_block, last_intermediary_value)


def recalc_cipher_block(cipher_block, plain_block, decrypt_func=None):
    # 根据当前密文块以及明文块，重新计算上一块密文块
    # 爆破当前密文块的解密后的中间值
    intermediary_value = []
    poa_decrypt(cipher_block, intermediary_value=intermediary_value, decrypt_func=decrypt_func)
    # C'[n-1]=P'[n]^MV[n]
    last_cipher_block = xor_list(intermediary_value, plain_block)
    return last_cipher_block


def crack_end_ciphertext(ciphertext, iv, decrypt_func=None):
    # 获取最后两块密文，以及最后一块密文对应的中间值
    cipher_blocks = split_blocks(iv + ciphertext)[-2:]
    intermediary_value = []
    poa_decrypt(cipher_blocks[1], intermediary_value=intermediary_value, decrypt_func=decrypt_func)
    return intermediary_value, cipher_blocks


def encrypt_ciphertext(ori_ciphertext, forge_plaintext, ori_iv, decrypt_func=None):
    """
    根据最后两块密文，和最后一块密文对应的明文，在没有密钥的情况下，加密任意数据。
    密文块、明文块、中间值，均转为整型列表，一个字节为一个元素，如：[16, 146, 28, 101, 34, 172, 35, 234, 229, 222, 121, 54, 221, 249, 57, 63]
    :param ori_ciphertext: 原始密文
    :param forge_plaintext: 要加密的明文
    :param ori_iv: 初始向量（实际上当密文块数大于等于2时，无需初始向量）
    :param decrypt_func: 原始
    :return: 新的初始向量与新密文
    """
    # 爆破解密最后一块密文对应的中间值，以及获取最后两块密文
    last_intermediary_value, end_cipher_blocks = crack_end_ciphertext(ori_ciphertext, ori_iv, decrypt_func=decrypt_func)
    plain_blocks = split_blocks(forge_plaintext, True)
    new_cipher_blocks = [
        calc_penultimate_cipher_block(plain_blocks[-1], last_intermediary_value),
        end_cipher_blocks[1]]
    # 从倒数第二个明文块开始，获取其对应的上一个密文块
    for i in range(-2, -1 - len(plain_blocks), -1):
        # C'[n-1] = P'[n]⊕D(C'[n]) = P'[n]⊕MV[n]
        new_cipher_blocks.insert(0, recalc_cipher_block(new_cipher_blocks[i], plain_blocks[i], decrypt_func=decrypt_func))
        print(f'block_{len(plain_blocks)+i}:\t {bytes(new_cipher_blocks[0])}')
    new_iv = bytes(new_cipher_blocks[0])

    ciphertext = b''
    for i in range(1, len(new_cipher_blocks)):
        ciphertext += bytes(new_cipher_blocks[i])

    print(b'new ciphertext: ' + ciphertext)
    print(b'new iv: ' + new_iv)
    return new_iv, ciphertext


if __name__ == '__main__':
    # 示例
    iv = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    plaintext = '0123456789abcde'
    # 密文
    cipher_text = aes_encrypt(plaintext, iv=iv)
    # 需要加密的明文
    new_plaintext = '''In cryptography, a padding oracle attack is an attack which uses the padding validation of a 
cryptographic message to decrypt the ciphertext. In cryptography, variable-length plaintext 
messages often have to be padded (expanded) to be compatible with the underlying cryptographic 
primitive. The attack relies on having a "padding oracle" who freely responds to queries about 
whether a message is correctly padded or not. The information could be directly given, or 
leaked through a side-channel.'''
    # 获取新的初始向量以及密文
    new_iv, ciphertext = encrypt_ciphertext(cipher_text, new_plaintext, iv)
    # 解密验证
    print('decrypt data: ' + aes_decrypt(ciphertext, iv=new_iv).decode('utf-8'))
