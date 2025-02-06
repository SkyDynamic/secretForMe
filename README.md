# 20250204解法
## 提示解释
- GIF, 串表压缩算法: LZW算法
- 古密码学: 凯撒加密
- 生日：324
## 加密过程
1、将字符串转为Unicode
```python
def string_to_unicode(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)

def unicode_to_string(s):
    import re
    
    def replace_unicode(match):
        return chr(int(match.group(1), 16))
    
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, s)
```
2、将转换后的Unicode字符串进行Lzw压缩
```python
def lzw_compress(uncompressed, max_dict_size=4096):
    dict_size = 256
    dictionary = {chr(i): i for i in range(dict_size)}
    w = ""
    result = []
    for c in uncompressed:
        wc = w + c
        if wc in dictionary:
            w = wc
        else:
            result.append(dictionary[w])
            if dict_size < max_dict_size:
                dictionary[wc] = dict_size
                dict_size += 1
            else:
                dictionary = {chr(i): i for i in range(256)}
                dict_size = 256
                dictionary[wc] = dict_size
                dict_size += 1
            w = c
    if w:
        result.append(dictionary[w])
    return result


def lzw_decompress(compressed, max_dict_size=4096):
    dict_size = 256
    dictionary = {i: chr(i) for i in range(dict_size)}
    w = result = chr(compressed.pop(0))
    for k in compressed:
        if k in dictionary:
            entry = dictionary[k]
        elif k == dict_size:
            entry = w + w[0]
        else:
            raise ValueError('Bad compressed k: %s' % k)
        result += entry
        
        if dict_size < max_dict_size:
            dictionary[dict_size] = w + entry[0]
            dict_size += 1
        else:
            dictionary = {i: chr(i) for i in range(256)}
            dict_size = 256
            dictionary[dict_size] = w + entry[0]
            dict_size += 1
        
        w = entry
    return result
```
3、将压缩后获得的整数列表改为bytes形式进行存储并使用凯撒加密法进行偏移
```python
def list2bytes(l):
    return b''.join(int.to_bytes(num, 2) for num in l)

def bytes2list(b):
    return [int.from_bytes(b[i:i + 2]) for i in range(0, len(b), 2)]

def caesar_encrypt_bytes(data, shift):
    encrypted_data = bytearray()
    for byte in data:
        new_byte = (byte + shift) % 256
        encrypted_data.append(new_byte)
    return bytes(encrypted_data)


def caesar_decrypt_bytes(data, shift):
    decrypted_data = bytearray()
    for byte in data:
        new_byte = (byte - shift) % 256
        decrypted_data.append(new_byte)
    return bytes(decrypted_data)
```
4、最后将偏移后的结果进行base64就获得了加密后的密文了
```python
base64.b64encode(decrypt_result).decode()
```

### 编码过程
```python
def encode(s, shift):
    compress_list = lzw_compress(string_to_unicode(s))
    byte_data = list2bytes(compress_list)
    encrypted_data = caesar_encrypt_bytes(byte_data, shift)
    return base64.b64encode(encrypted_data).decode()
```

### 解码过程
```python
def decode(s, shift):
    decoded_data = base64.b64decode(s)
    decrypted_data = caesar_decrypt_bytes(decoded_data, shift)
    decompressed_list = bytes2list(decrypted_data)
    decompressed_data = lzw_decompress(decompressed_list)
    return unicode_to_string(decompressed_data)
```
