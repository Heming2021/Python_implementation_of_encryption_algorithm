from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
import base64

def read_private_key(file_path="private.pem") -> bytes:
    with open(file_path, "rb") as x:
        b = x.read()
        return b

def crypto(msg):
    message = msg
    rsakey = RSA.importKey(open("public.pem").read())
    cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 创建用于执行pkcs1_v1_5加密或解密的密码
    cipher_text = base64.b64encode(cipher.encrypt(message.encode('utf-8')))
    print(cipher_text.decode('utf-8'))

def decryption(text_encrypted_base64: str, private_key: bytes):
    # 字符串指定编码（转为bytes）
    text_encrypted_base64 = text_encrypted_base64.encode('utf-8')
    # base64解码
    text_encrypted = base64.b64decode(text_encrypted_base64 )
    # 构建私钥对象
    cipher_private = PKCS1_v1_5.new(RSA.importKey(private_key))
    # 解密（bytes）
    text_decrypted = cipher_private.decrypt(text_encrypted , Random.new().read)
    # 解码为字符串
    text_decrypted = text_decrypted.decode()
    return text_decrypted

def signature(msg):
    message = msg
    rsakey = RSA.importKey(open("private.pem").read())
    signer = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(message.encode("utf-8"))
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    print(signature.decode('utf-8'))

def vrfy(msg):
    message_verify = msg
    signature = "fd99fQpbH48VT9YQKepyHSip9pwrJkm1PN3ZykHNrfTVk555fv392E7MtbIfcligOCWUx8nd3g+7J0Fo3x+9G1Y6MJs0CuMCbA4qulUMNGjzUpsN1URorMZfPKjPvhf22ARH9qZEnebQ7UUGO3ioy4nylZONb3Ldhga+PKyxYTM="
    rsakey = RSA.importKey(open("public.pem").read())
    verifier = Signature_pkcs1_v1_5.new(rsakey)
    hsmsg = SHA.new()
    hsmsg.update(message_verify.encode("utf-8"))
    is_verify = verifier.verify(hsmsg, base64.b64decode(signature))
    print(is_verify)

crypto("Hello")
# 解密
text_decrypted = decryption('B0oL7O68Gb9Gwx4EZN79D03099LVKYPMznPKc4/qd+6Y+vvr1yS9xcO040gwD5MCUgvg7mCbxCxLFyGGDVYSEx+YRhZAxfXroeAq4QHKaLvC6q3/8EmTFVp06epj1sIMrEqdVv9uj1/psXdL2LCBzYZXuuiLIMKW/h/G39kht4s=',read_private_key())
print('明文：' + text_decrypted)