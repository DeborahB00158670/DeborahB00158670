#GENERAL
#ENCODING
#Encoding Challenge 
from pwn import remote
from json import loads, dumps
from base64 import b64decode
from codecs import encode
from Crypto.Util.number import long_to_bytes

#Connection to socket.cryptohack.org 13377
r = remote('socket.cryptohack.org', 13377)

while 'flag' not in (encoded := loads(r.recvline().decode())):
    print(encoded)
    r.sendline(dumps({"decoded": {
        'base64': lambda e: b64decode(e).decode(),
        'hex': lambda e: bytes.fromhex(e).decode(),
        'rot13': lambda e: encode(e, 'rot_13'),
        'bigint': lambda e: long_to_bytes(int(e, 16)).decode(),
        'utf-8': lambda e: ''.join([chr(c) for c in e])
    }[encoded['type']](encoded['encoded'])}))

print(encoded['flag'])

#XOR
#XOR Properties 
from pwn import xor

key1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
key1_key2 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
key2_key3 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
flag_key1_key2_key3 = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

# From the self inverse property of xor, we know that a xor a = 0. So, we can find unknown keys by xoring the already known key.
# key2 = key1_xor_key2 ^ key1
# key3 = key2_xor_key3 ^ key2
# flag = flag_key1_key2_key3 ^ key1 ^ key2 ^ key3

key2 = xor(key1, key1_key2)
key3 = xor(key2, key2_key3)
flag = xor(flag_key1_key2_key3, key1, key2, key3)
print(flag)

#Favourite byte
#crypto{0x10_15_my_f4v0ur173_by7e}
# 73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d
encoded = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

def decode(s):
    return ''.join([chr(s ^ a) for a in encoded])

for i in range(0, 127):
    if "crypto" in decode(i):
        print(decode(i))
#You either know, XOR you don't
#crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}
# 0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104

from pwn import xor

encoded = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
# We know the encrypted data were created like this:
# secret_key ^ 'crypto{...}' = e
# We can use the XOR property and change the operands:
# e ^ 'crypto{...}' = secret_key

# XOR the first 7 bytes we know of the flag,
# with the first 7 bytes of the encrypted data
print(xor('crypto{'.encode(), encoded[:7]).decode('utf-8')) 

print(xor(encoded, 'myXORkey'.encode()))

#Lemur XOR
#crypto{X0Rly_n0t!}
from PIL import Image
from pwn import xor

lemur = Image.open("lemur.png")
flag = Image.open("flag.png")

outcome_bytes = xor(lemur.tobytes(), flag.tobytes())
outcome = Image.frombytes(flag.mode, flag.size, outcome_bytes)
outcome.save('outcome.png')

#MATHEMATICS
#Greatest Common Divisor
#Extended GCD
#Modular Arithmetic 1
#Modular Arithmetic 2
#Modular Inverting 

#DATA FORMATS
#Privacy-Enhanced Mail?
#CERTainly not
#SSH Keys
#Transparency 
