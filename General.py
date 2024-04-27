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
#1512
def gcd(a, b):
    while a != b:
        if a > b:
            a = a - b
        else:
            b = b - a
    return a

a = 66528
b = 52920
print('gcd({}, {}) = {}'.format(a, b, gcd(a, b)))

#Extended GCD
#crypto{10245,-8404}
def egcd(a, b):
    if(a == 0):
        return b,0,1

    gcd,x1,y1 = egcd(b%a, a)
    x = y1 - (b//a) * x1
    y = x1
    return gcd,x,y

p = 26513
q = 32321
g, u, v = egcd(p, q)

# ax + by = gcd(p,q)
print("Coefficients: crypto{%d,%d}" % (u, v))
print("Greatest Common Divisor: %d" % (g))

#Modular Arithmetic 1
a = 11 % 6
b = 8146798528947 % 17
print(min(a, b))
#4

#Modular Arithmetic 2
def mod(a,b):
    return a%b
p = 65537

print(mod(273246787654**(p-1),p))

#Modular Inverting 
d = 0
while (3 * d) % 13 != 1:
    d += 1

print(d)

#DATA FORMATS
#Privacy-Enhanced Mail?
from Cryptodome.PublicKey import RSA 
print(RSA.import_key(open('privacy_enhanced_mail.pem','r').read()).d) 
#15682700288056331364787171045819973654991149949197959929860861228180021707316851924456205543665565810892674190059831330231436970914474774562714945620519144389785158908994181951348846017432506464163564960993784254153395406799101314760033445065193429592512349952020982932218524462341002102063435489318813316464511621736943938440710470694912336237680219746204595128959161800595216366237538296447335375818871952520026993102148328897083547184286493241191505953601668858941129790966909236941127851370202421135897091086763569884760099112291072056970636380417349019579768748054760104838790424708988260443926906673795975104689

#CERTainly not
from Crypto.PublicKey import RSA

with open('2048b-rsa-example-cert.der', 'rb') as f:
    public_key_der = f.read()

public_key = RSA.import_key(public_key_der)
print(public_key.n)
#22825373692019530804306212864609512775374171823993708516509897631547513634635856375624003737068034549047677999310941837454378829351398302382629658264078775456838626207507725494030600516872852306191255492926495965536379271875310457319107936020730050476235278671528265817571433919561175665096171189758406136453987966255236963782666066962654678464950075923060327358691356632908606498231755963567382339010985222623205586923466405809217426670333410014429905146941652293366212903733630083016398810887356019977409467374742266276267137547021576874204809506045914964491063393800499167416471949021995447722415959979785959569497

#SSH Keys
from Crypto.PublicKey import RSA
f = open('bruce_rsa.pub', 'r')
pubkey = RSA.import_key(f.read())
print(pubkey.n)
#3931406272922523448436194599820093016241472658151801552845094518579507815990600459669259603645261532927611152984942840889898756532060894857045175300145765800633499005451738872081381267004069865557395638550041114206143085403607234109293286336393552756893984605214352988705258638979454736514997314223669075900783806715398880310695945945147755132919037973889075191785977797861557228678159538882153544717797100401096435062359474129755625453831882490603560134477043235433202708948615234536984715872113343812760102812323180391544496030163653046931414723851374554873036582282389904838597668286543337426581680817796038711228401443244655162199302352017964997866677317161014083116730535875521286631858102768961098851209400973899393964931605067856005410998631842673030901078008408649613538143799959803685041566964514489809211962984534322348394428010908984318940411698961150731204316670646676976361958828528229837610795843145048243492909

#Transparency
import hashlib
from Crypto.PublicKey import RSA

pem = open('transparency.pem', 'r').read()

key = RSA.importKey(pem).public_key()

der = key.exportKey(format='DER')

sha256 = hashlib.sha256(der)

sha256_fingerprint = sha256.hexdigest()

print(f"Public Key SHA256: {sha256_fingerprint}")

