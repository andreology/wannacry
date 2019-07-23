from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
f = open('myprivatekey.pem','wb')
print(key)
privatekey = key.exportKey('PEM')
print(privatekey)
f.write(privatekey)
f.close()

f = open('mypublickey.pem','wb')
publickey = key.publickey()
print(publickey)
publickey = publickey.exportKey('PEM')
f.write(publickey)
print(publickey)
f.close()
enckey = b'00000000000000123456789101112!90'
hmac = b'12345656700000123456789101134564'
#privatekey + hmac
message = b'You can attack now!'
f = open('mypublickey.pem')
publickey = RSA.importKey(f.read()) 
#publickey = key.publickey()
publickey = publickey.exportKey()
key = (enckey + hmac).decode()
print(key)


#publickey = RSA.importKey(open('mypublickey.pem').read())
cipher = PKCS1_OAEP.new(publickey)
ciphertext = cipher.encrypt(key)
print(ciphertext)
#error occurs with calling cipher.ecrypt(key). It may be the bytes 
#or I'm not following the right algorithm from lab instructions. 
key = RSA.importKey(open('myprivatekey.pem').read())
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)
print(message)