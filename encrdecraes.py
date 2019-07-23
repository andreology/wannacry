#Andre Barajas
#CECS 378
#File Encryption program using AES standard and HMAC hashing solution  
#March 2019

from Crypto.Cipher import AES
import os
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256

key = "00000000000000123456789101112!90"
HMACkey = b"12345656700000123456789101134564"
#Sixteen byte Initialization Vector 
iv = "Initialization V" 
#Users/baraj/Desktop/Csulb.Spring.19/Cs.328.ComputerSec/
dir = "CryptographyPython/"

def decr(ciphertext):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(ciphertext)
def MyencryptMAC(plaintext, key, HMACkey):
#if(len(key) < 32):
#return "ERROR: Key must be 32 Bytes or bigger"
#HMAC: maybe replace plaintext to key.encode() according to lab instructions 
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(plaintext)
	h = HMAC(HMACkey, hashes.SHA256(), backend=default_backend())
#plaintext.encode()
	h.update(ciphertext)
	tag = h.finalize()
	return (ciphertext, iv, tag)

def MyfileEncryptMAC(filepath):
	f = open(filepath, "r")
	contents = f.read()
	inittuple = MyencryptMAC(contents, key, HMACkey)
	filename, fileext = os.path.split(filepath)
	return (inittuple[0], inittuple[1], inittuple[2], key, HMACkey, fileext)
	f.close()

ptxtinput = input("Enter a Full File Path: ")
print(MyfileEncryptMAC(ptxtinput))
