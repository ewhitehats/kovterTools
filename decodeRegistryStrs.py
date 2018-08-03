import os
import sys

key = "2d5563ed288ac5396add9b78fbca810b"
# this the the campaign key is from decoded resource segment
# "2d5563ed288ac5396add9b78fbca810b" == md5("trees")
# If decoding does not work, run decodeResourceSegment.py on your sample of Kovter 
#  to make sure the campaign key is the 2d5563ed288ac5396add9b78fbca810b


def decode2(buf, key):
	buf = [ord(x) for x in buf]
	key = [ord(x) for x in key]
	table256 = [x for x in range(256)]

	# mix up table256
	muddle = 0
	for i in range(256):
		muddle = key[i % len(key)] + table256[i] + muddle 
		muddle %= 256
		v21 = table256[i] 
		table256[i] = table256[muddle]
		table256[muddle] = v21

	counter = 0
	muddle2 = 0
	for i in range(len(buf)):
		counter += 1
		counter %= 256
		muddle2 = table256[counter] + muddle2
		muddle2 %= 256
		v25 = table256[counter]
		table256[counter] = table256[muddle2]
		table256[muddle2] = v25
		buf[i] ^= table256[(table256[counter] + table256[muddle2]) % 256] 

	return "".join([chr(x) for x in buf])

print "decodeRegistryStrs.py"
print "This will decode the base64 encoded registry values in HKCU\Software\UniqueComputerNmae"
print "Usage: %s [path of file containing the encoded value]" % sys.argv[0]


enc = open(sys.argv[1],'rb').read()
b64_decode = enc.decode("base64")
dec1 = decode2(b64_decode, key)
key2 = dec1[:7]
dec2 = decode2(dec1[7:], key2)
print dec2
