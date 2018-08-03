import sys
import aplib
import struct

print "decodeMainExe.py"
print "This will decode the main.exe executable in the Chrome directory."
print "Note that the actual name of the file will vary from computer to computer."
print "Usage: %s [path to main.exe exectuable] [path to write decoded executable]" % sys.argv[0]


data = open(sys.argv[1],'rb').read()

key = "2d5563ed288ac5396add9b78fbca810b"
# this the the campaign key is from decoded resource segment
# "2d5563ed288ac5396add9b78fbca810b" == md5("trees")
# If decoding does not work, run decodeResourceSegment.py on your sample of Kovter 
#  to make sure the campaign key is the 2d5563ed288ac5396add9b78fbca810b
	
def xorDecodeString_3(buf, key):
	buf = [ord(x) for x in buf]
	key = [ord(x) for x in key]
	table256 = [x for x in range(256)]

	# mix up the table
	muddle = 0
	for counter in range(256):
		value = table256[counter] + muddle
		muddle = (key[counter % len(key)] + value) % 256
		swap = table256[counter]
		table256[counter] = table256[muddle]
		table256[muddle] = swap
	
	
	counter = 0
	muddle = 0
	for i in range(len(buf)):
		counter += 1
		counter %= 256
		muddle = (table256[counter] + muddle) %256
		swap = table256[counter]
		table256[counter] = table256[muddle]
		table256[muddle] = swap
		buf[i] ^= table256[(table256[muddle] + table256[counter]) % 256] 
		
	return "".join([chr(x) for x in buf])

dec = xorDecodeString_3(data, key)
innerKey = dec[:7]
dec2 = xorDecodeString_3(dec[7:], innerKey)
md5Checksum = dec2[:32]
compressedSize = struct.unpack("<I", "".join(dec2[32:36]))[0]
decompressedSize = struct.unpack("<I", "".join(dec2[36:40]))[0]
aplibCompressedBuf = dec2[40:]

decompressedBuf = aplib.decompress(aplibCompressedBuf).do()
print len(decompressedBuf[0])
print decompressedBuf[1]
fp_out = open(sys.argv[2], 'wb')
fp_out.write(decompressedBuf[0])
fp_out.close()