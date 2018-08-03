import sys

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

print "decodeResourceSegment.py"
print "This will decode the PE resource segment from the Kovter binary."
print "Extract the resource segment with resource hacker before running this tool."
print "Usage: %s [path to resource segment extracted to a file] [path to write decoded configuration data]" % sys.argv[0]

	
x = open(sys.argv[1], 'rb').read()
y = x[16:-16]
y = y.decode("base64")
xorKey = x[:16]
xorKey = xorKey[::-1]
decoded_resource_segment = decode2(y, xorKey)

fp_out = open(sys.argv[2], 'wb')
fp_out.write(decoded_resource_segment)
fp_out.close()