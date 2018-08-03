def getXrefs(ea):
	out = []
	cur = RfirstB(ea)
	out.append(cur)
	while 1:
		cur = RnextB(ea, cur)
		if cur == 0xFFFFFFFF:
			break
		out.append(cur)
	print out
	return out
	
print "NOTE: Address of xorDecodeString_1_addr must be added to python script!"
xorDecodeString_1_addr=	0x004025B8
xrefList = getXrefs(xorDecodeString_1_addr)
pairs =[]
for xref in xrefList:
	eax = 0
	edx = 0
	xref= int(xref)
	i = PrevHead(xref, 0 )
	while i > xref - 0x40:
		li = GetDisasm(i)
		
		if "mov" in li and "eax," in li and eax == 0:
			eax = int(GetOperandValue(i, 1))
		if "mov" in li and "edx," in li and edx == 0:
			edx = int(GetOperandValue(i,1))
		if eax != 0 and edx != 0:
			break
		i = PrevHead(i, 0 )
	if eax == 0 or edx == 0:
		continue
	addr = int(xref)
	pairs.append((addr, eax,edx))
 
	
def fixupName(buf):
	buf = buf.strip()
	try:
		buf = buf.split(" ")[1]
	except:
		return 0,0
	bufAddr = 0
	bufLen = 0
	
	if ".Text" in buf:
		buf = buf.replace(".Text", "")
		addr = LocByName(buf)
		if addr == 0xFFFFFFFF:
			return 0,0
		bufAddr = addr + 8
		bufLen = addr + 4
	else: 
		addr = LocByName(buf)
		if addr == 0xFFFFFFFF:
			return 0,0
		bufAddr = addr
		bufLen = addr - 4
	return bufAddr, bufLen
	
def decode2(buf, key):
	#buf = [ord(x) for x in buf]
	#key = [ord(x) for x in key]
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

	
def decode1(buf, key):
	#buf = [ord(x) for x in buf]
	#key = [ord(x) for x in key]
	out = []
	for i in range(len(buf)):
		cur = (buf[i] & 0x0F ) ^ (key[i % len(key)] & 0xF)
		cur += (buf[i] & 0xF0) 
		out.append(cur)
	return "".join([chr(x) for x in out])

out=[]
err=[]
	
for addr, enc, key in pairs:
	if enc > 0x45F618 or key > 0x45F618:
		print hex(addr), "MUST HAVE REGISTERS FOR DECRPYTION!"
		continue

	encLen = Dword(enc-4)
	encBuf = []
	for i in range(encLen):
		encBuf.append(Byte(enc + i))
		
	keyLen = Dword(key-4)
	keyBuf = []
	for i in range(keyLen):
		keyBuf.append(Byte(key + i))
	
	result = decode1(encBuf, keyBuf)
	if result == None:
		print "FUCK"
	out.append((addr, enc, key, result))
	


print out[0]
for tuple in out:
	MakeComm(tuple[0], 'DECODE=> "%s"' % tuple[3])
print len(out)
print len(err)
