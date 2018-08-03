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

print "NOTE: Address of xorDecodeString_2_addr must be added to python script!"
xorDecodeString_2_addr = 0x0444214
xrefList = getXrefs(xorDecodeString_2_addr)
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
 
def errorLookup(name):
	return name
	errDict = { "_str____1___6": "_str____1_:_6", "_str_t_a_____": "_str_t_a____(", "_str__g___0c__7": "_str__g__&0c__7", "_str_____O5_________": "_str_____O5___%_)___"}
	errDict['_str____M__o_'] = '_str_:__M__o_'
	errDict['_str_9_6k______lR_'] = '_str_9.6k_&____lR_'
	errDict['_str___Zd_r_______'] = '_str___Zd_r_[_____'
	if name in errDict.keys():
		print "FIXUP", name, "=>", errDict[name]
		return errDict[name]
	else:
		return name
	
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
		addr = LocByName(errorLookup(buf))
		if addr == 0xFFFFFFFF:
			return 0,0
		bufAddr = addr + 8
		bufLen = addr + 4
	else: 
		addr = LocByName(errorLookup(buf))
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
	
	result = decode2(encBuf, keyBuf)
	if result == None:
		print "FUCK"
	out.append((addr, enc, key, result))
	


print out[0]
for tuple in out:
	MakeComm(tuple[0], 'DECRYPT=> "%s"' % tuple[3])
	print hex(tuple[0]), tuple[3]
print len(out)
print len(err)
