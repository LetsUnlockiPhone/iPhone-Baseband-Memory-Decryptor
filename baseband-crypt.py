#!/usr/bin/python

# Copyright 2010: dogbert <dogber1@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# You have to install python 2.x along with gmpy 1.12 for running this script.

import hashlib, struct, gmpy

rsa_key1 = "0B 23 AE BA E3 75 7B 9D CE 44 58 8C CF 53 CC B0 73 F9 06 57 64 37 A0 6C 68 F4 91 4E 7A 82 CB 6E 12 CF FD 31 39 51 4C 06 C0 E9 CE A0 27 17 D6 95 FB DF 94 26 B2 1C C1 73 24 06 E3 A8 C2 0F 5D A3 41 6B D8 84 CB D0 EB 2E F9 DE 2F 21 78 DA C3 4D AF B9 BA D8 4B 7C 16 E2 CF 16 7A 1B 57 33 4F 26 4D 53 26 FD 8E 38 B6 23 CE 5E B4 81 80 2B C0 FB 9F 33 E1 3F 65 A2 49 C9 3F 08 6C 37 61 4B B7 C7".replace(" ","")

def dumphex(s):
	i = -1
	if s is None:
		return
	for i in xrange(0,len(s)/16+1):
		if (i)*16 == len(s):
			break
		o = '%08x  ' % (i*16)
		for j in range(0, 16):
			if len(s) > i*16+j:
				o += '%02x ' % ord(s[i*16+j])
			else:
				o += '   '
		o += ' |'
		for j in range(0, 16):
			if len(s) > i*16+j:
				if (ord(s[i*16+j]) > 0x1F) and (ord(s[i*16+j]) < 0x7F):
					o += s[i*16+j]
				else:
					o += '.'
			else:
				o += ' '
		o += '|'
		print o 
	print "\n"

def dumpArray(a):
	for i in range(0, len(a)//4):
		print "%08x %08x %08x %08x" % (a[4*i], a[4*i+1], a[4*i+2], a[4*i+3])
	if len(a) % 4 == 1:
		print "%08x" %  a[len(a)-1]
	if len(a) % 4 == 2:
		print "%08x %08x" %  (a[len(a)-2], a[len(a)-1])
	if len(a) % 4 == 3:
		print "%08x %08x %08x" %  (a[len(a)-3], a[len(a)-2], a[len(a)-1])
	print "\n"
			
def tea_encrypt(v,k):
	y = v[0]; z = v[1];
	s = 0; delta = 0x9e3779b9;

	for i in range(0,32):
		s = (s + delta) & 0xFFFFFFFF
		y += ((z << 4) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1])
		y &= 0xFFFFFFFF
		z += ((y << 4) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3])
		z &= 0xFFFFFFFF

	return [y, z]

def tea_decrypt(v,k):
	y = v[0]; z = v[1];
	s = 0xc6ef3720; delta = 0x9e3779b9;

	for i in range(0,32):
		z -= ((y << 4) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3])
		z &= 0xFFFFFFFF
		y -= ((z << 4) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1])
		y &= 0xFFFFFFFF
		s = (s - delta) & 0xFFFFFFFF

	return [y, z]

def tea_decrypt_cbc(v,k):
	iv = [0xFFFFFFFF, 0xFFFFFFFF]
	o = []

	for i in range(0, len(v)//2):
		t = tea_decrypt([v[2*i],v[2*i+1]], k)
		t[0] ^= iv[0]; t[1] ^= iv[1];
		o.append(t[0]); o.append(t[1]);
		iv[0] = v[2*i]; iv[1] = v[2*i+1];

	return o

def tea_3_round_encipher(v, k, iv):
	a = tea_encrypt(v, k)
	b = tea_encrypt( (a[0]^iv[0], a[1]^iv[1]), k)
	c = (b[0]^a[0],b[1]^a[1])
	return (b, tea_encrypt(c, k))

def hashKey(deviceKey, sha1NCK, norID, chipID):
	d, e = tea_3_round_encipher(norID, sha1NCK, deviceKey)
	f, g = tea_3_round_encipher(chipID, sha1NCK, e)
	return d+f

def getDeviceKey(norID, chipID):
	m = hashlib.sha1()
	m.update(struct.pack('I', norID[0]))
	m.update(struct.pack('I', norID[1]))
	m.update(struct.pack('I', norID[2]))
	m.update(struct.pack('I', norID[3]))
	m.update(struct.pack('I', chipID[0]))
	m.update(struct.pack('I', chipID[1]))
	m.update(struct.pack('I', chipID[2]))
	m.update(struct.pack('I', chipID[3]))
	return struct.unpack('>IIIII', m.digest())

def getChipKey(chipID):
	m = hashlib.sha1()
	m.update(struct.pack('I', chipID[0]))
	m.update(struct.pack('I', chipID[1]))
	m.update(struct.pack('I', chipID[2]))
	m.update(struct.pack('I', chipID[3]))
	return struct.unpack('>IIIII', m.digest())

def sha1NCK(NCK):
	m = hashlib.sha1()
	m.update(NCK)
	return struct.unpack('>IIIII', m.digest())

def decryptRSA(inB, key, exponent):
	b = ''
	for i in range(0, len(key)/2):
		b = b + struct.pack('B', int(key[2*i]+key[2*i+1],16)) 
	mKey = gmpy.mpz(b, 256)
	b = ''
	for i in inB:
		b = struct.pack('>I', i) + b
	mIn  = gmpy.mpz(b, 256)
	mExp = gmpy.mpz(exponent)
	out = pow(mIn,mExp) % mKey
	b = out.binary()
	return b 

def hexToBin(h):
	b = ''
	for i in range(0, len(h)//2):
		b += struct.pack('B', int(h[2*i]+h[2*i+1],16))
	return b	

def checkNCK(nck, token, norID, chipID):
	deviceKey = getDeviceKey(norID, chipID)
	nckKey = hashKey(deviceKey, sha1NCK(nck), norID, chipID)
	decrypted_token = tea_decrypt_cbc(token, nckKey)
	deciphered_token = decipherToken(decryptedToken)

def buildValidToken(norID, chipID):
	correct_token_start = '\x00\x01' + 81*'\xFF' + '\x00'
	status = 4
	correct_token_end = [status]
	correct_token_end += getDeviceKey(norID, chipID) + getChipKey(chipID)
	for i in correct_token_end:
		correct_token_start += struct.pack('<I', i)
	return correct_token_start

def decipherToken(token):
	u = decryptRSA(token, rsa_key1, 3)[::-1]
	return u[1:len(u)]

def printTestVectors():
	norID  = [0x401Dabcd, 0xef012345, 0x0, 0x0]
	chipID = [0xc4101Dab, 0xcdef0123, 0x4567890A, 0x0]
	token  = [0x12345678, 0xABCDEF01, 0x12345677, 0xABCDEF02,
          0x12345676, 0xABCDEF03, 0x12345675, 0xABCDEF04,
          0x12345674, 0xABCDEF05, 0x12345673, 0xABCDEF06, 
          0x12345672, 0xABCDEF07, 0x12345671, 0xABCDEF08,
          0x12345670, 0xABCDEF09, 0x1234566F, 0xABCDEF0a,
          0x1234566E, 0xABCDEF0b, 0x1234566D, 0xABCDEF0c,
          0x1234566C, 0xABCDEF0d, 0x1234566B, 0xABCDEF0e, 
          0x1234566A, 0xABCDEF0f, 0x12345669, 0xABCDEF10,
          0xDEADBEEF, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x12345678]

	print "Test Vector for outer TEA decryption"
	print "------------------------------------"
	print "Encrypted Token:"
	dumpArray(token)
	print "norID:"
	dumpArray(norID)
	print "chipID:"
	dumpArray(chipID)

	deviceKey = getDeviceKey(norID, chipID)
	nckKey = hashKey(deviceKey, sha1NCK('123456789876543'), norID, chipID)
	decrypted_token = tea_decrypt_cbc(token, nckKey)
	valid_token = buildValidToken(norID, chipID)
	print "deviceKey:"
	dumpArray(deviceKey)
	print "nckKey(123456789876543):"
	dumpArray(nckKey)
	print "Decrypted Token:"
	dumpArray(decrypted_token)
	print "Valid deciphered, decrypted token:"
	dumphex(valid_token)


	print "Test Vector for inner RSA-like deciphering"
	print "------------------------------------------"
	print "Enciphered Token:"
	dumpArray(token[0:32])
	deciphered_token = decipherToken(token[0:32])
	print "Deciphered Token:"
	dumphex(deciphered_token)

def analyzeSeczone(filename):

	f = open(filename, "rb")
	c = f.read()
	f.close()

	chipID = struct.unpack('<IIII', c[0x2800:0x2810])
	norID = struct.unpack('<IIII', c[0x2810:0x2820])
	deviceKey = getDeviceKey(norID, chipID)

	print "norID:"
	dumpArray(norID)
	print "chipID:"
	dumpArray(chipID)
	print "deviceKey:"
	dumpArray(deviceKey)

	a = []
	for i in range(0, len(c)//4):
		a += struct.unpack('<I', c[4*i:4*i+4])
	o = tea_decrypt_cbc(a, deviceKey)

	imei = struct.pack("<I", o[0xB00/4])
	imei += struct.pack("<I", o[0xB04/4])
	imei += struct.pack("<I", o[0xB08/4])
	imei += struct.pack("<I", o[0xB0c/4])
	s = "0"
	for x in range(1, 8):
		s += "%01d%01d" % (ord(imei[x]) % 16, ord(imei[x]) >> 4)
	print "IMEI: %s" % s

	print "IMEI Cert:"
	d = decipherToken(a[0xa00//4:0xa80//4])
	dumphex(d)
	print "IMEI Checksum:"
	m = hashlib.sha1()
	for x in a[0xb00//4:0xb10//4]:
		m.update(struct.pack('<I', x))
	dumpArray(struct.unpack('<IIIII', m.digest()))
	 
	print "SecTable Entries"
	print "ID   Offset Size  Entry"
	i = 0xC10 // 4;
	tsize = 0
	while (True):
		ident = o[i] & 0xFFFF
		offset = o[i+1] & 0xFFFF
		size = (o[i+1] >> 16) & 0xFFFF
		if (tsize==0):
			tsize = offset
		s = ""
		d = tea_decrypt_cbc(a[(0xC10+offset)//4:(0xC10+offset+size)//4], deviceKey)
		for j in range(0, len(d)):
			s += "%08X " %  d[j]
			if j % 7 == 6:
				s += '\n' + ' ' * 17 
		print "%04x  %04x %04x  %s" % (ident, offset, size, s)
		i += 2
		if i>=(0xC10+tsize)/4:
			break

	for i in range(1, 5):
		offset = i * 0x100
		d = decipherToken(o[offset//4:(offset+0x80)//4])

analyzeSeczone("seczone.bin")
#analyzeSeczone("seczone-3gs.bin")
#analyzeSeczone("seczone-3g-wiki.bin")

