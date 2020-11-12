import bitstring
from struct import *

def get_a_rdata(resolved_dns, start):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	ip_addr = ".".join([str(temp_resolved_dns[start:start+8].uint),
			str(temp_resolved_dns[start+8:start+16].uint),
			str(temp_resolved_dns[start+16:start+24].uint),
			str(temp_resolved_dns[start+24:start+32].uint)])
	return ip_addr, 4

def get_aaaa_rdata(resolved_dns, start):
	s = '!' + 'H' * 8
	data = unpack_from(s, resolved_dns, start)

	ip = ''
	for _ in data:
		ip += format(_, 'x') + ':'
	ip = ip[0:-1]

	return ip, 16

def get_mx_rdata(resolved_dns, start):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)

	n_bytes_scanned = 0
	pref = unpack_from('!H', resolved_dns, start)[0]
	n_bytes_scanned += 2

	exchange, x = getname(temp_resolved_dns, start + n_bytes_scanned)
	n_bytes_scanned += x

	return ([pref, exchange], n_bytes_scanned)

def get_soa_rdata(resolved_dns, start):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)

	n_bytes_scanned = 0
	mname, x = getname(temp_resolved_dns, start)
	n_bytes_scanned += x

	rname, x = getname(temp_resolved_dns, start + n_bytes_scanned)
	n_bytes_scanned += x

	data = unpack_from('!IIIII', resolved_dns, start + n_bytes_scanned)
	n_bytes_scanned += 20
	serial = data[0]
	refresh = data[1]
	retry = data[2]
	expire = data[3]
	minimum = data[4]

	return ([mname, rname, serial, refresh, retry, expire, minimum], n_bytes_scanned)

def get_ns_rdata(resolved_dns, start):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	ns, n_bytes_scanned = getname(temp_resolved_dns, start)

	return ns, n_bytes_scanned

def get_cname_rdata(resolved_dns, start):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	cname, n_bytes_scanned = getname(temp_resolved_dns, start)

	return cname, n_bytes_scanned

def getname(resolved_dns, start):
	data = ''
	# start is the bytes start
	# print(start)
	s = start*8
	e = s + 8
	back = False
	length = int(str(resolved_dns[s:e]), 16)
	# print('Initial length:')
	# print(length)
	n_bytes_scanned = 1
	if length >= 192:	# meaning it is a pointer
		while length >= 192:
			offset = int(str(resolved_dns[s+2:s+16]), 2)	# offset in bytes
			if back == False:
				n_bytes_scanned += 1
			s = offset*8
			e = s + 8
			length = int(str(resolved_dns[s:e]), 16)
			back = True
		length *= 8
	else:
		length *= 8
	
	while length > 0:

		s = e
		e += length
		# print(length)
		data += str(resolved_dns[s:e].bytes)[2:-1]
		# print(data)
		if back == False:
			n_bytes_scanned += length // 8

		s = e
		e += 8
		length = int(str(resolved_dns[s:e]), 16)
		if back == False:
			n_bytes_scanned += 1

		# print('nbs: ', end='')
		# print(n_bytes_scanned)
		# print(length)
		if length >= 192:	# meaning it is a pointer
			offset = int(str(resolved_dns[s+2:s+16]), 2)	# offset in bytes
			if back == False:
				n_bytes_scanned += 1
			s = offset*8 
			e = s + 8
			length = int(str(resolved_dns[s:e]), 16)*8
			back = True
		else:
			length *= 8
		# n_bytes_scanned += length // 8
		# print(n_bytes_scanned)

		if length != 0:
			data += '.'
			# print(length)

	return data, n_bytes_scanned

def get_header(resolved_dns):
	header = {}
	# !HHHHHH -> 96bits(12bytes)
	header_ls = unpack_from('!HHHHHH', resolved_dns, 0)
	header["id"] = hex(header_ls[0])
	header["flags"] = header_ls[1]
	header["qdcount"] = header_ls[2]
	header["ancount"] = header_ls[3]
	header["nscount"] = header_ls[4]
	header["arcount"] = header_ls[5]
	# print(header)
	header['qr'] = header['flags'] >> 15
	header['opcode'] = (header['flags'] & 0x7100) >> 11
	header['aa'] = (header['flags'] & 0x0400) >> 10
	header['tc'] = (header['flags'] & 0x0200) >> 9
	header['rd'] = (header['flags'] & 0x0100) >> 8
	header['ra'] = (header['flags'] & 0x0080) >> 7
	header['z']= (header['flags'] & 0x0070) >> 4
	header['rcode'] = (header['flags'] & 0x000f)

	return header

def getquestion(data):
	temp_data = bitstring.BitArray(data)

	header = get_header(data)
	# print(header)
	shift = 12 # 12 bytes
	query, bytes_scanned = getname(temp_data, shift)
	# print(query)
	shift += bytes_scanned
	qtype = unpack_from('!H', data, shift)[0]
	qclass = unpack_from('!H', data, shift + 2)[0]
	shift += 4

	question = {"query": query, "qtype": qtype, "qclass": qclass}

	return header, question, shift

def get_answer_from_data(resolved_dns, shift):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	ans = {}
	# name, type, class, ttl, rdlength, rdata
	name, x = getname(temp_resolved_dns, shift)
	# print(name)
	# print('name-x: ' + str(x))
	ans['name'] = name
	# print(ans)
	shift += x
	rr = unpack_from('!HHIH', resolved_dns, shift)
	rtype = rr[0]
	rclass = rr[1]
	ttl = rr[2]
	rdlength = rr[3]
	# print(rr)
	shift += 10
	if rtype == 1:	# a
		# print('a')
		data, x = get_a_rdata(temp_resolved_dns, shift*8)
		shift += x
		# ans.append(data)
		ans['class'] = rclass
		ans['type'] = 'a'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	elif rtype == 28:	# aaaa
		# print('aaaa')
		data, x = get_aaaa_rdata(resolved_dns, shift)
		shift += x
		# ans.append(data)
		ans['class'] = rclass
		ans['type'] = 'aaaa'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	elif rtype == 15:	# mx
		# print('mx')
		data , x = get_mx_rdata(resolved_dns, shift)
		shift += x
		# ans.append(data)
		ans['class'] = rclass
		ans['type'] = 'mx'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	elif rtype == 6:	# soa
		# print('soa')
		data, x = get_soa_rdata(resolved_dns, shift)
		shift += x
		# ans.append(data)
		ans['class'] = rclass
		ans['type'] = 'soa'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	elif rtype == 2:	# ns
		# print('ns')
		data, x = get_ns_rdata(resolved_dns, shift)
		shift += x
		# ans.append(data)
		ans['class'] = rclass
		ans['type'] = 'ns'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	elif rtype == 5:	# cname
		# print('cname')
		data, x = get_cname_rdata(resolved_dns, shift)
		# print('cname - x : ' + str(x))
		shift += x
		# ans.append(cname)
		ans['class'] = rclass
		ans['type'] = 'cname'
		ans['ttl'] = ttl
		ans['rdlength'] = rdlength
		ans['data'] = data
		# print(ans)
	
	return ans, shift

def get_answer(packet, header, shift):
	ans = {}
	ans['answer section'] = []
	ans['authoritative section'] = []
	ans['additional section'] = []
	for i in range(0, header['ancount']):
		rdata, shift = get_answer_from_data(packet, shift)
		ans['answer section'].append(rdata)
				
	for i in range(0, header['nscount']):
		rdata, shift = get_answer_from_data(packet, shift)
		ans['authoritative section'].append(rdata)

	for i in range(0, header['arcount']):
		rdata, shift = get_answer_from_data(packet, shift)
		ans['additional section'].append(rdata)

	return ans