from struct import *
import bitstring
import random
from processing import *

def convert_to_hex(x):
	hex_string = ''

	if x.__class__.__name__ == 'int':
		hex_string = hex(x)

		if x < 16:
			hex_string = '0' + hex_string[2:]
	elif x.__class__.__name__ == 'str':
		hex_string = ''.join([hex(ord(char))[2:] for char in x])

	return '0x' + hex_string

def build_packet(query, QTYPE = 'A', QCLASS = 'IN', QR = '0', RA = '0', countlst = None):
	# this function builds the packet on the basis of the dns headers
	
	DNS_query_format = [
		'hex=id',
		'bin=flags',
		'uintbe:16=qdcount',
		'uintbe:16=ancount',
		'uintbe:16=nscount',
		'uintbe:16=arcount'
	]
	transaction_id = random_trans_id()	# this transaction_id is in hexadecimal string format
	# print(transaction_id)
	QR = QR	# 0 => query
	opcode = '0000'
	AA = '0'
	TC = '0'
	RD = '1'
	RA = RA	# 0 => recursion not available, 1 => recursion available
	Z = '000'
	RCODE = '0000' # this will be 0 for a query a response contains the RCODE to detect errors
	# hence the total flag becomes concat(QR, opcode, ..., RCODE)
	flags = "0b" + QR + opcode + AA + TC + RD + RA + Z + RCODE
	QDCOUNT = 1
	if countlst == None:
		ANCOUNT = 0
		NSCOUNT = 0
		ARCOUNT = 0
	else:
		ANCOUNT = countlst[0]
		NSCOUNT = countlst[1]
		ARCOUNT = countlst[2]
	# print("TransactionID: ", transaction_id)
	# print("flag: ", flag)
	# print("qdcount: {}, ancount: {}, nscount: {}, arcount: {}".format(QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT))
	if QTYPE.lower() == 'a':
		QTYPE = 1
	elif QTYPE.lower() == 'aaaa':
		QTYPE = 28
	elif QTYPE.lower() == 'mx':
		QTYPE = 15
	elif QTYPE.lower() == 'soa':
		QTYPE = 6
	elif QTYPE.lower() == 'ns':
		QTYPE = 2
	elif QTYPE.lower() == 'cname':
		QTYPE = 5
	else:
		QTYPE = 1
	if QCLASS.lower() == 'in':
		QCLASS = "0x0001"
	else:
		QCLASS = "0x0001"
	DNS_query = {
		"id": transaction_id,
		"flags": flags,
		"qdcount": QDCOUNT,
		"ancount": ANCOUNT,
		"nscount": NSCOUNT,
		"arcount": ARCOUNT
	}
	# until here we have our dns header ready, now we need to create the query section
	
	host_name_query = query.split('.')
	# print(host_name_query)
	count = 0
	for i in range(len(host_name_query)):

		host_name_query[i] = host_name_query[i]

		DNS_query_format.append("hex=qname" + str(count))
		DNS_query["qname" + str(count)] =  convert_to_hex(len(host_name_query[i]))
		
		count += 1

		DNS_query_format.append("hex=qname" + str(count))
		DNS_query["qname" + str(count)] = convert_to_hex(host_name_query[i])

		count += 1

	# now we have the qname ready, now add the terminating condition i.e. 0x00(in hex) to indicate end of query
	DNS_query_format.append("hex=qname" + str(count))
	DNS_query["qname" + str(count)] = convert_to_hex(0)

	# now adding qtype (here 1 for A)
	
	DNS_query_format.append("uintbe:16=qtype")
	DNS_query["qtype"] = QTYPE

	# now adding qclass (here 0x0001 for IN(internet))
	
	DNS_query_format.append("hex=qclass")
	DNS_query["qclass"] = "0x0001"
	# print(DNS_query_format)
	# print(DNS_query)
	# combining the above dns header and question for the complete dns data
	dns_data = bitstring.pack(",".join(DNS_query_format), **DNS_query)	# **DNS_query denotes unpacking the dictionary as it is here
	# print(dns_data)

	return dns_data, transaction_id

def random_trans_id():
	# allowed range for transaction_id is from 0 to 2^16 - 1
	# generate a number between them and convert it to hex and return
	return hex(random.randrange(0, 2**16 - 1))
