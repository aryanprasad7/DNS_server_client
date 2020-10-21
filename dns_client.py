from socket import *
import sys
import random
import string
import bitstring
from struct import *
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

def build_packet(query, QTYPE = 'A', QCLASS = 'IN'):
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
	QR = '0'	# 0 => query
	opcode = '0000'
	AA = '0'
	TC = '0'
	RD = '1'
	RA = '0'
	Z = '000'
	RCODE = '0000' # this will be 0 for a query a response contains the RCODE to detect errors
	# hence the total flag becomes concat(QR, opcode, ..., RCODE)
	flags = "0b" + QR + opcode + AA + TC + RD + RA + Z + RCODE
	QDCOUNT = 1
	ANCOUNT = 0
	NSCOUNT = 0
	ARCOUNT = 0
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

		host_name_query[i] = host_name_query[i].strip()

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
	dns_data = bitstring.pack(",".join(DNS_query_format), **DNS_query)	# **DNS_header denotes unpacking the dictionary as it is here
	# print(dns_data)

	return dns_data, transaction_id

def random_trans_id():
	# allowed range for transaction_id is from 0 to 2^16 - 1
	# generate a number between them and convert it to hex and return
	return hex(random.randrange(0, 2**16 - 1))

def unpack_packet(resolved_dns, transaction_id):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	# now we have temp_resolved_dns in hex form
	# while resolved_dns is in bytes

	header = get_header(resolved_dns)
	# print(header)
	shift = 12	# 12 bytes of the dns header

	if header['id'][2:] == transaction_id[2:]:
		# print("TransactionID Matched")
		pass
	else:
		print("Error: received packet not matching.")
		return

	host_name, n_bytes_scanned = getname(temp_resolved_dns, shift)

	shift += n_bytes_scanned
	qtype = unpack_from('!H', resolved_dns, shift)[0]
	qclass = unpack_from('!H', resolved_dns, shift + 2)[0]
	shift += 4
	# print(qtype)
	# print(qclass)
	# print(n_bytes_scanned)
	# print(host_name)
	finalans = []
	if header['rcode'] == 0:
		for i in range(0, header['ancount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			finalans.extend(ans)

		for i in range(0, header['nscount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			finalans.extend(ans)

		for i in range(0, header['arcount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			finalans.extend(ans)

		print(finalans)

	elif header['rcode'] == 1:
		# format error
		print("** Format error")
	elif header['rcode'] == 2:
		# server failure
		print("** Server failure")
	elif header['rcode'] == 3:
		# name error
		print("** Name error: the given domain name doesn't exist")
	elif header['rcode'] == 4:
		# not implemented
		print("** The name server doesn't support the requested kind of query")
	elif header['rcode'] == 5:
	 	# refused
		print("** Refused to perform such operation")


def main():

	# firstly create a socket
	clientsocket = socket(AF_INET, SOCK_DGRAM) # udp socket

	dnsPort = 53
	dnsserverIP = '8.8.8.8'
	# dnsserverIP = '208.67.222.222'
	# dnsserverIP = '127.0.0.3'
	# by default
	qtype = 'A'
	qclass = 'IN'
	
	if len(sys.argv) == 1:
		# if there are no arguments then start iterative mode
		while True:
			query = input("> ")
			# print(query)
			if 'set' in query:
				to_set = query.split()[1]
				if 'type' in to_set:
					# we need to set the type of the query to the right side =
					# print("type is present")
					try:
						qtype = to_set.split('=')[1].strip()
					except:
						continue
					print(qtype)
				elif 'class' in to_set:
					# print("class is present")
					try:
						qclass = to_set.split('=')[1].strip()
					except:
						continue
					print(qclass)
				else:
					print("** Invalid query or arguments. **")
			# to exit the loop the query is exit
			elif query == "exit":
				clientsocket.close()
				break

			# if we have a host name as a query
			else:
				dns_packet, transaction_id = build_packet(query, qtype, qclass)
				# print(dns_packet.bytes)
				# now we will need to add a timeout here until we receive the response or send the query again
				clientsocket.sendto(dns_packet.tobytes(), (dnsserverIP, dnsPort))
				resolved_dns, addr = clientsocket.recvfrom(1024)
				# print(resolved_dns)
				unpack_packet(resolved_dns, transaction_id)

	else:
		
		query = sys.argv[1]
		
		# now query has the host to be queried
		# now we need to form a packet and send it to the dns server for processing
		dns_packet, transaction_id = build_packet(query)	# this packet is in hex format, need to convert it to bytes to transmit it to the server

		# send the packet to the required server, for time being take the google dns server
		# now we will need to add a timeout here until we receive the response or send the query again
		clientsocket.sendto(dns_packet.tobytes(), (dnsserverIP, dnsPort))

		resolved_dns, addr = clientsocket.recvfrom(512)

		# print(resolved_dns)

		unpack_packet(resolved_dns, transaction_id)



if __name__ == '__main__':
	main()


"""
	The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	
	# flags
	transaction_id = None
	QR = None # query -> 0 or response -> 1
	opcode = '0000' # as we are always sending a standard query
	AA = None	# this is valid in reponse for authoritative answers
	TC = None # this is the truncation flag for signalling if the length of query exceeds the limit and it is truncated
	RD = '1' # we require a recursive query(RD->Recursion desired)
	RA = None # (RA->Recursion available, this if for a response field)
	Z = '000' # reserved for future use, must be 0 everytime
	RCODE = None
	 # RCODE - a 4bit value indicating 
		0->no error, 
		1->format error, 
		2->server failure, 
		3->name error, 
		4->not implemented, 
		5->name server refused, 
		6-15->reserved for future use
	
	QDCOUNT = 1	# number of entries in question section -> 16bit
	ANCOUNT = None	# number of RR in answer section -> 16bit
	NSCOUNT = None	# number of name server RRs in authority records section -> 16bit
	ARCOUNT = None	# number of RR in additional records section -> 16bit
	QTYPE = 'A'
	QCLASS = 'IN'
	"""