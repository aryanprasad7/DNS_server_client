from socket import *
import sys
import random
import bitstring
from struct import *
from build_packet import *

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
	finalans = {}
	finalans['answer section'] = []
	finalans['authoritative section'] = []
	finalans['additional section'] = []
	if header['rcode'] == 0:
		for i in range(0, header['ancount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			# finalans.append({'answer section': ans})
			finalans['answer section'].append(ans)

		for i in range(0, header['nscount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			finalans['authoritative section'].append(ans)

		for i in range(0, header['arcount']):	# we will fetch the number of answers that are present
			ans, shift = get_answer_from_data(resolved_dns, shift)
			finalans['additional section'].append(ans)

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
	# dnsserverIP = '8.8.8.8'
	# dnsserverIP = '208.67.222.222'
	dnsserverIP = '127.0.0.3'
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

		resolved_dns, addr = clientsocket.recvfrom(1024)

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