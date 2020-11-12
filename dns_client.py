from socket import *
import sys
import random
import bitstring
from struct import *
from build_packet import *
import time
import datetime

def unpack_packet(resolved_dns, transaction_id):
	temp_resolved_dns = bitstring.BitArray(resolved_dns)
	# now we have temp_resolved_dns in hex form
	# while resolved_dns is in bytes

	header, question, bytes_scanned = getquestion(resolved_dns)
	# print(header)
	shift = bytes_scanned	# 12 bytes of the dns header

	if header['id'][2:] == transaction_id[2:]:
		# print("TransactionID Matched")
		pass
	else:
		print("Error: received packet not matching.")
		return None, None, None

	finalans = None
	if header['rcode'] == 0:
		finalans = get_answer(resolved_dns, header, shift)
		return (header, question, finalans)

	elif header['rcode'] == 1:
		# format error
		print("** Format error")
		return None, None, None
	elif header['rcode'] == 2:
		# server failure
		print("** Server failure")
		return None, None, None
	elif header['rcode'] == 3:
		# name error
		print("** Name error: the given domain name doesn't exist")
		return None, None, None 
	elif header['rcode'] == 4:
		# not implemented
		print("** The name server doesn't support the requested kind of query")
		return None, None, None
	elif header['rcode'] == 5:
	 	# refused
		print("** Refused to perform such operation")
		return None, None, None

def format_print(header, question, answer, dnsserverIP, msg_size):
	
	opcode = header['opcode']
	if opcode == 0:
		opcode = 'QUERY'
	status = header['rcode']
	if status == 0:
		status = 'NOERROR'
	print("GOT ANSWER: ")
	print(";; ->>HEADER<<- id: {}, opcode: {}, status: {}".format(int(header['id'], 16), opcode, status))
	print(";; flags: qr: {}, aa: {}, tc: {}, rd: {}, ra: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n".format(header['qr'], header['aa'], header['tc'], header['rd'], header['ra'], header['qdcount'], header['ancount'], header['nscount'], header['arcount']))

	qclass = 1
	if question['qclass'] == 1:
		qclass = 'in'

	qtype = 1
	if qtype == 1:	# a
		qtype = 'a'
	elif qtype == 28:	# aaaa
		qtype = 'aaaa'
	elif qtype == 15:	# mx
		qtype = 'mx'
	elif qtype == 6:	# soa
		qtype = 'soa'
	elif qtype == 2:	# ns
		qtype = 'ns'
	elif qtype == 5:	# cname
		qtype = 'cname'

	print(";; QUESTION SECTION:")
	print(";{}\t\t{}\t{}\n".format(question['query'], qclass.upper(), qtype.upper()))
	
	if header['ancount']:
		print(";; ANSWER SECTION:")
		for ans in answer['answer section']:
			print("{}\t\t{}\tIN\t{}\t{}".format(ans['name'], ans['ttl'], ans['type'].upper(), ans['data']))
		print()

	if header['nscount']:
		print(";; AUTHORITY SECTION:")
		for ans in answer['authoritative section']:
			print("{}\t\t{}\tIN\t{}\t{}".format(ans['name'], ans['ttl'], ans['type'].upper(), ans['data']))
		print()

	if header['arcount']:
		print(";; ADDITIONAL SECTION:")
		for ans in answer['additional section']:
			print("{}\t\t{}\tIN\t{}\t{}".format(ans['name'], ans['ttl'], ans['type'].upper(), ans['data']))
		print()

	print(";; SERVER: {}#53({})".format(dnsserverIP, dnsserverIP))
	print(";; WHEN: ", end = '')
	print(datetime.datetime.now())
	print(";; MSG SIZE rcvd: {}\n".format(msg_size))


def main():

	# firstly create a socket
	clientsocket = socket(AF_INET, SOCK_DGRAM) # udp socket
	clientsocket.settimeout(6)

	dnsPort = 53
	dnsserverIP = '8.8.8.8'
	# dnsserverIP = '208.67.222.222'
	# dnsserverIP = '127.0.0.3'
	dnsserverIP_list = []
	try:
		file = open('/etc/resolv.conf', 'r')
		while True:
			line = file.readline()

			if not line:
				break

			if line.startswith('#'):
				continue
			elif line.startswith('nameserver'):
				ip = line.split()[1].strip()
				dnsserverIP_list.append(ip)
	except:
		print("Unable to open file")

	try:
		dnsserverIP = random.choice(dnsserverIP_list)
	except:
		pass

	# by default
	qtype = 'A'
	qclass = 'IN'
	
	if len(sys.argv) == 1:
		# if there are no arguments then start iterative mode
		while True:
			try:
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

				elif 'server' in query:
					dnsserverIP = query.split()[1].strip()
					print("Server changed to: " + str(dnsserverIP))
				# to exit the loop the query is exit
				elif query == "exit":
					clientsocket.close()
					break

				# if we have a host name as a query
				else:
					dns_packet, transaction_id = build_packet(query, qtype, qclass)
					resolved_dns = None
					# now we will need to add a timeout here until we receive the response or send the query again
					count = 0
					while count < 3:
						clientsocket.sendto(dns_packet.tobytes(), (dnsserverIP, dnsPort))
						count += 1
						try:
							resolved_dns, addr = clientsocket.recvfrom(1024)
							break
						except:
							if count < 3:
								print("Timed out, sending again...")
						
					# print(resolved_dns)
					if count < 3:
						header, question, answer = unpack_packet(resolved_dns, transaction_id)
						if header and question and answer:
							format_print(header, question, answer, dnsserverIP, len(resolved_dns))
					else:
						print("Connection timed out..")

			except KeyboardInterrupt:
				print()
				clientsocket.close()
				break

		clientsocket.close()

	else:
		
		query = sys.argv[1]
		resolved_dns = None
		# now query has the host to be queried
		# now we need to form a packet and send it to the dns server for processing
		dns_packet, transaction_id = build_packet(query)	# this packet is in hex format, need to convert it to bytes to transmit it to the server

		# send the packet to the required server, for time being take the google dns server
		# now we will need to add a timeout here until we receive the response or send the query again
		count = 1
		while True:
			clientsocket.sendto(dns_packet.tobytes(), (dnsserverIP, dnsPort))
			
			try:
				resolved_dns, addr = clientsocket.recvfrom(1024)
				break
			except:
				count += 1
				if count <= 3:
					print('Timed out, Sending again...')
				else:
					break
			
		# print(resolved_dns)

		if count < 3 and resolved_dns:
			header, question, answer = unpack_packet(resolved_dns, transaction_id)
			if header and question and answer:
				format_print(header, question, answer, dnsserverIP, len(resolved_dns))
		else:
			print("Connection timed out..")

		clientsocket.close()



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