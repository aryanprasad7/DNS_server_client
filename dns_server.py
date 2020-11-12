from socket import *
import sys
import threading
import bitstring
from struct import *
import random
from processing import *
from build_packet import *
import threading
import ipaddress
from dns_cache import *
import json, pickle

# one idea will be to use threading and keep one thread on the cache to clear the entry
# who's TTL has finished

""" As the packet arrives from the client we depack it and extract the query,
	then the step would be to find that request/query in our cache, if the record exists
	then pack this into a packet and send it to the client back.

	Now if the record doesn't exist in our cache, then we forward this query to the root server,
	which will then give us the response for that particular query, then we update our cache by 
	adding this response and send this response back to the client.
"""

# cache = Cache()

def search_record(query, qtype):
	return None

def make_response(question):
	ans = search_record(question['query'], question['qtype'])	# this function will give a list of all possible answers for the particular query and its type and None if it does not exist
	
	# if we dont get the searched record in our cache, then we forward this query to the root server
	if ans == None:
		return None
	else:	# we have the record and we prepare the packet from it
		pass

def string_bytes(string):
	string = string.split('.')
	bytes_str = b''
	for i in range(len(string)):

		string[i] = string[i].strip()
		length = len(string[i])
		bytes_str += length.to_bytes(1, 'big') + string[i].encode()

	bytes_str += b'\x00'

	return bytes_str

def handle_client_query(client_query, client_addr, serversocket):
	serverPort = 53
	rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']

	header, question, bytes_scanned = getquestion(client_query)
	
	response = make_response(question)
	
	qtype = {
	'a': 1,
	'aaaa': 28,
	'soa': 6,
	'mx': 15,
	'ns': 2,
	'cname': 5,
	1: 'a',
	28: 'aaaa',
	6: 'soa',
	15: 'mx',
	2: 'ns',
	5: 'cname'
	}
	client_query_type = question['qtype']
	client_query_type = qtype[client_query_type]

	if response == None:	# record is not present in cache call the root server for the query

		random_root_ip = random.choice(rootserverlist)
		response, ans = root_server_query(client_query, random_root_ip, serverPort, client_query_type)
	
		
		if ans == None:
			# the case when there might be an error
			serversocket.sendto(response, client_addr)
	
		else:
			# we have the answer now create an answer packet along with client query which will have the question

			# save the answer first in the cache
			# saveincache(ans['answer section'])
			
			print(ans)
			ques = ans['question section']
			ques['qtype'] = qtype[ques['qtype']]
			ques['qclass'] = 'in'

			# header + question
			countls = [len(ans['answer section']), len(ans['authoritative section']), len(ans['additional section'])]
			packet, t_id = build_packet(ques['query'], ques['qtype'], ques['qclass'], '1', '1', countls)
			packet = packet.tobytes()
			packet = client_query[0:2] + packet[2:]

			# answer
			for answer in ans['answer section']:
				# name, type, class, ttl, rdlength, rdata
				
				# name
				packet += string_bytes(answer['name'])

				# type
				rtype = answer['type']
				rtype = qtype[rtype]
				packet += rtype.to_bytes(2, 'big')

				# class
				packet += b'\x00\x01'

				# ttl
				packet += answer['ttl'].to_bytes(4, 'big')

				# rdlength
				packet += len(answer['data']).to_bytes(2, 'big')

				# now depending on the type we need to change the packing technique for the data
				if answer['type'] == 'a':
					data = answer['data']
					data = data.split('.')
					for i in range(len(data)):
						data[i] = data[i].strip()
						packet += int(data[i]).to_bytes(1, 'big')

				elif answer['type'] == 'ns' or answer['type'] == 'cname':
					packet += string_bytes(answer['data'])

				elif answer['type'] == 'mx':
					# preference, name
					data = answer['data']
					pref = data[0]
					name = data[1]
					
					packet += pref.to_bytes(2, 'big')
					packet += string_bytes(name)

				elif answer['type'] == 'aaaa':
					packed += ipaddress.IPv6Address(answer['data']).packed

				elif answer['type'] == 'soa':
					# mname, rname, serial, refresh, retry, expire, minimum
					mname, rname, serial, refresh, retry, expire, minimum = answer['data']

					packet += string_bytes(mname)
					packet += string_bytes(rname)
					packet += serial.to_bytes(4, 'big')
					packet += refresh.to_bytes(4, 'big')
					packet += retry.to_bytes(4, 'big')
					packet += expire.to_bytes(4, 'big')
					packet += minimum.to_bytes(4, 'big')

			# authoritative
			for answer in ans['authoritative section']:
				# name, type, class, ttl, rdlength, rdata
				
				# name
				packet += string_bytes(answer['name'])

				# type
				rtype = answer['type']
				rtype = qtype[rtype]
				packet += rtype.to_bytes(2, 'big')

				# class
				packet += b'\x00\x01'

				# ttl
				packet += answer['ttl'].to_bytes(4, 'big')

				# rdlength
				packet += len(answer['data']).to_bytes(2, 'big')

				# now depending on the type we need to change the packing technique for the data
				if answer['type'] == 'a':
					data = answer['data']
					data = data.split('.')
					for i in range(len(data)):
						data[i] = data[i].strip()
						packet += int(data[i]).to_bytes(1, 'big')

				elif answer['type'] == 'ns' or answer['type'] == 'cname':
					packet += string_bytes(answer['data'])

				elif answer['type'] == 'aaaa':
					packed += ipaddress.IPv6Address(answer['data']).packed
					
				elif answer['type'] == 'mx':
					# preference, name
					data = answer['data']
					pref = data[0]
					name = data[1]
					
					packet += pref.to_bytes(2, 'big')
					packet += string_bytes(name)

				elif answer['type'] == 'soa':
					# mname, rname, serial, refresh, retry, expire, minimum
					mname, rname, serial, refresh, retry, expire, minimum = answer['data']

					packet += string_bytes(mname)
					packet += string_bytes(rname)
					packet += serial.to_bytes(4, 'big')
					packet += refresh.to_bytes(4, 'big')
					packet += retry.to_bytes(4, 'big')
					packet += expire.to_bytes(4, 'big')
					packet += minimum.to_bytes(4, 'big')

			# additional
			for answer in ans['additional section']:
				# name, type, class, ttl, rdlength, rdata
				
				if not answer['name']:
					continue
				# name
				packet += string_bytes(answer['name'])

				# type
				rtype = answer['type']
				rtype = qtype[rtype]
				packet += rtype.to_bytes(2, 'big')

				# class
				packet += b'\x00\x01'

				# ttl
				packet += answer['ttl'].to_bytes(4, 'big')

				# rdlength
				packet += len(answer['data']).to_bytes(2, 'big')

				# now depending on the type we need to change the packing technique for the data
				if answer['type'] == 'a':
					data = answer['data']
					data = data.split('.')
					for i in range(len(data)):
						data[i] = data[i].strip()
						packet += int(data[i]).to_bytes(1, 'big')

				elif answer['type'] == 'ns' or answer['type'] == 'cname':
					packet += string_bytes(answer['data'])

				elif answer['type'] == 'aaaa':
					packet += ipaddress.IPv6Address(answer['data']).packed
					
				elif answer['type'] == 'mx':
					# preference, name
					data = answer['data']
					pref = data[0]
					name = data[1]
					
					packet += pref.to_bytes(2, 'big')
					packet += string_bytes(name)

				elif answer['type'] == 'soa':
					# mname, rname, serial, refresh, retry, expire, minimum
					mname, rname, serial, refresh, retry, expire, minimum = answer['data']

					packet += string_bytes(mname)
					packet += string_bytes(rname)
					packet += serial.to_bytes(4, 'big')
					packet += refresh.to_bytes(4, 'big')
					packet += retry.to_bytes(4, 'big')
					packet += expire.to_bytes(4, 'big')
					packet += minimum.to_bytes(4, 'big')


			print(packet)

			serversocket.sendto(packet, client_addr)
	else:
		# after processing the data we send it back to the same addr we received it from
		serversocket.sendto(response, client_addr)


def root_server_query(client_query, random_root_ip, serverPort, client_query_type):
	# rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']
	# random_root_ip = random.choice(rootserverlist)
		
	clientsocket = socket(AF_INET, SOCK_DGRAM)
	clientsocket.sendto(client_query, (random_root_ip, serverPort))
	
	response, rootaddr = clientsocket.recvfrom(1024)
	# print("ans after contacting the root server:\n" + str(root_ans))
	header, question, bytes_scanned = getquestion(response)
	print(header)
	print(question)

	# check for errors from the root server
	# if error then return the same packet with the error to the client, without doing any caching
	if header['rcode'] != 0:
		return response, None

	# as seen from observation root dns servers do not support recursion hence we need to do iterative query
	if header['ra'] == 1 and header['ancount']:	# recursion is available, hence we get the final answer, and we forward it to the client after saving in cache
		# after receiving the query we add it to our cache and also send the same to the client
		return response, None

	while True:
		if header['rcode'] == 0:	# root server does not support recursion, hence we contact the server which we get from root server
			shift = bytes_scanned
			ans = {}
			ans['answer section'] = []
			ans['authoritative section'] = []
			ans['additional section'] = []
			for i in range(0, header['ancount']):
				rdata, shift = get_answer_from_data(response, shift)
				ans['answer section'].append(rdata)
				
			for i in range(0, header['nscount']):
				rdata, shift = get_answer_from_data(response, shift)
				ans['authoritative section'].append(rdata)

			for i in range(0, header['arcount']):
				rdata, shift = get_answer_from_data(response, shift)
				ans['additional section'].append(rdata)

			print("ans: ")
			print(ans)

			if header['ancount'] != 0:
				"""if the answer contains only cname!=client_query_type, then query the root server again
					with query as the cname received, continue this process until we receive the required
					type of the answer
				"""
				
				for answer in ans['answer section']:
					if answer['type'] == client_query_type:
						ans['question section'] = question
						return response, ans
					"""else:	# again query the root server with the cname that we get in the answer
						return response, None
					"""

				for answer in ans['answer section']:
					if answer['type'] == 'cname':
						# query the root server again with the cname data
						data = answer['data']
						data2bqueried, t_id = build_packet(data)
						resp, a = root_server_query(data2bqueried.tobytes(), random_root_ip, serverPort, client_query_type)
						# ans['answer section'].append(a['answer section'])
						# ans['authoritative section'].append(a['authoritative section'])
						# ans['additional section'].append(a['additional section'])
						for i in range(len(a['answer section'])):
							ans['answer section'].append(a['answer section'][i])
						for i in range(len(a['authoritative section'])):
							ans['authoritative section'].append(a['authoritative section'][i])
						for i in range(len(a['additional section'])):
							ans['additional section'].append(a['additional section'][i])

						print(ans)
						ans['question section'] = question
						return resp, ans

				break

			# making a list of 'a' records
			record_a = []
			for i in range(0, len(ans['additional section'])):
				record = ans['additional section'][i]
				try:
					if record['type'] == 'a':
						record_a.append(record)
				except:
					pass

			print(record_a)
			try:
				record = random.choice(record_a)
				nxt_server2query = record['data']
				print(nxt_server2query)

				clientsocket.sendto(client_query, (nxt_server2query, serverPort))
				response, nxt_addr = clientsocket.recvfrom(1024)
				print(response)
				
				header, question, bytes_scanned = getquestion(response)
				print(header)
				print(question)

				if header['rcode'] != 0:
					return response, None

			except:	# if there is an error in this step => we have to query the same server with a different host
				record_ns = []
				for i in range(0, len(ans['authoritative section'])):
					record = ans['authoritative section'][i]
					try:
						if record['type'] == 'ns':
							record_ns.append(record)
					except:
						pass

				print(record_ns)
				try:
					ns_2b_queried = random.choice(record_ns)['data']
				except:
					return response, None
				# now prepare a packet with the query host to be 'ns_2b_queried'
				query_packet, t_id = build_packet(ns_2b_queried)
				res, a = root_server_query(query_packet.tobytes(), random_root_ip, serverPort, 'a')		# 'a' because we need the ipaddress of the name server
				ip = a['answer section'][0]['data']

				# now query to the 'ip'
				clientsocket.sendto(client_query, (ip, serverPort))
				response, addr = clientsocket.recvfrom(1024)
				print(response)
				
				header, question, bytes_scanned = getquestion(response)
				print(header)
				print(question)

				# if header['rcode'] != 0:
				# 	return response, None

def main():
	serverPort = 53
	serverIP = '127.0.0.3'
	rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']
	
	# firstly creating a socket to accept client connections
	serversocket = socket(AF_INET, SOCK_DGRAM)
	serversocket.bind((serverIP, serverPort))

	# whenever the server starts load the cache from the file(maybe json or pickle)
	# cachefile = open('.cache', 'r+')
	# global cache
	# cache = Cache(json.load(cachefile))

	while True:
		client_query, client_addr = serversocket.recvfrom(1024)
		print(client_query)

		thread = threading.Thread(target = handle_client_query, args = (client_query, client_addr, serversocket,))
		thread.start()

	# after we close the server we dump the cache content into a picle file
	
	# json.dumps(cache, cachefile)
	# cachefile.close()

main()