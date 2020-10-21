from socket import *
import sys
import threading
import bitstring
from struct import *
import random
from processing import *

# one idea will be to use threading and keep one thread on the cache to clear the entry
# who's TTL has finished

""" As the packet arrives from the client we depack it and extract the query,
	then the step would be to find that request/query in our cache, if the record exists
	then pack this into a packet and send it to the client back.

	Now if the record doesn't exist in our cache, then we forward this query to the root server,
	which will then give us the response for that particular query, then we update our cache by 
	adding this response and send this response back to the client.
"""

def search_record(query, qtype):
	return None

def make_response(question):
	ans = search_record(question['query'], question['qtype'])	# this function will give a list of all possible answers for the particular query and its type and None if it does not exist
	
	# if we dont get the searched record in our cache, then we forward this query to the root server
	if ans == None:
		return None
	else:	# we have the record and we prepare the packet from it
		pass
	
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


def main():
	serverPort = 53
	serverIP = '127.0.0.3'
	rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']
	# firstly creating a socket to accept client connections
	serversocket = socket(AF_INET, SOCK_DGRAM)
	serversocket.bind((serverIP, serverPort))

	while True:
		data, addr = serversocket.recvfrom(512)
		print(data)
		header, question, bytes_scanned = getquestion(data)
		response = make_response(question)

		if response == None:	# record is not present in cache
			random_root_ip = random.choice(rootserverlist)
			
			clientsocket = socket(AF_INET, SOCK_DGRAM)
			clientsocket.sendto(data, (random_root_ip, serverPort))
			
			root_ans, rootaddr = clientsocket.recvfrom(512)
			print(root_ans)
			header = get_header(root_ans)
			print(header)
			# as seen from observation root dns servers do not support recursion hence we need to to iterative query

			if header['ra'] == 0 and header['ancount'] == 0:	# root server does not support recursion, hence we contact the server which we get from root server
				shift = bytes_scanned
				if header['rcode'] == 0:
					ans = []
					
					for i in range(0, header['nscount']):
						data, shift = get_answer_from_data(root_ans, shift)
						ans.append(data)

					for i in range(0, header['arcount']):
						data, shift = get_answer_from_data(root_ans, shift)
						ans.append(data)

					print(ans)
						
			else:	# recursion is available, hence we get the final answer, and we forward it to the client after saving in cache
				# after receiving the query we add it to our cache and also send the same to the client
				serversocket.sendto(root_ans, addr)
		else:
			# after processing the data we send it back to the same addr we received it from
			serversocket.sendto(response, addr)




if __name__ == '__main__':
	main()