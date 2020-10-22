from socket import *
import sys
import threading
import bitstring
from struct import *
import random
from processing import *
from build_packet import *
import threading

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

def handle_client_query(client_query, client_addr, serversocket):
	serverPort = 53
	rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']
	header, question, bytes_scanned = getquestion(client_query)
	response = make_response(question)
	client_query_type = question['qtype']

	if response == None:	# record is not present in cache
		random_root_ip = random.choice(rootserverlist)
		
		clientsocket = socket(AF_INET, SOCK_DGRAM)
		clientsocket.sendto(client_query, (random_root_ip, serverPort))
		
		response, rootaddr = clientsocket.recvfrom(1024)
		# print("ans after contacting the root server:\n" + str(root_ans))
		header, question, bytes_scanned = getquestion(response)
		print(header)
		# as seen from observation root dns servers do not support recursion hence we need to do iterative query
		if header['ra'] == 1 and header['ancount']:	# recursion is available, hence we get the final answer, and we forward it to the client after saving in cache
			# after receiving the query we add it to our cache and also send the same to the client
			serversocket.sendto(response, addr)

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

				print(ans)

				if header['ancount'] != 0:
					serversocket.sendto(response, client_addr)
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
				except:	# if there is an error in this step => we have to query the same server with a different host
					record_ns = []
					for i in range(0, len(ans['authoritative section'])):
						try:
							if ans[i]['type'] == 'ns':
								record_ns.append(ans[i])
						except:
							pass

					ns_2b_queried = random.choice(record_ns)['data']
					# now prepare a packet with the query host to be 'ns_2b_queried'
					query_packet, t_id = build_packet(ns_2b_queried)
					clientsocket.sendto(query_packet.tobytes(), (nxt_server2query, serverPort))
					nresponse, ns_addr = clientsocket.recvfrom(1024)
					print(nresponse)
					tmp_hdr, tmp_q, tmp_bs = getquestion(nresponse)
					print(tmp_hdr)
					tmp_shift = tmp_bs
					tmp_ans = []
					for i in range(0, tmp_hdr['ancount']):
						rdata, tmp_shift = get_answer_from_data(response, tmp_shift)
						tmp_ans.append(rdata)
					
					for i in range(0, tmp_hdr['nscount']):
						rdata, tmp_shift = get_answer_from_data(nresponse, tmp_shift)
						tmp_ans.append(rdata)

					for i in range(0, tmp_hdr['arcount']):
						rdata, tmp_shift = get_answer_from_data(nresponse, tmp_shift)
						tmp_ans.append(rdata)

					print(tmp_ans)
					rec_a = []
					for i in range(0, len(tmp_ans)):
						record = tmp_ans[i]
						try:
							if record['type'] == 'a':
								rec_a.append(record)
						except:
							pass

					# print(rec_a)
					record = random.choice(rec_a)

				nxt_server2query = record['data']
				print(nxt_server2query)

				clientsocket.sendto(client_query, (nxt_server2query, serverPort))
				response, nxt_addr = clientsocket.recvfrom(1024)
				print(response)
				header, question, bytes_scanned = getquestion(response)
				print(header)

	else:
		# after processing the data we send it back to the same addr we received it from
		serversocket.sendto(response, client_addr)


def main():
	serverPort = 53
	serverIP = '127.0.0.3'
	rootserverlist = ['192.203.230.10', '199.7.83.42', '198.97.190.53', '192.112.36.4', '192.33.4.12', '198.41.0.4']
	# firstly creating a socket to accept client connections
	serversocket = socket(AF_INET, SOCK_DGRAM)
	serversocket.bind((serverIP, serverPort))

	while True:
		client_query, client_addr = serversocket.recvfrom(1024)
		print(client_query)

		thread = threading.Thread(target = handle_client_query, args = (client_query, client_addr, serversocket,))
		thread.start()

if __name__ == '__main__':
	main()