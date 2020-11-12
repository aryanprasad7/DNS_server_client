# DNS_server_client

<---------- Server ---------->

To run the server: sudo python3 dns_server.py

<---------- Client ---------->

To run in iterative mode: python dns_client.py
In iterative: set type=<type> ; (type = a, cname, mx, soa, aaaa, ns; default = a) - to change the type of the query
			  server <serverIP> ; to change the server to the particular ip, default - nameserver in /etc/resolv.conf

To run in normal mode: python dns_client.py <query>

