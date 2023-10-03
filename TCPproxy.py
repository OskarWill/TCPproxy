import sys
import socket
import threading


#Proxy Server sits between the sender and receiver and receives data before the server. Data can be manipulated or merely observed.


HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])			#The entire ASCII alphabet/number system of characters: Returns either a character or a '.'

def hexdump(src, length=16, show=True):
	if isinstance(src, bytes):
		src = src.decode()
	results = list()
	for i in range(0, len(src), length):
		word = str(src[i:i+length])
		printable = word.translate(HEX_FILTER)								#Translates Hexidecimal response into a letter string 	
		hexa= ''.join([f'{ord(c):02X}' for c in word])						#joins letter strings into a word
		hexwidth = length*3
		results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
	if show:
		for line in results:
			print(line)																#prints array in commandline

	else:
		return results

def receive_from(connection):
	buffer = b""																			#receiving bytes
	connection.settimeout(10)																			#close if nothing received in 10 seconds
	try:
		while True:
			data = connection.recv(4096)												#
			if not data:
				break

			buffer += data

	except Exception as e:
		print('error ', e)
		pass


def request_handler(buffer):
	''' Performs modification of packets (ex. fuzzing, testing for auth issues, finding credentials)'''
	return buffer


def response_handler(buffer):
	''' Performs modification of packets (ex. fuzzing, testing for auth issues, finding credentials)'''
	return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)											#remote socket connection
	remote_socket.connect((remote_host, remote_port))

	if receive_first:
		remote_buffer = receive_from(remote_socket)	
		if len(remote_buffer):																					#if bytes have been received
			print("[<==] Received %d bytes from remote" % len(remote_buffer))									
			hexdump(remote_buffer)																				#hexidecimally sort bytes into words

			remote_buffer = response_handler(remote_buffer)
			client_socket.send(remote_buffer)																	#send bytes to local clilent
			print("[==>] Sent to local.")

	while True:
		local_buffer = receive_from(client_socket)																
		if len(local_buffer):		
			print("[<==] Received %d bytes from local." % len (local_buffer))									#bytes sent from local computer
			hexdump(local_buffer)																
															#outgoing data
			local_buffer = reqeust_handler(local_buffer)
			remote_socket.send(local_buffer)																	#sends bytes from local computer to remote socket
			print("[==>] Sent to remote.")														

		remote_buffer = receive_from(remote_socket)			#Incoming data
		if len(remote_buffer):
			print("[<==] Received %d bytes from remote." % len(remote_buffer))									#Bytes received from remote socket
			hexdump(remote_buffer)

			remote_buffer = response_handler(remote_buffer)
			client_socket.send(remote_buffer)																	#send remote socket bytes to local computer
			print("[==>] Sent to local.")											

		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close()
			remote_socket.close()
			print("[*] No more data. Closing connections.")
			break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		server.bind((local_host, local_port))												#binds local host, local port to server 
	except Exception as e:
		print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
		print("[!!] Check for other listening sockets or correct permissions.")
		print(e)
		sys.exit(0)

	print("[*] Listening on %s:%d" % (local_host, local_port))								#listening on local host and chosen port
	server.listen(5)																#listening for 5 connections
	while True:
		client_socket, addr = server.accept()											#if connection is found
		print("> Received incoming connection from %s:%d" % (addr[0], addr[1]))		

		proxy_thread = threading.Thread(													#start new thread looking for new connections (up to 5)
			target = proxy_handler,
			args = (client_socket, remote_host,
					remote_port, receive_first))
		proxy_thread.start()




def main():
	if len(sys.argv[1:]) != 5: 															# If input is not = 5 
		print("Usage: ./TCPproxy.py [localhost] [localport]", end='')
		print("[remotehost] [remoteport] [receivefirst]")
		print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 True")
		sys.exit(0)

	local_host = sys.argv[1] 														#First input = local host
	local_port = int(sys.argv[2])													#second input = local port 

	remote_host = sys.argv[3]														#Third input = remote host
	remote_port = int(sys.argv[4])													#fourth input = remote port

	receive_first = sys.argv[5]														#Fifth input = receive first --> True/False

	if "True" in receive_first:
		receive_first = True
	else:
		receive_first = False










if __name__ == "__main__":
	main()